package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const captchaListenPort = "8765"

// redactSensitiveQueryRe matches sensitive token/hash params in form bodies and
// query strings. Replaced with "<redacted:N>" so logs reveal presence and length
// without exposing the JWT itself.
var redactSensitiveQueryRe = regexp.MustCompile(`(?i)\b(session_token|access_token|success_token|hash|debug_info|browser_fp)=([^&\s]*)`)

var redactCookieValueRe = regexp.MustCompile(`(remix[a-z]+|prcl|domain_sid)=([^;\s]+)`)

func redactBodyForLog(s string) string {
	return redactSensitiveQueryRe.ReplaceAllStringFunc(s, func(m string) string {
		groups := redactSensitiveQueryRe.FindStringSubmatch(m)
		if len(groups) < 3 {
			return m
		}
		return groups[1] + "=<redacted:" + fmt.Sprint(len(groups[2])) + ">"
	})
}

func redactHeaderForLog(name, value string) string {
	switch strings.ToLower(name) {
	case "cookie", "set-cookie":
		return redactCookieValueRe.ReplaceAllString(value, "$1=<redacted>")
	case "referer", "origin", "location":
		return redactBodyForLog(value)
	case "authorization", "proxy-authorization":
		return "<redacted>"
	}
	return value
}

type browserCommand struct {
	name string
	args []string
}

func localCaptchaOrigin() string {
	return "http://localhost:" + captchaListenPort
}

func localCaptchaListenAddrs() []string {
	return []string{
		"127.0.0.1:" + captchaListenPort,
		"[::1]:" + captchaListenPort,
	}
}

func localCaptchaHosts() []string {
	return []string{
		"localhost:" + captchaListenPort,
		"127.0.0.1:" + captchaListenPort,
		"[::1]:" + captchaListenPort,
	}
}

func isLocalCaptchaHost(host string) bool {
	for _, localHost := range localCaptchaHosts() {
		if strings.EqualFold(host, localHost) {
			return true
		}
	}
	return false
}

func localCaptchaURLForTarget(targetURL *neturl.URL) string {
	localURL := &neturl.URL{
		Scheme:   "http",
		Host:     "localhost:" + captchaListenPort,
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	if localURL.Path == "" {
		localURL.Path = "/"
	}
	return localURL.String()
}

func targetOrigin(targetURL *neturl.URL) string {
	return targetURL.Scheme + "://" + targetURL.Host
}

func isSafeLocalRedirectPath(raw string) bool {
	if raw == "" || raw[0] != '/' {
		return false
	}
	if len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\') {
		return false
	}
	return true
}

func rewriteProxyRedirectLocation(raw string, targetURL *neturl.URL) (string, bool) {
	if isSafeLocalRedirectPath(raw) {
		return raw, true
	}

	parsed, err := neturl.Parse(raw)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, targetURL.Scheme) || !strings.EqualFold(parsed.Host, targetURL.Host) {
		return "", false
	}

	return localCaptchaURLForTarget(parsed), true
}

func rewriteProxyHeaderURL(raw string, targetURL *neturl.URL) string {
	if raw == "" {
		return raw
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.Scheme != "http" || !isLocalCaptchaHost(parsed.Host) {
		return raw
	}
	parsed.Scheme = targetURL.Scheme
	parsed.Host = targetURL.Host
	return parsed.String()
}

func rewriteProxyRequest(req *http.Request, targetURL *neturl.URL) {
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	if req.URL.Path == "" {
		req.URL.Path = targetURL.Path
	}
	req.Host = targetURL.Host

	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE")
	// Strip WebView identity / fingerprint leak headers. Android WebView
	// auto-injects X-Requested-With with the host package name, which would
	// reveal the proxy app to VK.
	for _, h := range []string{
		"X-Requested-With",
		"X-Android-Package",
		"X-Android-Cert",
		"X-Client-Data",
		"X-Discord-Locale",
		"X-Discord-Timezone",
		"Save-Data",
		"Purpose",
		"Sec-Purpose",
	} {
		req.Header.Del(h)
	}
	for _, headerName := range []string{"Origin", "Referer"} {
		if rewritten := rewriteProxyHeaderURL(req.Header.Get(headerName), targetURL); rewritten != "" {
			req.Header.Set(headerName, rewritten)
		} else {
			req.Header.Del(headerName)
		}
	}
}

func extractSuccessToken(body []byte) string {
	var payload struct {
		Response struct {
			SuccessToken string `json:"success_token"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Response.SuccessToken
}

func rewriteProxyCookies(header http.Header) {
	cookies := (&http.Response{Header: header}).Cookies()
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, cookie := range cookies {
		cookie.Domain = ""
		cookie.Secure = false
		cookie.Partitioned = false
		if cookie.SameSite == http.SameSiteNoneMode || cookie.SameSite == http.SameSiteStrictMode {
			cookie.SameSite = http.SameSiteLaxMode
		}
		header.Add("Set-Cookie", cookie.String())
	}
}

var htmlURLAttrDoubleRe = regexp.MustCompile(`(?i)((?:src|href|action)\s*=\s*)"((?:https?:)?//[^"]+)"`)
var htmlURLAttrSingleRe = regexp.MustCompile(`(?i)((?:src|href|action)\s*=\s*)'((?:https?:)?//[^']+)'`)

var (
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`)
	styleBlockRe  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style\s*>`)
)

// rewriteHTMLAttrsServerSide rewrites absolute and protocol-relative URLs in
// src/href/action attributes of raw HTML. URLs matching the upstream origin go
// to localhost; other absolute URLs are routed through /generic_proxy. Skips
// <script> and <style> blocks: their contents are JS/CSS, not HTML attributes.
func rewriteHTMLAttrsServerSide(html string, targetURL *neturl.URL) string {
	localOrigin := localCaptchaOrigin()
	upstreamOrigin := targetOrigin(targetURL)

	rewriteURL := func(rawURL string) string {
		absURL := rawURL
		if strings.HasPrefix(rawURL, "//") {
			absURL = targetURL.Scheme + ":" + rawURL
		}
		if strings.HasPrefix(absURL, upstreamOrigin) {
			return localOrigin + absURL[len(upstreamOrigin):]
		}
		if strings.HasPrefix(absURL, localOrigin) {
			return rawURL
		}
		return "/generic_proxy?proxy_url=" + neturl.QueryEscape(absURL)
	}

	rewriteAttrs := func(s string) string {
		s = htmlURLAttrDoubleRe.ReplaceAllStringFunc(s, func(match string) string {
			groups := htmlURLAttrDoubleRe.FindStringSubmatch(match)
			if len(groups) < 3 {
				return match
			}
			return groups[1] + `"` + rewriteURL(groups[2]) + `"`
		})
		s = htmlURLAttrSingleRe.ReplaceAllStringFunc(s, func(match string) string {
			groups := htmlURLAttrSingleRe.FindStringSubmatch(match)
			if len(groups) < 3 {
				return match
			}
			return groups[1] + `'` + rewriteURL(groups[2]) + `'`
		})
		return s
	}

	type span struct{ a, b int }
	var spans []span
	for _, m := range scriptBlockRe.FindAllStringIndex(html, -1) {
		spans = append(spans, span{m[0], m[1]})
	}
	for _, m := range styleBlockRe.FindAllStringIndex(html, -1) {
		spans = append(spans, span{m[0], m[1]})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].a < spans[j].a })

	var b strings.Builder
	last := 0
	for _, s := range spans {
		if s.a < last {
			continue
		}
		b.WriteString(rewriteAttrs(html[last:s.a]))
		b.WriteString(html[s.a:s.b])
		last = s.b
	}
	b.WriteString(rewriteAttrs(html[last:]))
	return b.String()
}

func rewriteCaptchaHTML(html string, targetURL *neturl.URL) string {
	localOrigin := localCaptchaOrigin()
	upstreamOrigin := targetOrigin(targetURL)

	html = strings.ReplaceAll(html, upstreamOrigin, localOrigin)
	html = rewriteHTMLAttrsServerSide(html, targetURL)

	script := fmt.Sprintf(`
<script>
(function() {
    var localOrigin = %q;
    var upstreamOrigin = %q;

    function rewriteUrl(urlStr) {
        if (!urlStr || typeof urlStr !== 'string') return urlStr;
        if (urlStr.indexOf(localOrigin) === 0) return urlStr;
        if (urlStr.indexOf(upstreamOrigin) === 0) return localOrigin + urlStr.slice(upstreamOrigin.length);
        if (urlStr.indexOf('//') === 0) {
            return '/generic_proxy?proxy_url=' + encodeURIComponent(window.location.protocol + urlStr);
        }
        if (urlStr.indexOf('http://') === 0 || urlStr.indexOf('https://') === 0) {
            return '/generic_proxy?proxy_url=' + encodeURIComponent(urlStr);
        }
        return urlStr;
    }

    function rewriteElementAttr(el, attr) {
        if (!el || !el.getAttribute) return;
        var value = el.getAttribute(attr);
        if (!value) return;
        var rewritten = rewriteUrl(value);
        if (rewritten !== value) {
            el.setAttribute(attr, rewritten);
        }
    }

    function rewriteDocument(root) {
        if (!root || !root.querySelectorAll) return;
        root.querySelectorAll('[href]').forEach(function(el) { rewriteElementAttr(el, 'href'); });
        root.querySelectorAll('[src]').forEach(function(el) { rewriteElementAttr(el, 'src'); });
        root.querySelectorAll('form[action]').forEach(function(el) { rewriteElementAttr(el, 'action'); });
    }

    function handleSuccessToken(token) {
        if (!token) return;
        console.log('Captcha solved, sending token to proxy...');
        var body = 'token=' + encodeURIComponent(token);

        // sendBeacon is the most reliable on mobile Safari:
        // it's fire-and-forget and works even if the page navigates away.
        if (navigator && navigator.sendBeacon) {
            var blob = new Blob([body], {type: 'application/x-www-form-urlencoded'});
            var sent = navigator.sendBeacon('/local-captcha-result', blob);
            if (sent) {
                console.log('Token sent via sendBeacon');
                showDone();
                return;
            }
        }

        fetch('/local-captcha-result', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: body
        }).then(function(r) {
            console.log('Proxy acknowledged token');
            showDone();
        }).catch(function(e) {
            console.error('Fetch failed, trying form submit...', e);
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/local-captcha-result';
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'token';
            input.value = token;
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        });
    }

    function showDone() {
        try { window.close(); } catch (e) {}
    }

    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        if (arguments[1] && typeof arguments[1] === 'string') {
            this._origUrl = arguments[1];
            arguments[1] = rewriteUrl(arguments[1]);
        }
        return origOpen.apply(this, arguments);
    };

    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        var xhr = this;
        if (this._origUrl && this._origUrl.indexOf('captchaNotRobot.check') !== -1) {
            xhr.addEventListener('load', function() {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.response && data.response.success_token) {
                        handleSuccessToken(data.response.success_token);
                    }
                } catch (e) {}
            });
        }
        return origSend.apply(this, arguments);
    };

    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function() {
            var url = arguments[0];
            var isObj = (typeof url === 'object' && url && url.url);
            var urlStr = isObj ? url.url : url;
            var origUrlStr = urlStr;

            if (typeof urlStr === 'string') {
                urlStr = rewriteUrl(urlStr);
                arguments[0] = urlStr;
            }

            var p = origFetch.apply(this, arguments);
            if (typeof origUrlStr === 'string' && origUrlStr.indexOf('captchaNotRobot.check') !== -1) {
                p.then(function(response) {
                    return response.clone().json();
                }).then(function(data) {
                    if (data.response && data.response.success_token) {
                        handleSuccessToken(data.response.success_token);
                    }
                }).catch(function() {});
            }
            return p;
        };
    }

    document.addEventListener('submit', function(event) {
        if (event.target && event.target.action) {
            event.target.action = rewriteUrl(event.target.action);
        }
    }, true);

    document.addEventListener('click', function(event) {
        var target = event.target && event.target.closest ? event.target.closest('a[href]') : null;
        if (target && target.href) {
            target.href = rewriteUrl(target.href);
        }
    }, true);

    var origFormSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        if (this.action) {
            this.action = rewriteUrl(this.action);
        }
        return origFormSubmit.apply(this, arguments);
    };

    var origWindowOpen = window.open;
    if (origWindowOpen) {
        window.open = function(url) {
            if (typeof url === 'string') {
                arguments[0] = rewriteUrl(url);
            }
            return origWindowOpen.apply(this, arguments);
        };
    }

    rewriteDocument(document);
    if (document.documentElement && window.MutationObserver) {
        new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'attributes' && mutation.target) {
                    rewriteElementAttr(mutation.target, mutation.attributeName);
                    return;
                }
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1) {
                        rewriteDocument(node);
                    }
                });
            });
        }).observe(document.documentElement, {
            subtree: true,
            childList: true,
            attributes: true,
            attributeFilter: ['href', 'src', 'action']
        });
    }
})();
</script>
`, localOrigin, upstreamOrigin)

	// Inject as early as possible — at the opening <head> tag — so XHR/fetch
	// overrides are active before any inline <script> in <head> runs.
	switch {
	case strings.Contains(html, "<head>"):
		return strings.Replace(html, "<head>", "<head>"+script, 1)
	case strings.Contains(html, "</head>"):
		return strings.Replace(html, "</head>", script+"</head>", 1)
	case strings.Contains(html, "</body>"):
		return strings.Replace(html, "</body>", script+"</body>", 1)
	default:
		return html + script
	}
}

func newCaptchaProxyTransport() *http.Transport {
	d := appDialer()
	return &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		DialContext:           d.DialContext,
	}
}

func startCaptchaServer(srv *http.Server, logPrefix string) error {
	var listenErrs []string
	var listening bool

	for _, addr := range localCaptchaListenAddrs() {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			listenErrs = append(listenErrs, fmt.Sprintf("%s (%v)", addr, err))
			continue
		}
		listening = true
		go func(listener net.Listener) {
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("%s: %s", logPrefix, err)
			}
		}(listener)
	}

	if listening {
		return nil
	}

	return fmt.Errorf("captcha listeners failed: %s", strings.Join(listenErrs, "; "))
}

// runCaptchaServerAndWait triggers the browser, then waits for a solution token.
func runCaptchaServerAndWait(handler http.Handler, captchaURL string, keyCh <-chan string, logPrefix string) (string, error) {
	srv := &http.Server{Handler: handler}

	if err := startCaptchaServer(srv, logPrefix); err != nil {
		return "", err
	}

	fmt.Println("\n==============================================")
	fmt.Println("ACTION REQUIRED: MANUAL CAPTCHA SOLVING NEEDED")
	fmt.Println("Open this URL in your browser: " + localCaptchaOrigin())
	fmt.Println("==============================================")
	fmt.Println()

	log.Printf("[%s] Opening browser...", logPrefix)
	openBrowser(captchaURL)

	key := <-keyCh

	// Best-effort shutdown: token is already received, return it even if
	// Shutdown times out (e.g. ishConn.SetDeadline is no-op on iSH and
	// active connections can't be force-closed).
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("%s: shutdown warning (token already received): %v", logPrefix, err)
	}

	return key, nil
}

func notifyKey(keyCh chan<- string, key string) {
	if key != "" {
		select {
		case keyCh <- key:
		default:
		}
	}
}

func solveCaptchaViaHTTP(captchaImg string) (string, error) {
	keyCh := make(chan string, 1)
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;text-align:center;padding:20px}
img{max-width:100%%;margin:16px 0}
input{font-size:24px;padding:12px;width:80%%;box-sizing:border-box}
button{font-size:24px;padding:12px 32px;margin-top:12px;cursor:pointer}</style>
</head><body>
<h2>Solve the Captcha</h2>
<img src="%s" alt="captcha"/>
<form onsubmit="fetch('/solve?key='+encodeURIComponent(document.getElementById('k').value)).then(()=>{document.body.innerHTML='<h2>Done!</h2>';setTimeout(function(){window.close();}, 300);});return false;">
<br><input id="k" type="text" autofocus placeholder="Text from image"/>
<br><button type="submit">Submit</button>
</form></body></html>`, captchaImg)
	})

	mux.HandleFunc("/solve", func(w http.ResponseWriter, r *http.Request) {
		notifyKey(keyCh, r.URL.Query().Get("key"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body><h2>Done!</h2></body></html>`)
	})

	return runCaptchaServerAndWait(mux, localCaptchaOrigin(), keyCh, "captcha-image")
}

// loggingTransport intercepts captchaNotRobot.componentDone / .check requests
// from the WebView, captures the (User-Agent, Sec-CH-UA*, device, browser_fp)
// tuple, and persists it as SavedProfile so subsequent auto-solve attempts
// can replay the same fingerprint.
type loggingTransport struct {
	rt    http.RoundTripper
	debug bool
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	isCaptchaRequest := req.Body != nil && (strings.Contains(req.URL.Path, "captchaNotRobot.check") || strings.Contains(req.URL.Path, "captchaNotRobot.componentDone"))

	if isCaptchaRequest {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			log.Printf("[Captcha Proxy] Failed to read request body: %v", err)
			b = nil
		}
		req.Body = io.NopCloser(bytes.NewReader(b))

		if t.debug {
			log.Printf("[Captcha Proxy] Real browser sent %s data: %s", req.URL.Path, redactBodyForLog(string(b)))
			for k, v := range req.Header {
				log.Printf("[Captcha Proxy] Header (%s): %s = %s", req.URL.Path, k, redactHeaderForLog(k, strings.Join(v, ", ")))
			}
		}

		parsedBody, perr := neturl.ParseQuery(string(b))
		if perr != nil {
			log.Printf("[Captcha Proxy] Failed to parse request body: %v", perr)
		}
		device := parsedBody.Get("device")
		browserFp := parsedBody.Get("browser_fp")

		if device != "" && browserFp != "" {
			sp := SavedProfile{
				Profile: Profile{
					UserAgent:       req.Header.Get("User-Agent"),
					SecChUa:         req.Header.Get("Sec-Ch-Ua"),
					SecChUaMobile:   req.Header.Get("Sec-Ch-Ua-Mobile"),
					SecChUaPlatform: req.Header.Get("Sec-Ch-Ua-Platform"),
				},
				DeviceJSON: device,
				BrowserFp:  browserFp,
			}
			if err := SaveProfileToDisk(sp); err != nil {
				log.Printf("[Captcha Proxy] Failed to save browser profile: %v", err)
			} else {
				log.Printf("[Captcha Proxy] Successfully intercepted and saved real browser profile!")
			}
		}
	}
	return t.rt.RoundTrip(req)
}

// genericProxyAllowedSuffixes are upstream host suffixes the WebView is
// permitted to fetch via /generic_proxy. Anything else is rejected so the
// loopback proxy cannot be abused as an open SSRF gadget.
var genericProxyAllowedSuffixes = []string{
	"vk.com", "vk.ru", "vkuser.net", "vk-cdn.net",
	"userapi.com", "okcdn.ru",
	"mc.yandex.ru",
}

func isAllowedGenericProxyHost(host string) bool {
	host = strings.ToLower(host)
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	for _, suffix := range genericProxyAllowedSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func solveCaptchaViaProxy(redirectURI string) (string, error) {
	keyCh := make(chan string, 1)

	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %v", err)
	}

	transport := &loggingTransport{rt: newCaptchaProxyTransport(), debug: isDebug}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			rewriteProxyRequest(req.Out, targetURL)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[Captcha Proxy] ERROR for %s %s: %v", r.Method, r.URL.String(), err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:20px"><h2>Captcha proxy error</h2><p>%s %s</p><p>%v</p></body></html>`, r.Method, r.URL.String(), err)
		},
		ModifyResponse: func(res *http.Response) error {
			rewriteProxyCookies(res.Header)

			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					if rewritten, ok := rewriteProxyRedirectLocation(loc, targetURL); ok {
						res.Header.Set("Location", rewritten)
					} else {
						res.Header.Del("Location")
					}
				}
			}

			contentType := res.Header.Get("Content-Type")
			contentEncoding := res.Header.Get("Content-Encoding")
			if isDebug {
				log.Printf("[Captcha Proxy] %s %d | Content-Type: %q, Encoding: %q", res.Request.Method, res.StatusCode, contentType, contentEncoding)
			}

			shouldInspectBody := strings.Contains(contentType, "text/html") ||
				strings.Contains(contentType, "application/xhtml+xml") ||
				strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")

			if !shouldInspectBody {
				return nil
			}

			reader := res.Body
			if res.Header.Get("Content-Encoding") == "gzip" {
				gzReader, err := gzip.NewReader(res.Body)
				if err == nil {
					reader = gzReader
					defer func() {
						if err := gzReader.Close(); err != nil {
							log.Printf("failed to close gzip reader: %v", err)
						}
					}()
				}
			}

			bodyBytes, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if err := res.Body.Close(); err != nil {
				return err
			}

			if strings.Contains(res.Request.URL.Path, "captchaNotRobot.check") {
				notifyKey(keyCh, extractSuccessToken(bodyBytes))
			}

			if strings.Contains(contentType, "text/html") {
				for _, headerName := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
					"Alt-Svc",
				} {
					res.Header.Del(headerName)
				}

				bodyBytes = []byte(rewriteCaptchaHTML(string(bodyBytes), targetURL))
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			res.ContentLength = int64(len(bodyBytes))
			res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))

			return nil
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		if token != "" {
			log.Printf("[Captcha] Received success token from browser (%d bytes)", len(token))
			notifyKey(keyCh, token)
		} else {
			log.Printf("[Captcha] Received empty token from browser")
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	})

	mux.HandleFunc("/generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		targetAuthURL := r.URL.Query().Get("proxy_url")
		targetParsed, err := neturl.Parse(targetAuthURL)
		if err != nil || targetParsed.Host == "" {
			http.Error(w, "Bad URL", http.StatusBadRequest)
			return
		}
		if targetParsed.Scheme != "http" && targetParsed.Scheme != "https" {
			http.Error(w, "Unsupported scheme", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(targetParsed.Host, targetURL.Host) && !isAllowedGenericProxyHost(targetParsed.Host) {
			log.Printf("[Captcha Proxy] /generic_proxy rejected host=%s", targetParsed.Host)
			http.Error(w, "Host not allowed", http.StatusForbidden)
			return
		}
		genericReverse := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = targetParsed.Path
				req.Out.URL.RawQuery = targetParsed.RawQuery
				rewriteProxyRequest(req.Out, targetParsed)
			},
			ModifyResponse: func(res *http.Response) error {
				for _, h := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
				} {
					res.Header.Del(h)
				}
				res.Header.Set("Access-Control-Allow-Origin", "*")

				// captchaNotRobot.check goes to api.vk.ru (different host from
				// the main proxy upstream vk.com), so it's routed via
				// /generic_proxy. Extract success_token here so the server-side
				// path works on iOS even if the JS callback never fires.
				if strings.Contains(targetAuthURL, "captchaNotRobot.check") {
					bodyBytes, readErr := io.ReadAll(res.Body)
					if readErr == nil {
						_ = res.Body.Close()
						res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
						res.ContentLength = int64(len(bodyBytes))
						res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))
						notifyKey(keyCh, extractSuccessToken(bodyBytes))
					}
				}

				return nil
			},
		}
		genericReverse.ServeHTTP(w, r)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[Captcha Proxy] HTTP %s %s", r.Method, r.URL.Path)
		if r.URL.Path == "/" && targetURL.Path != "" && targetURL.Path != "/" && r.URL.RawQuery == "" {
			http.Redirect(w, r, localCaptchaURLForTarget(targetURL), http.StatusTemporaryRedirect)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	return runCaptchaServerAndWait(mux, localCaptchaURLForTarget(targetURL), keyCh, "captcha-proxy")
}

func openBrowser(url string) {
	for _, cmd := range browserOpenCommands(runtime.GOOS, url) {
		if err := exec.Command(cmd.name, cmd.args...).Start(); err == nil {
			return
		}
	}
}

func browserOpenCommands(goos string, url string) []browserCommand {
	switch goos {
	case "windows":
		// rundll32 url.dll,FileProtocolHandler is more reliable than 'cmd /c start'
		// because it bypasses cmd.exe and avoids issues with '&' and other special chars.
		return []browserCommand{
			{name: "rundll32", args: []string{"url.dll,FileProtocolHandler", url}},
			{name: "cmd", args: []string{"/c", "start", "", url}},
		}
	case "darwin":
		return []browserCommand{{name: "open", args: []string{url}}}
	case "linux":
		return []browserCommand{
			{name: "xdg-open", args: []string{url}},
			{name: "gio", args: []string{"open", url}},
		}
	case "android":
		return []browserCommand{
			{name: "termux-open-url", args: []string{url}},
			{name: "/system/bin/am", args: []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{name: "am", args: []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{name: "xdg-open", args: []string{url}},
		}
	case "ios":
		return []browserCommand{
			{name: "open", args: []string{url}},
			{name: "uiopen", args: []string{url}},
		}
	}
	return nil
}
