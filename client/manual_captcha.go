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
	"runtime"
	"strings"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
)

const captchaListenPort = "8765"

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
	req.Header.Del("TE") // Disable transfer encoding compression
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

func rewriteCaptchaHTML(html string, targetURL *neturl.URL) string {
	localOrigin := localCaptchaOrigin()
	upstreamOrigin := targetOrigin(targetURL)
	html = strings.ReplaceAll(html, upstreamOrigin, localOrigin)

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
        fetch('/local-captcha-result', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'token=' + encodeURIComponent(token)
        }).then(function() {
            document.body.innerHTML = '<h2 style="text-align:center;margin-top:20vh">Done! You can close the page.</h2>';
            setTimeout(function() { window.close(); }, 300);
        }).catch(function() {});
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

	switch {
	case strings.Contains(html, "</head>"):
		return strings.Replace(html, "</head>", script+"</head>", 1)
	case strings.Contains(html, "</body>"):
		return strings.Replace(html, "</body>", script+"</body>", 1)
	default:
		return html + script
	}
}

func newCaptchaProxyTransport(dialer *dnsdialer.Dialer) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	if dialer != nil {
		transport.DialContext = dialer.DialContext
	}
	return transport
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

// runCaptchaServerAndWait triggers the browser, and waiting gracefully for the solution token.
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

	openBrowser(captchaURL)

	key := <-keyCh

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return "", err
	}

	return key, nil
}

// notifyKey pushes the key string to the given channel without blocking
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

	return runCaptchaServerAndWait(mux, localCaptchaOrigin(), keyCh, "captcha HTTP server error")
}

func solveCaptchaViaProxy(redirectURI string, dialer *dnsdialer.Dialer) (string, error) {
	keyCh := make(chan string, 1)

	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %v", err)
	}

	transport := newCaptchaProxyTransport(dialer)

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
					log.Printf("[Captcha Proxy] Redirecting to: %s", loc)
					if rewritten, ok := rewriteProxyRedirectLocation(loc, targetURL); ok {
						res.Header.Set("Location", rewritten)
					} else {
						res.Header.Del("Location")
					}
				}
			}

			contentType := res.Header.Get("Content-Type")
			contentEncoding := res.Header.Get("Content-Encoding")
			log.Printf("[Captcha Proxy] %s %d | Content-Type: %q, Encoding: %q", res.Request.Method, res.StatusCode, contentType, contentEncoding)

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
		notifyKey(keyCh, r.FormValue("token")) // r.FormValue automatically parses the form
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = fmt.Fprint(w, "ok")
	})

	mux.HandleFunc("/generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		targetAuthURL := r.URL.Query().Get("proxy_url")
		targetParsed, err := neturl.Parse(targetAuthURL)
		if err != nil || targetParsed.Host == "" {
			http.Error(w, "Bad URL", http.StatusBadRequest)
			return
		}
		genericReverse := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = targetParsed.Path
				req.Out.URL.RawQuery = targetParsed.RawQuery
				rewriteProxyRequest(req.Out, targetParsed)
			},
		}
		genericReverse.ServeHTTP(w, r)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[Captcha Proxy] HTTP %s %s", r.Method, r.URL.String())
		if r.URL.Path == "/" && targetURL.Path != "" && targetURL.Path != "/" && r.URL.RawQuery == "" {
			log.Printf("[Captcha Proxy] Redirecting ROOT to: %s", localCaptchaURLForTarget(targetURL))
			http.Redirect(w, r, localCaptchaURLForTarget(targetURL), http.StatusTemporaryRedirect)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	return runCaptchaServerAndWait(mux, localCaptchaURLForTarget(targetURL), keyCh, "proxy HTTP server error")
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
		return []browserCommand{{name: "cmd", args: []string{"/c", "start", url}}}
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
