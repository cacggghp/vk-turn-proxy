#!/usr/bin/env python3
"""
vk-turn-proxy captcha solver — local HTTP server that uses Playwright + headless
Chromium to solve VK's not_robot_captcha and return a success_token.

Run:
    pip install playwright requests
    playwright install chromium
    python3 captcha_solver.py [--listen 127.0.0.1:8766]

HTTP API:
    POST /solve
        Body (JSON): {"redirect_uri": "https://id.vk.ru/not_robot_captcha?..."}
        Response (JSON): {"success_token": "...", "elapsed": 8.3}
                         or {"error": "...", "elapsed": 8.3}

The Go vk-turn-proxy client can be configured (via -captcha-solver flag) to
call this server instead of trying to solve captcha inline. This bypasses
VK's bot detection because the captchaNotRobot.check request comes from a
real Chromium browser with a real FingerprintJS visitor_id.

Note: Chromium must be installed via `playwright install chromium`.
"""
import argparse
import json
import re
import random
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from playwright.sync_api import sync_playwright

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

# Reuse a single browser instance across requests (Chromium startup is ~500ms)
_browser_lock = threading.Lock()
_browser = None
_playwright_ctx = None


def get_browser():
    global _browser, _playwright_ctx
    with _browser_lock:
        if _browser is None:
            _playwright_ctx = sync_playwright().start()
            _browser = _playwright_ctx.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
            )
        return _browser


def solve_captcha(redirect_uri: str, timeout: float = 30.0) -> dict:
    """Load the captcha page in Chromium, click the checkbox, return success_token."""
    start = time.time()
    success_token = {"value": None, "error": None}

    browser = get_browser()
    context = browser.new_context(
        user_agent=UA,
        viewport={"width": 1920, "height": 1080},
        locale="en-US",
        extra_http_headers={
            "sec-ch-ua": '"Chromium";v="146", "Not A(Brand";v="24", "Google Chrome";v="146"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    )
    context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
        window.chrome = {runtime: {}};
    """)
    page = context.new_page()

    def on_response(response):
        if "captchaNotRobot.check" in response.url:
            try:
                data = response.json()
                if data.get("response", {}).get("success_token"):
                    success_token["value"] = data["response"]["success_token"]
            except Exception as e:
                success_token["error"] = f"response parse: {e}"

    page.on("response", on_response)

    try:
        page.goto(redirect_uri, wait_until="networkidle", timeout=20000)
        checkbox = page.wait_for_selector("#not-robot-captcha-checkbox", timeout=10000)
        box = checkbox.bounding_box()
        target_x = box["x"] + box["width"] / 2
        target_y = box["y"] + box["height"] / 2

        # Realistic mouse path (cubic bezier)
        start_x = random.randint(100, 400)
        start_y = random.randint(100, 400)
        steps = 40
        for i in range(steps):
            t = i / (steps - 1)
            cp1x = start_x + random.uniform(50, 200)
            cp1y = start_y + random.uniform(50, 200)
            cp2x = target_x - random.uniform(20, 100)
            cp2y = target_y - random.uniform(20, 100)
            x = (1-t)**3 * start_x + 3*(1-t)**2*t * cp1x + 3*(1-t)*t**2 * cp2x + t**3 * target_x
            y = (1-t)**3 * start_y + 3*(1-t)**2*t * cp1y + 3*(1-t)*t**2 * cp2y + t**3 * target_y
            page.mouse.move(x, y)
            page.wait_for_timeout(20)

        page.wait_for_timeout(300)
        page.mouse.click(target_x, target_y)

        # Wait for success_token
        deadline = time.time() + timeout
        while time.time() < deadline and not success_token["value"] and not success_token["error"]:
            page.wait_for_timeout(100)

    except Exception as e:
        success_token["error"] = str(e)
    finally:
        context.close()

    elapsed = time.time() - start
    if success_token["value"]:
        return {"success_token": success_token["value"], "elapsed": round(elapsed, 1)}
    return {"error": success_token["error"] or "no success_token received", "elapsed": round(elapsed, 1)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Log to stdout with timestamp
        print(f"[{time.strftime('%H:%M:%S')}] {args[0]}")

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True, "engine": "playwright"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/solve":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            req = json.loads(body) if body else {}
        except Exception as e:
            self._json(400, {"error": f"bad request: {e}"})
            return

        redirect_uri = req.get("redirect_uri", "")
        if not redirect_uri:
            self._json(400, {"error": "missing redirect_uri"})
            return

        print(f"[/solve] redirect_uri={redirect_uri[:80]}...")
        result = solve_captcha(redirect_uri)
        print(f"[/solve] result: token={'OK' if result.get('success_token') else 'FAIL'} elapsed={result.get('elapsed')}s")
        self._json(200, result)

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:8766", help="listen address")
    args = ap.parse_args()

    # Warm up the browser instance
    print("[init] warming up Chromium...")
    get_browser()
    print("[init] ready")

    host, port = args.listen.split(":")
    # IMPORTANT: use plain HTTPServer (single-threaded), NOT ThreadingHTTPServer.
    # Playwright's sync API uses greenlets that are pinned to a single thread —
    # calling browser.new_context() from a worker thread raises
    # "greenlet.error: Cannot switch to a different thread". Serializing all
    # requests on the main thread is fine because captcha solving is rare
    # (once per ~10 minutes per stream) and takes ~8s.
    from http.server import HTTPServer
    srv = HTTPServer((host, int(port)), Handler)
    srv.daemon_threads = False
    print(f"[listen] http://{args.listen} (single-threaded)")
    print("[listen] POST /solve with {\"redirect_uri\": \"...\"} to solve captcha")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[shutdown]")
        if _browser:
            _browser.close()
        if _playwright_ctx:
            _playwright_ctx.stop()


if __name__ == "__main__":
    main()
