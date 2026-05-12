#!/usr/bin/env python3
"""
CURLman Proxy Server
────────────────────
A lightweight HTTP proxy that forwards requests from the CURLman browser UI
to any target URL, bypassing browser CORS restrictions.

Usage:
    python proxy.py                  # runs on http://localhost:7474
    python proxy.py --port 9090      # custom port
    python proxy.py --host 0.0.0.0   # expose on LAN

Requirements:  pip install requests
"""

import argparse
import json
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO

try:
    import requests
    from requests_toolbelt.multipart import decoder as mp_decoder
except ImportError:
    requests = None

# ──────────────────────────────────────────────────────────────────
#  Install check
# ──────────────────────────────────────────────────────────────────
def ensure_deps():
    import subprocess
    pkgs = ["requests"]
    for pkg in pkgs:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[proxy] Installing missing dependency: {pkg}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])
    # re-import after install
    global requests
    import requests as _r
    requests = _r

ensure_deps()
import requests  # noqa: E402  (re-import after ensure)

# ──────────────────────────────────────────────────────────────────
#  Headers that must NOT be forwarded (hop-by-hop / browser-injected)
# ──────────────────────────────────────────────────────────────────
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "host",           # will be set correctly by requests
    "content-length", # requests computes this itself
}

CORS_HEADERS = {
    "Access-Control-Allow-Origin":      "*",
    "Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
    "Access-Control-Allow-Headers":     "*",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Expose-Headers":    "*",
}

# ──────────────────────────────────────────────────────────────────
#  Handler
# ──────────────────────────────────────────────────────────────────
class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"   # disables keep-alive; each request gets its own connection

    # ── silence the default request log; we print our own ──
    def log_message(self, fmt, *args):
        pass

    # ── CORS pre-flight ──────────────────────────────────────
    def do_OPTIONS(self):
        self._send_cors_preflight()

    def _send_cors_preflight(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── All real methods route here ──────────────────────────
    def do_GET(self):     self._route("GET")
    def do_POST(self):    self._route("POST")
    def do_PUT(self):     self._route("PUT")
    def do_DELETE(self):  self._route("DELETE")
    def do_PATCH(self):   self._route("PATCH")
    def do_HEAD(self):    self._route("HEAD")

    def _route(self, method):
        path = self.path.split("?")[0].rstrip("/") or "/"

        # GET /ping  → health check
        if path == "/ping":
            body = json.dumps({"status": "ok", "server": "CURLman Proxy"}).encode()
            self.send_response(200)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print("  \033[92m200\033[0m  PING")
            return

        # POST /  → proxy the request
        if path == "/" and method == "POST":
            self._proxy(method)
            return

        # anything else → 404
        self._error(404, f"Unknown proxy endpoint: {self.path}")

    # ── Core proxy logic ─────────────────────────────────────
    def _proxy(self, _ignored_method):
        t0 = time.time()

        # ── 1. Parse the JSON envelope sent by CURLman ───────
        try:
            length   = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length) if length else b""
            envelope = json.loads(raw_body)
        except Exception as e:
            return self._error(400, f"Bad envelope JSON: {e}")

        target_url   = envelope.get("url", "").strip()
        target_hdrs  = envelope.get("headers", {})   # dict
        body_type    = envelope.get("bodyType", "none")
        body_data    = envelope.get("body", None)     # str | dict | None
        # ↓ use the method declared in the envelope, NOT the incoming HTTP verb
        method       = envelope.get("method", "GET").upper()

        if not target_url:
            return self._error(400, "Missing 'url' in request envelope")

        # ── 2. Build kwargs for requests ──────────────────────
        req_headers = {k: v for k, v in target_hdrs.items()
                       if k.lower() not in HOP_BY_HOP}

        req_kwargs = dict(
            headers=req_headers,
            allow_redirects=True,
            timeout=30,
            stream=False,       # read full response at once — avoids framing issues
            verify=True,
        )

        # ── 3. Attach body based on bodyType ─────────────────
        if method not in ("GET", "HEAD") and body_type != "none":

            if body_type == "json":
                # body_data is a raw JSON string from the textarea
                req_kwargs["data"] = body_data.encode() if body_data else b""
                req_headers.setdefault("Content-Type", "application/json")

            elif body_type == "form":
                # body_data is application/x-www-form-urlencoded string
                req_kwargs["data"] = body_data.encode() if body_data else b""
                req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

            elif body_type == "text":
                req_kwargs["data"] = body_data.encode("utf-8") if body_data else b""
                req_headers.setdefault("Content-Type", "text/plain")

            elif body_type == "xml":
                req_kwargs["data"] = body_data.encode("utf-8") if body_data else b""
                req_headers.setdefault("Content-Type", "application/xml")

            elif body_type == "multipart":
                # body_data is a dict: { fieldName: {type:"text"|"file", value, filename, mimetype} }
                files   = {}
                fields  = {}
                for name, part in (body_data or {}).items():
                    if part.get("type") == "file":
                        content  = bytes(part["bytes"])   # list of ints from JS
                        filename = part.get("filename", name)
                        mime     = part.get("mimetype", "application/octet-stream")
                        files[name] = (filename, BytesIO(content), mime)
                    else:
                        fields[name] = part.get("value", "")
                # Use requests' built-in multipart encoder
                # Pass files dict; text fields go in data=
                req_kwargs["files"]  = files  if files  else None
                req_kwargs["data"]   = fields if fields else None
                # Do NOT set Content-Type manually — requests sets it with boundary

            elif body_type == "raw":
                # body_data: { bytes: [...], mimetype: "..." }
                raw = body_data or {}
                content = bytes(raw.get("bytes", []))
                req_kwargs["data"] = content
                req_headers.setdefault("Content-Type",
                                       raw.get("mimetype", "application/octet-stream"))

        # ── 4. Fire the request ───────────────────────────────
        try:
            resp = requests.request(method, target_url, **req_kwargs)
        except requests.exceptions.SSLError as e:
            return self._error(502, f"SSL error: {e}")
        except requests.exceptions.ConnectionError as e:
            return self._error(502, f"Connection error: {e}")
        except requests.exceptions.Timeout:
            return self._error(504, "Target server timed out")
        except Exception as e:
            return self._error(502, f"Proxy error: {e}")

        elapsed_ms = round((time.time() - t0) * 1000)

        # ── 5. Read response body ─────────────────────────────
        try:
            resp_body = resp.content   # bytes
        except Exception as e:
            return self._error(502, f"Failed reading response: {e}")

        # ── 6. Build response headers to send back ────────────
        STRIP_RESP = HOP_BY_HOP | {"content-length", "content-encoding"}
        fwd_headers = {}
        for k, v in resp.headers.items():
            if k.lower() not in STRIP_RESP:
                fwd_headers[k] = v

        # ── 7. Send response ──────────────────────────────────
        self.send_response(resp.status_code)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        for k, v in fwd_headers.items():
            self.send_header(k, v)
        self.send_header("X-Proxy-Time-Ms", str(elapsed_ms))
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Connection", "close")
        self.end_headers()

        if method != "HEAD":
            self.wfile.write(resp_body)
            self.wfile.flush()

        # ── 8. Console log ────────────────────────────────────
        status_color = "\033[92m" if 200 <= resp.status_code < 300 else \
                       "\033[93m" if 300 <= resp.status_code < 400 else "\033[91m"
        reset = "\033[0m"
        print(f"  {status_color}{resp.status_code}{reset}  {method:7}  {elapsed_ms:>5}ms  {target_url}")

    # ── Error helper ──────────────────────────────────────────
    def _error(self, code, message):
        body = json.dumps({"error": message}).encode()
        self.send_response(code)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"  \033[91m{code}\033[0m  PROXY ERROR  {message}")


# ──────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CURLman Proxy Server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=7474,
                        help="Bind port (default: 7474)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), ProxyHandler)

    print()
    print("  \033[92m●\033[0m  CURLman Proxy Server")
    print(f"     Listening on  \033[96mhttp://{args.host}:{args.port}\033[0m")
    print(f"     Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n  Proxy stopped.\n")
        server.server_close()


if __name__ == "__main__":
    main()
