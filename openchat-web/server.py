#!/usr/bin/env python3
"""OpenChat replicator: static frontend + CORS relay. Stdlib only. No deps."""
import json, urllib.request, urllib.parse, os, hashlib
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))

class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=BASE, **kw)
    def log_message(self, *a):
        pass
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()
    def do_POST(self):
        if self.path == "/relay-raw":
            # generic raw forward (used for S3 PUT): {url, method, headers, bodyB64}
            import base64 as _b64
            try:
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}")
                data = _b64.b64decode(req.get("bodyB64", "") or b"")
                r = urllib.request.Request(req["url"], data=data or None,
                    method=req.get("method", "PUT"), headers=req.get("headers", {}))
                try:
                    resp = urllib.request.urlopen(r, timeout=120)
                    out = {"status": resp.status, "body": resp.read()[:2000].decode("utf-8", "replace")}
                except Exception as e:
                    try:
                        out = {"status": getattr(e, "code", 0), "body": e.read()[:2000].decode("utf-8", "replace")}  # type: ignore
                    except Exception:
                        out = {"status": 0, "body": f"fetch failed: {e}"}
            except Exception as e:
                out = {"status": 0, "body": f"relay error: {e}"}
            raw = json.dumps(out).encode()
            self.send_response(200); self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw); return
        if self.path == "/relay-stream":
            # streaming passthrough: forward form, pipe response bytes as they arrive
            try:
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}")
                data = urllib.parse.urlencode(req.get("form", {})).encode()
                r = urllib.request.Request(req["url"], data=data, headers={
                    "User-Agent": "okhttp/4.12.4",
                    "Content-Type": "application/x-www-form-urlencoded"})
                try:
                    resp = urllib.request.urlopen(r, timeout=90)
                except Exception as e:
                    resp = e  # HTTPError still has .read()
                self.send_response(getattr(resp, "status", getattr(resp, "code", 200)) or 200)
                self._cors()
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                while True:
                    ch = resp.read(8192)
                    if not ch:
                        break
                    self.wfile.write(ch)
                    self.wfile.flush()
            except Exception:
                pass
            return
        if self.path == "/md5":
            n = int(self.headers.get("Content-Length", 0))
            s = json.loads(self.rfile.read(n) or b'""')
            raw = json.dumps({"md5": hashlib.md5(s.encode()).hexdigest()}).encode()
            self.send_response(200); self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw); return
        if self.path != "/relay":
            self.send_response(404); self._cors(); self.end_headers(); return
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
            url, form = req["url"], req.get("form", {})
            data = urllib.parse.urlencode(form).encode()
            r = urllib.request.Request(url, data=data, headers={
                "User-Agent": "okhttp/4.12.4",
                "Content-Type": "application/x-www-form-urlencoded"})
            try:
                resp = urllib.request.urlopen(r, timeout=90)
                body = resp.read().decode("utf-8", "replace")
                out = {"status": resp.status, "body": body}
            except Exception as e:
                # HTTPError carries body (e.g. 4xx with payload)
                try:
                    body = e.read().decode("utf-8", "replace")  # type: ignore
                    out = {"status": getattr(e, "code", 0), "body": body}
                except Exception:
                    out = {"status": 0, "body": f"fetch failed: {e}"}
        except Exception as e:
            out = {"status": 0, "body": f"relay error: {e}"}
        raw = json.dumps(out).encode()
        self.send_response(200); self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8901"))
    print(f"openchat-web on http://127.0.0.1:{port}  (relay: POST /relay)")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
