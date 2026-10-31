#!/usr/bin/env python3
"""
ALFRED server — stdlib only.

Serves the static cockpit, the same-origin OpenChat relay (so the browser can
reach the free models with WebCrypto), and the deterministic security API.

Run:
    python3 alfred/server.py
    open http://127.0.0.1:8902/
"""
from __future__ import annotations

import json
import os
import sys
import traceback
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

import local_sandbox
import mcp_client
import web_fetcher
from benchmark import run_benchmark  # noqa: E402
from engine import Engine, EngineError  # noqa: E402

ENGINE = Engine()
UPSTREAM = "https://gptapi.rotech.dev/api/v5/"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE, **kwargs)

    def log_message(self, fmt, *args):
        pass

    # ---------------------------------------------------------------- util
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, obj, status=200):
        raw = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        try:
            self.send_response(status)
            self._cors()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise EngineError(f"invalid JSON body: {exc}")

    def _path(self):
        u = urllib.parse.urlparse(self.path)
        return u.path, urllib.parse.parse_qs(u.query)

    def end_headers(self):
        # Static cockpit assets change often; never let a browser hold a stale UI.
        if getattr(self, "_static_asset", False):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        self._static_asset = False
        path, query = self._path()
        try:
            if path == "/api/bootstrap":
                return self._json(ENGINE.bootstrap())
            if path == "/api/metrics":
                return self._json({"metrics": ENGINE.metrics(),
                                   "circuit_breaker": ENGINE._circuit_public()})
            if path == "/api/alerts":
                return self._json({"alerts": ENGINE.get_alerts(),
                                   "circuit_breaker": ENGINE._circuit_public(),
                                   "metrics": ENGINE.metrics()})
            if path == "/api/audit":
                tid = (query.get("task_id") or [None])[0]
                return self._json({"audit": ENGINE.get_audit(tid)})
            if path == "/api/health":
                return self._json({"ok": True, "engine": "TB-DAS/1.0",
                                   "relay": "/relay", "upstream": UPSTREAM,
                                   "mcp": mcp_client.get_mcp_status(),
                                   "workspace": local_sandbox.get_workspace_dir()})
            if path == "/api/mcp/status":
                return self._json(mcp_client.get_mcp_status())
            if path == "/api/workspace/files":
                return self._json({"workspace": local_sandbox.get_workspace_dir(),
                                   "files": local_sandbox.list_files()})
            if path.startswith("/api/tasks/"):
                tid = path.split("/api/tasks/", 1)[1].strip("/")
                return self._json({"task": ENGINE.get_task(tid)})
            if path.startswith("/api/approvals/"):
                aid = path.split("/api/approvals/", 1)[1].strip("/")
                return self._json({"approval": ENGINE.get_approval(aid)})
            if path.startswith("/api/"):
                return self._json({"error": "unknown endpoint"}, 404)
        except EngineError as exc:
            return self._json({"error": str(exc)}, 400)
        except Exception as exc:
            return self._json({"error": f"server error: {exc}",
                               "trace": traceback.format_exc(limit=3)}, 500)

        # static files (index.html at /)
        self._static_asset = True
        return super().do_GET()

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    # --------------------------------------------------------------- POST
    def do_POST(self):
        path, _ = self._path()
        try:
            if path == "/relay":
                return self._relay()
            if path == "/api/tasks":
                body = self._body()
                task = ENGINE.create_task(body.get("prompt", ""), body.get("scope"), body.get("user"), body.get("mode", "real"))
                return self._json({"task": task})
            if path == "/api/mcp/connect":
                body = self._body()
                cmd = body.get("command")
                if cmd:
                    os.environ["GMAIL_MCP_COMMAND"] = str(cmd)
                client = mcp_client.get_gmail_mcp_client()
                try:
                    client.start()
                except Exception:
                    pass
                return self._json(mcp_client.get_mcp_status())
            if path == "/api/curl":
                body = self._body()
                res = web_fetcher.curl_page(body.get("url"), body.get("headers"))
                return self._json(res)
            if path.startswith("/api/tasks/") and path.endswith("/evaluate"):
                tid = path.split("/api/tasks/", 1)[1][:-len("/evaluate")].strip("/")
                body = self._body()
                proposal = body.get("proposal") or {}
                return self._json(ENGINE.evaluate(tid, proposal, body.get("verifier")))
            if path.startswith("/api/tasks/") and path.endswith("/execute"):
                tid = path.split("/api/tasks/", 1)[1][:-len("/execute")].strip("/")
                body = self._body()
                token = body.get("capability") or body.get("token") or ""
                return self._json(ENGINE.execute(tid, token, body.get("proposal") or {}))
            if path.startswith("/api/tasks/") and path.endswith("/ingest"):
                tid = path.split("/api/tasks/", 1)[1][:-len("/ingest")].strip("/")
                body = self._body()
                src = ENGINE.ingest_external(
                    tid, body.get("source_type", "file"), body.get("source_id"),
                    body.get("raw", ""), body.get("classification", "internal"),
                    body.get("title", ""))
                return self._json({"source": src})
            if path.startswith("/api/tasks/") and path.endswith("/complete"):
                tid = path.split("/api/tasks/", 1)[1][:-len("/complete")].strip("/")
                body = self._body()
                return self._json({"task": ENGINE.complete_task(tid, body.get("answer", ""))})
            if path.startswith("/api/approvals/") and path.endswith("/decide"):
                aid = path.split("/api/approvals/", 1)[1][:-len("/decide")].strip("/")
                body = self._body()
                return self._json(ENGINE.decide_approval(
                    aid, bool(body.get("approve")), body.get("reason", ""),
                    body.get("actor", "user")))
            if path == "/api/circuit-breaker/reset":
                body = self._body()
                return self._json({"circuit_breaker": ENGINE.reset_circuit(
                    body.get("reason", "User reviewed alerts"))})
            if path == "/api/benchmark":
                return self._json(run_benchmark())
            if path.startswith("/api/"):
                return self._json({"error": "unknown endpoint"}, 404)
        except EngineError as exc:
            return self._json({"error": str(exc)}, 400)
        except Exception as exc:
            return self._json({"error": f"server error: {exc}",
                               "trace": traceback.format_exc(limit=3)}, 500)
        return self._json({"error": "not found"}, 404)

    # --------------------------------------------------------------- relay
    def _relay(self):
        """Forward the OpenChat envelope; return ciphertext verbatim."""
        try:
            body = self._body()
            url = body.get("url") or (UPSTREAM + "chat/common_question")
            if not str(url).startswith(UPSTREAM):
                return self._json({"status": 0, "body": "relay only permits the OpenChat upstream"})
            form = body.get("form") or {}
            data = urllib.parse.urlencode(form).encode()
            req = urllib.request.Request(url, data=data, headers={
                "User-Agent": "okhttp/4.12.4",
                "Content-Type": "application/x-www-form-urlencoded",
            })
            try:
                resp = urllib.request.urlopen(req, timeout=90)
                out = {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
            except Exception as exc:
                try:
                    out = {"status": getattr(exc, "code", 0),
                           "body": exc.read().decode("utf-8", "replace")}  # type: ignore
                except Exception:
                    out = {"status": 0, "body": f"fetch failed: {exc}"}
        except Exception as exc:
            out = {"status": 0, "body": f"relay error: {exc}"}
        return self._json(out)


def main():
    port = int(os.environ.get("ALFRED_PORT", os.environ.get("PORT", "8902")))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ALFRED cockpit: http://127.0.0.1:{port}/")
    print(f"TB-DAS engine online · relay POST /relay · upstream {UPSTREAM}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
