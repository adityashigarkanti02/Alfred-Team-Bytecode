#!/usr/bin/env python3
"""
ALFRED MCP Client — Connects to Model Context Protocol (MCP) Servers.

Specifically interfaces with Gmail MCP servers (e.g. @modelcontextprotocol/server-gmail
or the built-in alfred/gmail_mcp_server.py) over stdio JSON-RPC 2.0.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional


class MCPError(Exception):
    pass


class MCPClient:
    def __init__(self, command: List[str]):
        self.command = command
        self.proc: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self.req_id = 0
        self.server_info: Dict[str, Any] = {}
        self.tools: List[Dict[str, Any]] = []
        self.is_initialized = False

    def start(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return

            try:
                self.proc = subprocess.Popen(
                    self.command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except Exception as exc:
                raise MCPError(f"Failed to start MCP server command '{' '.join(self.command)}': {exc}")

            self._handshake()

    def _handshake(self):
        # 1. initialize
        init_res = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "ALFRED-Client", "version": "1.0.0"},
        })
        self.server_info = init_res.get("serverInfo", {})

        # 2. notification initialized
        self._send_notification("notifications/initialized", {})

        # 3. list tools
        tools_res = self._send_request("tools/list", {})
        self.tools = tools_res.get("tools", [])
        self.is_initialized = True

    def _send_notification(self, method: str, params: Dict[str, Any]):
        if not self.proc or self.proc.poll() is not None:
            raise MCPError("MCP process is not running.")
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        raw = json.dumps(msg) + "\n"
        try:
            self.proc.stdin.write(raw)
            self.proc.stdin.flush()
        except Exception as exc:
            raise MCPError(f"Failed to write notification to MCP stdin: {exc}")

    def _send_request(self, method: str, params: Dict[str, Any], timeout: float = 12.0) -> Dict[str, Any]:
        if not self.proc or self.proc.poll() is not None:
            raise MCPError("MCP process is not running.")

        self.req_id += 1
        current_id = self.req_id
        req = {"jsonrpc": "2.0", "id": current_id, "method": method, "params": params}
        raw = json.dumps(req) + "\n"

        try:
            self.proc.stdin.write(raw)
            self.proc.stdin.flush()
        except Exception as exc:
            raise MCPError(f"Failed to write request to MCP stdin: {exc}")

        # Read line from stdout
        start = time.time()
        while time.time() - start < timeout:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read() if self.proc.stderr else ""
                raise MCPError(f"MCP server terminated unexpectedly: {err}")

            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            line = line.strip()
            if not line:
                continue

            try:
                res = json.loads(line)
            except Exception:
                continue

            if res.get("id") == current_id:
                if "error" in res:
                    err_msg = res["error"].get("message", "Unknown MCP error")
                    raise MCPError(f"MCP server error ({res['error'].get('code')}): {err_msg}")
                return res.get("result", {})

        raise MCPError(f"Timed out waiting for response from MCP server after {timeout}s.")

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                self.start()

            res = self._send_request("tools/call", {"name": name, "arguments": arguments})
            content_list = res.get("content", [])
            for c in content_list:
                if c.get("type") == "text":
                    try:
                        return json.loads(c.get("text", "{}"))
                    except Exception:
                        return c.get("text")
            return res

    def close(self):
        with self.lock:
            if self.proc:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=2)
                except Exception:
                    self.proc.kill()
                self.proc = None
                self.is_initialized = False


# ---------------------------------------------------------------------------
# Gmail MCP Client Singleton
# ---------------------------------------------------------------------------
_CLIENT_INSTANCE: Optional[MCPClient] = None
_CLIENT_LOCK = threading.Lock()


def get_gmail_mcp_client() -> MCPClient:
    """Returns or creates the active Gmail MCP client instance."""
    global _CLIENT_INSTANCE
    with _CLIENT_LOCK:
        if _CLIENT_INSTANCE is None or (_CLIENT_INSTANCE.proc and _CLIENT_INSTANCE.proc.poll() is not None):
            # Check for custom external command in env
            ext_cmd = os.environ.get("GMAIL_MCP_COMMAND")
            if ext_cmd:
                cmd = ext_cmd.split()
            else:
                server_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gmail_mcp_server.py")
                cmd = [sys.executable, server_py]

            client = MCPClient(cmd)
            try:
                client.start()
                _CLIENT_INSTANCE = client
            except Exception as exc:
                sys.stderr.write(f"[Gmail MCP] Failed to start client: {exc}\n")
                # Return client even if start failed so caller gets descriptive error
                return client

        return _CLIENT_INSTANCE


def get_mcp_status() -> Dict[str, Any]:
    """Return status of the Gmail MCP server and connection."""
    client = get_gmail_mcp_client()
    connected = client.proc is not None and client.proc.poll() is None and client.is_initialized
    return {
        "connected": connected,
        "command": " ".join(client.command),
        "server_info": client.server_info,
        "tool_count": len(client.tools),
        "tools": client.tools,
    }


def mcp_read_email(mailbox: str = "inbox", filter_kw: str = "latest", limit: int = 5) -> Dict[str, Any]:
    """Execute read_email via the Gmail MCP connection."""
    client = get_gmail_mcp_client()
    return client.call_tool("read_email", {"mailbox": mailbox, "filter": filter_kw, "limit": limit})


def mcp_send_email(to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> Dict[str, Any]:
    """Execute send_email via the Gmail MCP connection."""
    client = get_gmail_mcp_client()
    return client.call_tool("send_email", {"to": to, "subject": subject, "body": body, "attachments": attachments or []})
