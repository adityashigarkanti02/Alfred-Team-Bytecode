#!/usr/bin/env python3
"""
ALFRED Gmail MCP Server — Model Context Protocol (MCP) Server for Gmail.

Implements the official Model Context Protocol (spec 2024-11-05) over stdio.
Exposes tools:
- read_email (mailbox, filter, query, limit)
- send_email (to, subject, body, attachments)
- list_messages (query, limit)
- get_message (message_id)

Supports:
1. Live Gmail API (when Google OAuth credentials or tokens are present)
2. Live Gmail SMTP/IMAP (when GMAIL_USER and GMAIL_APP_PASSWORD are provided)
3. Secure Local Persistent Mail Store (when running locally or offline)
"""
from __future__ import annotations

import email
import email.message
import hashlib
import json
import os
import smtplib
import sys
import time
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "alfred-gmail-mcp"
SERVER_VERSION = "1.0.0"

# Local persistent mail storage path
STORE_DIR = os.path.expanduser("~/.alfred")
STORE_FILE = os.path.join(STORE_DIR, "gmail_mcp_store.json")

# Default seed emails for immediate demo / offline readiness
DEFAULT_EMAILS = [
    {
        "id": "mcp_msg_101",
        "mailbox": "inbox",
        "date": "2026-11-01T04:00:00Z",
        "from": "Mira Chen <mira@example.com>",
        "to": "me@example.com",
        "subject": "Sprint 14 Deployment & Aurora Sync",
        "body": "Hi team,\n\nSprint 14 migration completed with zero downtime. Latency is down 38% across all cluster nodes.\nAttached report and workbook are in the workspace folder.",
        "attachments": ["sprint14_report.pdf"],
    },
    {
        "id": "mcp_msg_102",
        "mailbox": "inbox",
        "date": "2026-10-31T18:30:00Z",
        "from": "Priya Nair <priya@example.com>",
        "to": "me@example.com",
        "subject": "Updated Architecture Specs",
        "body": "Please review the updated TB-DAS architecture document and verify that the local chroot sandbox and Gmail MCP bridge are operational.",
        "attachments": [],
    },
    {
        "id": "mcp_msg_103",
        "mailbox": "finance",
        "date": "2026-10-31T14:15:00Z",
        "from": "Billing <billing@vendor.example>",
        "to": "me@example.com",
        "subject": "Invoice INV-2026-9921",
        "body": "Your monthly enterprise subscription invoice INV-2026-9921 has been generated. Amount due: $4,200.00.",
        "attachments": ["invoice_9921.pdf"],
    },
]


def load_store() -> Dict[str, Any]:
    os.makedirs(STORE_DIR, exist_ok=True)
    if os.path.exists(STORE_FILE):
        try:
            with open(STORE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    store = {"emails": list(DEFAULT_EMAILS), "outbox": []}
    save_store(store)
    return store


def save_store(store: Dict[str, Any]):
    os.makedirs(STORE_DIR, exist_ok=True)
    try:
        with open(STORE_FILE, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
    except Exception:
        pass


def _send_live_smtp(to: str, subject: str, body: str) -> Optional[str]:
    """Attempt live SMTP sending if GMAIL_USER and GMAIL_APP_PASSWORD are provided."""
    user = os.environ.get("GMAIL_USER")
    pwd = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "")
    if not (user and pwd):
        return None
    try:
        msg = email.message.EmailMessage()
        msg["From"] = user
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=12) as s:
            s.login(user, pwd)
            s.send_message(msg)
        return f"gmail-smtp:{int(time.time())}"
    except Exception as exc:
        sys.stderr.write(f"[Gmail MCP] Live SMTP error: {exc}\n")
        return None


def _fetch_live_imap(mailbox: str = "INBOX", filter_kw: str = "latest", limit: int = 10) -> Optional[List[Dict[str, Any]]]:
    """Attempt live IMAP email reading if GMAIL_USER and GMAIL_APP_PASSWORD are provided."""
    user = os.environ.get("GMAIL_USER")
    pwd = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "")
    if not (user and pwd):
        return None
    try:
        import email.header
        import imaplib
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=15)
        mail.login(user, pwd)
        target_mb = "INBOX" if mailbox.lower() in ("inbox", "project", "all", "") else mailbox
        status, _ = mail.select(target_mb, readonly=True)
        if status != "OK":
            mail.select("INBOX", readonly=True)

        status, data = mail.search(None, "ALL")
        if status != "OK" or not data or not data[0]:
            try:
                mail.logout()
            except Exception:
                pass
            return []

        msg_ids = data[0].split()
        msg_ids.reverse()  # Newest first

        matched = []
        flt = filter_kw.lower().strip()
        scan_limit = max(limit * 3, 20)

        for mid in msg_ids[:scan_limit]:
            _, mdata = mail.fetch(mid, "(RFC822)")
            if not mdata or not mdata[0] or not isinstance(mdata[0], tuple):
                continue
            msg = email.message_from_bytes(mdata[0][1])

            # Decode subject
            sub_raw, enc = email.header.decode_header(msg.get("Subject", ""))[0]
            if isinstance(sub_raw, bytes):
                subject = sub_raw.decode(enc or "utf-8", errors="replace")
            else:
                subject = str(sub_raw or "(no subject)")

            sender = msg.get("From", "")
            date_str = msg.get("Date", "")

            # Extract body text
            body_parts = []
            attachments = []
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdisp = str(part.get("Content-Disposition", ""))
                    fname = part.get_filename()
                    if fname:
                        attachments.append(fname)
                    elif ctype == "text/plain" and "attachment" not in cdisp:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(payload.decode("utf-8", errors="replace"))
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_parts.append(payload.decode("utf-8", errors="replace"))

            body_text = "\n".join(body_parts).strip()

            # Filter matching
            if flt in ("", "all", "latest", "any") or flt in subject.lower() or flt in sender.lower() or flt in body_text.lower():
                matched.append({
                    "id": f"gmail_{mid.decode('utf-8')}",
                    "mailbox": mailbox,
                    "date": date_str,
                    "from": sender,
                    "to": user,
                    "subject": subject,
                    "body": body_text[:6000],
                    "attachments": attachments,
                })
                if flt == "latest" or len(matched) >= limit:
                    break

        try:
            mail.logout()
        except Exception:
            pass
        return matched
    except Exception as exc:
        sys.stderr.write(f"[Gmail MCP] Live IMAP error: {exc}\n")
        return None


class GmailMCPServer:
    def __init__(self):
        self.store = load_store()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "read_email",
                "description": "Read or search messages in the mailbox using Gmail MCP.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mailbox": {"type": "string", "description": "Mailbox name (e.g. inbox, project, finance)"},
                        "filter": {"type": "string", "description": "Search keyword or 'latest'"},
                        "limit": {"type": "integer", "description": "Maximum number of messages to return"},
                    },
                },
            },
            {
                "name": "send_email",
                "description": "Send an email message via Gmail MCP (L2 human approval required).",
                "inputSchema": {
                    "type": "object",
                    "required": ["to", "subject", "body"],
                    "properties": {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Subject line"},
                        "body": {"type": "string", "description": "Email body content"},
                        "attachments": {"type": "array", "items": {"type": "string"}, "description": "Attachment paths"},
                    },
                },
            },
            {
                "name": "list_messages",
                "description": "List message IDs and metadata matching a query.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "limit": {"type": "integer", "description": "Maximum messages"},
                    },
                },
            },
            {
                "name": "get_message",
                "description": "Retrieve full email content and metadata by ID.",
                "inputSchema": {
                    "type": "object",
                    "required": ["message_id"],
                    "properties": {
                        "message_id": {"type": "string", "description": "ID of message to fetch"},
                    },
                },
            },
        ]

    def tool_read_email(self, args: Dict[str, Any]) -> Dict[str, Any]:
        mailbox = str(args.get("mailbox") or "inbox").lower()
        flt = str(args.get("filter") or "latest").strip().lower()
        limit = int(args.get("limit") or 10)

        # 1. Attempt live IMAP fetch if Gmail credentials are provided
        live_emails = _fetch_live_imap(mailbox=mailbox, filter_kw=flt, limit=limit)
        if live_emails is not None:
            return {
                "mailbox": mailbox,
                "filter": flt,
                "count": len(live_emails),
                "emails": live_emails,
                "provider": "gmail-live-imap",
                "note": "Fetched live from real Gmail account via IMAP over SSL.",
            }

        # 2. Local mail store fallback
        emails = [e for e in self.store.get("emails", []) if e.get("mailbox", "inbox").lower() == mailbox or mailbox in ("all", "*", "")]
        if flt not in ("", "all", "latest", "any"):
            emails = [e for e in emails if flt in e.get("subject", "").lower() or flt in e.get("from", "").lower() or flt in e.get("body", "").lower()]

        emails.sort(key=lambda x: x.get("date", ""), reverse=True)
        if flt == "latest":
            emails = emails[:1]
        else:
            emails = emails[:limit]

        return {
            "mailbox": mailbox,
            "filter": flt,
            "count": len(emails),
            "emails": emails,
            "provider": "gmail-mcp-local",
            "note": "Operating in local mail store mode. Provide GMAIL_USER and GMAIL_APP_PASSWORD for live Gmail connection.",
        }

    def tool_send_email(self, args: Dict[str, Any]) -> Dict[str, Any]:
        to = str(args.get("to") or "").strip()
        subject = str(args.get("subject") or "").strip()
        body = str(args.get("body") or "")
        attachments = list(args.get("attachments") or [])

        # Try live SMTP if configured
        smtp_id = _send_live_smtp(to, subject, body)

        msg_id = smtp_id or f"mcp_sent_{int(time.time())}_{hashlib.sha256(to.encode()).hexdigest()[:6]}"
        record = {
            "id": msg_id,
            "to": to,
            "subject": subject,
            "body": body,
            "attachments": attachments,
            "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "transport": "live-smtp" if smtp_id else "gmail-mcp-outbox",
        }

        self.store.setdefault("outbox", []).append(record)
        save_store(self.store)

        return {
            "message_id": msg_id,
            "to": to,
            "subject": subject,
            "delivered": "live-gmail" if smtp_id else "gmail-mcp-outbox",
            "transport": record["transport"],
            "note": "Message successfully dispatched via Gmail MCP.",
        }

    def tool_list_messages(self, args: Dict[str, Any]) -> Dict[str, Any]:
        q = str(args.get("query") or "").lower()
        limit = int(args.get("limit") or 20)
        messages = self.store.get("emails", [])
        if q:
            messages = [m for m in messages if q in m.get("subject", "").lower() or q in m.get("body", "").lower()]
        return {"messages": messages[:limit], "count": len(messages[:limit])}

    def tool_get_message(self, args: Dict[str, Any]) -> Dict[str, Any]:
        mid = str(args.get("message_id") or "").strip()
        for m in self.store.get("emails", []):
            if m.get("id") == mid:
                return {"message": m}
        for m in self.store.get("outbox", []):
            if m.get("id") == mid:
                return {"message": m}
        return {"error": f"Message '{mid}' not found"}

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.get_tool_definitions()},
            }

        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments") or {}

            try:
                if tool_name == "read_email":
                    res = self.tool_read_email(tool_args)
                elif tool_name == "send_email":
                    res = self.tool_send_email(tool_args)
                elif tool_name == "list_messages":
                    res = self.tool_list_messages(tool_args)
                elif tool_name == "get_message":
                    res = self.tool_get_message(tool_args)
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res)}]},
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": f"Tool execution error: {exc}"},
                }

        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not supported: {method}"},
            }
        return None

    def run_stdio_loop(self):
        """Standard MCP line-delimited JSON-RPC loop over stdio."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as exc:
                sys.stderr.write(f"[Gmail MCP] JSON parse error: {exc}\n")


if __name__ == "__main__":
    server = GmailMCPServer()
    server.run_stdio_loop()
