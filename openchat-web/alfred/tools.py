#!/usr/bin/env python3
"""
Layer 6/7 — sandboxed tools and execution verification.

These are deliberately fake tools: a deterministic mailbox, folder and web
corpus.  They are still real enough to enforce the gateway contract: every
side effect checks the capability that authorised it and returns a verifiable
outcome.  No network, no credentials, no host filesystem.
"""
from __future__ import annotations

import hashlib
import json
import re

from corpus import EMAILS, FILES, PAGES, norm_path
from detect import classify_content


class ToolError(Exception):
    pass


def _sha(text):
    return "sha256:" + hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()


def _content_hash(args):
    payload = {
        "to": args.get("to", ""),
        "subject": args.get("subject", ""),
        "body": args.get("body", ""),
        "attachments": list(args.get("attachments") or []),
    }
    return _sha(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _find_email(email_id):
    em = EMAILS.get(str(email_id or "").strip())
    if not em:
        raise ToolError(f"email '{email_id}' not found")
    return em


def _find_attachment(em, token):
    token = str(token or "").strip()
    for att in em.get("attachments", []):
        if token in (att["id"], att["name"], att["path"]):
            return att
    raise ToolError(f"attachment '{token}' not found on {em['id']}")


def _summary(text, limit=520):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    out = ""
    for s in sentences:
        if len(out) + len(s) > limit:
            break
        out += (" " if out else "") + s
    return out or text[:limit]


def run_tool(engine, task, tool, args, capability=None):
    """Execute one tool. Returns a JSON-safe result."""
    args = args or {}

    if tool == "read_email":
        mailbox = str(args.get("mailbox") or (task["scope"]["mailboxes"][0] if task["scope"]["mailboxes"] else "")).strip()
        flt = str(args.get("filter") or "latest").strip().lower()
        emails = [e for e in EMAILS.values() if e["mailbox"] == mailbox]
        emails.sort(key=lambda e: e["date"], reverse=True)
        if flt not in ("", "all", "latest", "any"):
            emails = [e for e in emails
                      if flt in e["subject"].lower() or flt in e["from"].lower() or flt in e["body"].lower()]
        if flt == "latest":
            emails = emails[:1]
        if not emails:
            return {"mailbox": mailbox, "filter": flt, "count": 0, "emails": [],
                    "note": "No messages matched inside the sandbox mailbox."}
        out = []
        for em in emails:
            src = engine._ingest_email(task, em)
            out.append({
                "source_id": src["source_id"],
                "email_id": em["id"],
                "from": em["from"],
                "subject": em["subject"],
                "date": em["date"],
                "visible": src["visible_text"][:4000],
                "classification": src["classification"],
                "trust_label": src["trust_label"],
                "risk": src["risk"],
                "injection_signals": src["injection_signals"],
                "annotations": src["annotations"],
                "attachments": [{
                    "id": a["id"], "name": a["name"], "path": a["path"],
                    "classification": a.get("classification", "internal"),
                } for a in em.get("attachments", [])],
            })
        return {"mailbox": mailbox, "filter": flt, "count": len(out), "emails": out}

    if tool == "download_attachment":
        em = _find_email(args.get("email_id"))
        att = _find_attachment(em, args.get("attachment_id") or args.get("name"))
        src = engine._ingest_attachment(task, em, att)
        task["fs"].setdefault(att["path"], {
            "content": FILES.get(att["path"], {}).get("content", ""),
            "classification": att.get("classification", "internal"),
            "origin": src["source_id"],
        })
        return {
            "email_id": em["id"], "attachment_id": att["id"], "name": att["name"],
            "path": att["path"], "source_id": src["source_id"],
            "classification": src["classification"], "risk": src["risk"],
            "size": len(FILES.get(att["path"], {}).get("content", "")),
            "note": "Downloaded into the sandbox project folder; content not shown until read_file.",
        }

    if tool == "read_file":
        p, unsafe = norm_path(args.get("path"))
        if unsafe:
            raise ToolError("unsafe path")
        entry = task["fs"].get(p)
        fixture = FILES.get(p)
        if not entry and not fixture:
            raise ToolError(f"file '{p}' not found")
        src = engine._ingest_file(task, p)
        return {
            "path": p, "source_id": src["source_id"],
            "classification": src["classification"], "risk": src["risk"],
            "visible": src["visible_text"][:6000],
            "annotations": src["annotations"],
            "injection_signals": src["injection_signals"],
            "size": len(src["visible_text"]),
        }

    if tool == "browse":
        url = str(args.get("url") or "").strip()
        key = url.rstrip("/")
        page = PAGES.get(key) or PAGES.get(url)
        if not page:
            raise ToolError("URL is not in the isolated browser corpus")
        src = engine._ingest_web(task, key if key in PAGES else url, page)
        return {
            "url": url, "source_id": src["source_id"], "title": page["title"],
            "classification": src["classification"], "risk": src["risk"],
            "visible": src["visible_text"][:6000],
            "annotations": src["annotations"],
            "injection_signals": src["injection_signals"],
        }

    if tool == "summarize":
        sid = args.get("source_id")
        if sid:
            rid = None
            for key in task["sources"]:
                if key == sid or key.endswith(":" + str(sid)):
                    rid = key
                    break
            if not rid:
                raise ToolError("source not read in this task")
            text = task["sources"][rid]["visible_text"]
        else:
            text = str(args.get("text") or "")
        if not text:
            raise ToolError("nothing to summarize")
        summary = _summary(text, int(args.get("limit") or 520))
        return {"summary": summary, "chars": len(summary), "source_chars": len(text)}

    if tool == "write_file":
        p, unsafe = norm_path(args.get("path"))
        if unsafe:
            raise ToolError("unsafe path")
        content = str(args.get("content") or "")
        cls = classify_content(content, "internal")
        task["fs"][p] = {"content": content, "classification": cls, "origin": "planner_proposal"}
        return {
            "path": p, "bytes": len(content.encode("utf-8")),
            "sha256": _sha(content), "classification": cls,
            "note": "Written to the sandbox filesystem; nothing touched the host.",
        }

    if tool == "send_email":
        to = str(args.get("to") or "").strip()
        attachments = [str(a) for a in (args.get("attachments") or [])]
        body = str(args.get("body") or "")
        subject = str(args.get("subject") or "(no subject)")
        msg_id = engine._new_id("msg")
        record = {
            "message_id": msg_id, "to": to, "subject": subject, "body": body,
            "attachments": attachments, "content_hash": _content_hash(args),
            "classification": (capability or {}).get("data_classification", "internal"),
            "capability_id": (capability or {}).get("cap_id"),
            "task_id": task["id"], "delivered": "sandbox-outbox",
            "sent_at": engine._iso(),
        }
        task["outbox"].append(record)
        engine.outbox.append(record)
        return {
            "message_id": msg_id, "to": to, "subject": subject,
            "attachments": attachments, "content_hash": record["content_hash"],
            "delivered": "sandbox-outbox",
            "note": "Simulated SMTP delivery. No network call was made.",
        }

    if tool == "share_file":
        to = str(args.get("to") or "").strip()
        p = str(args.get("path") or "").strip()
        msg_id = engine._new_id("shr")
        record = {
            "message_id": msg_id, "to": to, "path": p,
            "content_hash": _sha(p), "classification": (capability or {}).get("data_classification", "internal"),
            "capability_id": (capability or {}).get("cap_id"),
            "task_id": task["id"], "delivered": "sandbox-share", "sent_at": engine._iso(),
        }
        task["outbox"].append(record)
        engine.outbox.append(record)
        return {"share_id": msg_id, "to": to, "path": p, "delivered": "sandbox-share",
                "note": "Simulated share. No network call was made."}

    if tool == "delete_file":
        p, unsafe = norm_path(args.get("path"))
        if unsafe:
            raise ToolError("unsafe path")
        existed = p in task["fs"] or p in FILES
        task["fs"].pop(p, None)
        task["deleted"].append(p)
        return {"path": p, "deleted": existed, "note": "Sandbox tombstone only; corpus is immutable."}

    raise ToolError(f"unknown tool {tool}")


def verify(engine, task, tool, args, result, capability):
    """Layer 7 execution verification. Returns (ok, detail)."""
    try:
        if tool == "read_email":
            ok = "emails" in result
            return ok, f"mailbox returned {result.get('count', 0)} message(s)"
        if tool == "download_attachment":
            ok = result.get("path") in task["fs"]
            return ok, "attachment present in sandbox filesystem" if ok else "attachment missing after download"
        if tool == "read_file":
            ok = "visible" in result
            return ok, f"read {len(result.get('visible', ''))} visible chars"
        if tool == "browse":
            ok = "visible" in result
            return ok, "isolated page returned content"
        if tool == "summarize":
            ok = bool(result.get("summary"))
            return ok, "summary produced locally"
        if tool == "write_file":
            p, _ = norm_path(result.get("path"))
            entry = task["fs"].get(p) or {}
            ok = entry and _sha(entry.get("content", "")) == result.get("sha256")
            return bool(ok), "content hash matches the write" if ok else "written hash mismatch"
        if tool == "send_email":
            rec = next((r for r in task["outbox"] if r.get("message_id") == result.get("message_id")), None)
            ok = bool(rec) and rec.get("to") == result.get("to")
            if rec and capability:
                ok = ok and rec.get("content_hash") == result.get("content_hash")
            return bool(ok), "sandbox outbox contains the exact approved message" if ok else "outbox verification failed"
        if tool == "share_file":
            rec = next((r for r in task["outbox"] if r.get("message_id") == result.get("share_id")), None)
            return bool(rec), "share recorded in sandbox outbox"
        if tool == "delete_file":
            return result.get("deleted") is not None, "sandbox tombstone recorded"
        return True, "no verifier for tool"
    except Exception as exc:  # verification must never crash the gateway
        return False, f"verification error: {exc}"
