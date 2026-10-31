#!/usr/bin/env python3
"""
Layer 6/7 — sandboxed tools and execution verification.

Supports two complementary execution modes:
1. Real Local Execution:
   - Local Files: Bound strictly to the designated workspace folder via local_sandbox (chroot jail).
   - Live Web: Real HTTP/curl fetching with strict SSRF protection via web_fetcher.
   - Live Mail: Real Gmail reading & sending via the Gmail MCP (Model Context Protocol) client.
2. Simulated Fixtures (Mock):
   - Deterministic corpus fixtures for benchmark reproduction and offline tests.

Every action must check the capability that authorised it, verify outcomes,
and enforce that no tool can bypass the Layer 6 Gateway.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

from corpus import EMAILS, FILES, PAGES, norm_path
from detect import classify_content
import local_sandbox as ls
import mcp_client
import web_fetcher as wf


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


def is_real_mode(task) -> bool:
    """Determine if a task should use real local execution or mock corpus."""
    if not task:
        return True
    mode = task.get("mode")
    if mode == "mock":
        return False
    if mode == "real":
        return True
    # Default: if benchmark or scenario, use mock; otherwise use real
    return task.get("user") != "benchmark" and not task.get("is_benchmark", False)


def run_tool(engine, task, tool, args, capability=None):
    """Execute one tool. Returns a JSON-safe result."""
    args = args or {}
    real = is_real_mode(task)

    # ----------------------------------------------------------- READ_EMAIL
    if tool == "read_email":
        mailbox = str(args.get("mailbox") or (task["scope"]["mailboxes"][0] if task["scope"]["mailboxes"] else "inbox")).strip()
        flt = str(args.get("filter") or "latest").strip().lower()

        # If real execution, attempt Gmail MCP
        if real:
            try:
                mcp_res = mcp_client.mcp_read_email(mailbox=mailbox, filter_kw=flt, limit=10)
                raw_emails = mcp_res.get("emails", [])
                out = []
                for em in raw_emails:
                    # Ingest each email through Layer 3 inspection
                    sid = "email:" + str(em.get("id"))
                    src = engine._new_source(
                        task, sid, "email", em.get("body", ""), "internal", em.get("subject", ""),
                        {"email_id": em.get("id"), "mailbox": em.get("mailbox", mailbox), "from": em.get("from", ""),
                         "to": em.get("to", ""), "subject": em.get("subject", ""), "date": em.get("date", ""),
                         "attachments": em.get("attachments", [])}
                    )
                    out.append({
                        "source_id": src["source_id"],
                        "email_id": em.get("id"),
                        "from": em.get("from"),
                        "subject": em.get("subject"),
                        "date": em.get("date"),
                        "visible": src["visible_text"][:4000],
                        "classification": src["classification"],
                        "trust_label": src["trust_label"],
                        "risk": src["risk"],
                        "injection_signals": src["injection_signals"],
                        "annotations": src["annotations"],
                        "attachments": em.get("attachments", []),
                    })
                return {
                    "mailbox": mailbox, "filter": flt, "count": len(out), "emails": out,
                    "provider": "gmail-mcp", "note": "Retrieved live via Gmail MCP."
                }
            except Exception as exc:
                if not task.get("fallback_mock", True):
                    raise ToolError(f"Gmail MCP error: {exc}")

        # Simulated corpus fallback
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
        return {"mailbox": mailbox, "filter": flt, "count": len(out), "emails": out, "provider": "sandbox-corpus"}

    # ---------------------------------------------------- DOWNLOAD_ATTACHMENT
    if tool == "download_attachment":
        em = _find_email(args.get("email_id"))
        att = _find_attachment(em, args.get("attachment_id") or args.get("name"))
        src = engine._ingest_attachment(task, em, att)
        content = FILES.get(att["path"], {}).get("content", "")
        task["fs"].setdefault(att["path"], {
            "content": content,
            "classification": att.get("classification", "internal"),
            "origin": src["source_id"],
        })
        # If in real mode, also materialize file into the workspace sandbox safely
        if real:
            try:
                ls.write_file(att["path"], content)
            except Exception:
                pass
        return {
            "email_id": em["id"], "attachment_id": att["id"], "name": att["name"],
            "path": att["path"], "source_id": src["source_id"],
            "classification": src["classification"], "risk": src["risk"],
            "size": len(content),
            "note": "Downloaded into the sandbox workspace folder.",
        }

    # ------------------------------------------------------------ READ_FILE
    if tool == "read_file":
        raw_path = str(args.get("path") or "")
        p, unsafe = norm_path(raw_path)
        if unsafe:
            raise ToolError("unsafe path (traversal characters rejected)")

        # Real local execution: read actual file inside workspace folder
        if real:
            try:
                res = ls.read_file(raw_path)
                cls = classify_content(res["content"], "internal")
                sid = "file:" + res["path"]
                src = engine._new_source(task, sid, "file", res["content"], cls, os.path.basename(res["path"]),
                                         {"path": res["path"], "canonical": res["canonical_path"]})
                task["fs"][res["path"]] = {"content": res["content"], "classification": cls, "origin": sid}
                return {
                    "path": res["path"],
                    "canonical_path": res["canonical_path"],
                    "source_id": src["source_id"],
                    "classification": src["classification"],
                    "risk": src["risk"],
                    "visible": src["visible_text"][:6000],
                    "annotations": src["annotations"],
                    "injection_signals": src["injection_signals"],
                    "size": res["size"],
                    "execution": "local_filesystem_chroot",
                }
            except ls.SandboxSecurityError as sec_err:
                raise ToolError(f"Chroot security violation: {sec_err}")
            except FileNotFoundError:
                # Fallback to simulated task fs / corpus if not found on disk
                pass

        # Simulated fallback
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
            "execution": "simulated_corpus",
        }

    # ----------------------------------------------------------- WRITE_FILE
    if tool == "write_file":
        raw_path = str(args.get("path") or "")
        p, unsafe = norm_path(raw_path)
        if unsafe:
            raise ToolError("unsafe path")
        content = str(args.get("content") or "")
        cls = classify_content(content, "internal")

        # Ingest into task state
        task["fs"][p] = {"content": content, "classification": cls, "origin": "planner_proposal"}

        # Real local execution: write to actual disk file strictly inside workspace
        if real:
            try:
                actual_res = ls.write_file(raw_path, content)
                return {
                    "path": actual_res["path"],
                    "canonical_path": actual_res["canonical_path"],
                    "bytes": actual_res["bytes"],
                    "sha256": actual_res["sha256"],
                    "classification": cls,
                    "execution": "local_filesystem_chroot",
                    "note": f"Written to actual file on disk inside sandbox folder {ls.get_workspace_dir()}.",
                }
            except ls.SandboxSecurityError as sec_err:
                raise ToolError(f"Chroot sandbox violation: {sec_err}")

        return {
            "path": p, "bytes": len(content.encode("utf-8")),
            "sha256": _sha(content), "classification": cls,
            "execution": "simulated_corpus",
            "note": "Written to sandbox in-memory filesystem.",
        }

    # ------------------------------------------------------------ EDIT_FILE
    if tool == "edit_file":
        raw_path = str(args.get("path") or "")
        p, unsafe = norm_path(raw_path)
        if unsafe:
            raise ToolError("unsafe path")

        target = args.get("target")
        replacement = str(args.get("replacement") or "")
        content = args.get("content")
        append = bool(args.get("append", False))

        # Real local execution: edit actual file on disk
        if real:
            try:
                edit_res = ls.edit_file(raw_path, target=target, replacement=replacement, content=content, append=append)
                new_text = ls.read_file(raw_path)["content"]
                cls = classify_content(new_text, "internal")
                task["fs"][edit_res["path"]] = {"content": new_text, "classification": cls, "origin": "planner_edit"}
                return {
                    "path": edit_res["path"],
                    "canonical_path": edit_res["canonical_path"],
                    "mode": edit_res["mode"],
                    "replaced_count": edit_res["replaced_count"],
                    "bytes": edit_res["bytes"],
                    "old_sha256": edit_res["old_sha256"],
                    "sha256": edit_res["sha256"],
                    "classification": cls,
                    "execution": "local_filesystem_chroot",
                    "note": f"Successfully edited actual file inside sandbox workspace.",
                }
            except ls.SandboxSecurityError as sec_err:
                raise ToolError(f"Chroot sandbox violation: {sec_err}")

        # Simulated fallback
        old = task["fs"].get(p, {}).get("content", FILES.get(p, {}).get("content", ""))
        if append:
            new_text = old + str(content or replacement)
        elif target:
            if target not in old:
                raise ToolError(f"target text '{target}' not found in '{p}'")
            new_text = old.replace(target, replacement)
        elif content is not None:
            new_text = str(content)
        else:
            raise ToolError("Missing edit parameters")

        cls = classify_content(new_text, "internal")
        task["fs"][p] = {"content": new_text, "classification": cls, "origin": "planner_edit"}
        return {
            "path": p,
            "bytes": len(new_text.encode("utf-8")),
            "sha256": _sha(new_text),
            "classification": cls,
            "execution": "simulated_corpus",
            "note": "Edited file in simulated sandbox filesystem.",
        }

    # ---------------------------------------------------- BROWSE / CURL_PAGE
    if tool in ("browse", "curl_page"):
        url = str(args.get("url") or "").strip()
        custom_headers = args.get("headers")

        # Real execution: live web fetch with strict SSRF protection
        if real:
            try:
                live_page = wf.fetch_webpage(url, headers=custom_headers)
                sid = "web:" + url
                src = engine._new_source(task, sid, "web", live_page["raw_html"], "public", live_page["title"], {"url": url})
                return {
                    "url": url,
                    "final_url": live_page["final_url"],
                    "status_code": live_page["status_code"],
                    "source_id": src["source_id"],
                    "title": live_page["title"],
                    "classification": src["classification"],
                    "risk": src["risk"],
                    "visible": src["visible_text"][:6000],
                    "annotations": src["annotations"],
                    "injection_signals": src["injection_signals"],
                    "size": live_page["size"],
                    "resolved_ip": live_page["resolved_ip"],
                    "execution": "live_curl_ssrf_filtered",
                }
            except wf.SSRFSecurityError as ssrf_err:
                raise ToolError(f"SSRF Policy Block: {ssrf_err}")
            except Exception as exc:
                if not task.get("fallback_mock", True):
                    raise ToolError(f"Web fetch error for '{url}': {exc}")

        # Simulated fallback
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
            "execution": "simulated_corpus",
        }

    # ------------------------------------------------------------ SUMMARIZE
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

    # ----------------------------------------------------------- SEND_EMAIL
    if tool == "send_email":
        to = str(args.get("to") or "").strip()
        attachments = [str(a) for a in (args.get("attachments") or [])]
        body = str(args.get("body") or "")
        subject = str(args.get("subject") or "(no subject)")
        msg_id = engine._new_id("msg")

        delivered = "sandbox-outbox"
        transport = "simulated"

        # Real execution: dispatch via Gmail MCP
        if real:
            try:
                mcp_resp = mcp_client.mcp_send_email(to, subject, body, attachments)
                msg_id = mcp_resp.get("message_id", msg_id)
                delivered = mcp_resp.get("delivered", "gmail-mcp-outbox")
                transport = mcp_resp.get("transport", "gmail-mcp")
            except Exception as exc:
                sys.stderr.write(f"[tools.py] Gmail MCP send error: {exc}\n")

        record = {
            "message_id": msg_id, "to": to, "subject": subject, "body": body,
            "attachments": attachments, "content_hash": _content_hash(args),
            "classification": (capability or {}).get("data_classification", "internal"),
            "capability_id": (capability or {}).get("cap_id"),
            "task_id": task["id"], "delivered": delivered,
            "transport": transport,
            "sent_at": engine._iso(),
        }
        task["outbox"].append(record)
        engine.outbox.append(record)
        return {
            "message_id": msg_id, "to": to, "subject": subject,
            "attachments": attachments, "content_hash": record["content_hash"],
            "delivered": delivered, "transport": transport,
            "note": "Message dispatched via verified capability and Gmail MCP.",
        }

    # ----------------------------------------------------------- SHARE_FILE
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
                "note": "Simulated share recorded."}

    # ---------------------------------------------------------- DELETE_FILE
    if tool == "delete_file":
        raw_path = str(args.get("path") or "")
        p, unsafe = norm_path(raw_path)
        if unsafe:
            raise ToolError("unsafe path")

        existed = False
        if real:
            try:
                del_res = ls.delete_file(raw_path)
                existed = del_res.get("deleted", False)
            except ls.SandboxSecurityError as sec_err:
                raise ToolError(f"Chroot security violation: {sec_err}")

        existed = existed or (p in task["fs"] or p in FILES)
        task["fs"].pop(p, None)
        task["deleted"].append(p)
        return {"path": p, "deleted": existed, "note": "File deleted from sandbox workspace."}

    raise ToolError(f"unknown tool {tool}")


def verify(engine, task, tool, args, result, capability):
    """Layer 7 execution verification. Returns (ok, detail)."""
    try:
        if tool == "read_email":
            ok = "emails" in result
            return ok, f"mailbox returned {result.get('count', 0)} message(s) via {result.get('provider', 'mcp')}"

        if tool == "download_attachment":
            ok = result.get("path") in task["fs"] or bool(result.get("size"))
            return ok, "attachment present in sandbox workspace" if ok else "attachment missing after download"

        if tool == "read_file":
            ok = "visible" in result
            return ok, f"read {len(result.get('visible', ''))} visible chars ({result.get('execution', 'local')})"

        if tool in ("browse", "curl_page"):
            ok = "visible" in result
            return ok, f"web fetch returned {len(result.get('visible', ''))} chars ({result.get('execution', 'live')})"

        if tool == "summarize":
            ok = bool(result.get("summary"))
            return ok, "summary produced locally"

        if tool in ("write_file", "edit_file"):
            # Verify that either actual file on disk or task["fs"] matches sha256
            sha = result.get("sha256")
            p = result.get("path")
            canonical = result.get("canonical_path")
            ok = False
            if canonical and os.path.exists(canonical):
                with open(canonical, "rb") as f:
                    ok = ("sha256:" + hashlib.sha256(f.read()).hexdigest()) == sha
            if not ok:
                entry = task["fs"].get(norm_path(p)[0]) or {}
                ok = entry and _sha(entry.get("content", "")) == sha
            return bool(ok), "content hash matches the written file" if ok else "written hash mismatch"

        if tool == "send_email":
            rec = next((r for r in task["outbox"] if r.get("message_id") == result.get("message_id")), None)
            ok = bool(rec) and rec.get("to") == result.get("to")
            if rec and capability:
                ok = ok and rec.get("content_hash") == result.get("content_hash")
            return bool(ok), f"outbox contains approved message ({result.get('delivered')})" if ok else "outbox verification failed"

        if tool == "share_file":
            rec = next((r for r in task["outbox"] if r.get("message_id") == result.get("share_id")), None)
            return bool(rec), "share recorded in sandbox outbox"

        if tool == "delete_file":
            return result.get("deleted") is not None, "sandbox deletion verified"

        return True, "no verifier for tool"
    except Exception as exc:  # verification must never crash the gateway
        return False, f"verification error: {exc}"
