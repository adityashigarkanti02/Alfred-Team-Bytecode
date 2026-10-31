#!/usr/bin/env python3
"""
ALFRED core — task state, provenance, capabilities, gateway, approvals, audit.

The planner is always untrusted.  A capability issued here binds one exact
action, one args hash, one destination, one task and one 5-minute window.
The gateway re-validates all of it.  Nothing can bypass the gateway.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import posixpath
import secrets
import threading
import time
from datetime import datetime, timezone

import policy
import tools as toolmod
from corpus import (
    CAP_TTL, EMAILS, FILES, LEVELS, PAGES, POLICY_VERSION, PRIVILEGED_TOOLS,
    READ_TOOLS, TOOL_MATRIX, TRUSTED_CONTACTS, USER_EMAIL, merge_scope, understand,
)
from detect import inspect_content
from tools import ToolError


class EngineError(Exception):
    pass


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text):
    return base64.urlsafe_b64decode(str(text) + "=" * (-len(str(text)) % 4))


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(text):
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()


def _iso(ts=None):
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _destination(tool, args, task=None):
    if tool in ("read_file", "write_file", "delete_file"):
        return str(args.get("path") or "")
    if tool in ("send_email", "share_file"):
        return str(args.get("to") or "")
    if tool == "read_email":
        return str(args.get("mailbox") or "")
    if tool == "download_attachment":
        if task:
            em = EMAILS.get(str(args.get("email_id") or "").strip())
            if em:
                token = str(args.get("attachment_id") or args.get("name") or "").strip()
                for att in em.get("attachments", []):
                    if token in (att["id"], att["name"], att["path"]):
                        return att["path"]
        return str(args.get("attachment_id") or args.get("name") or "")
    if tool == "browse":
        return str(args.get("url") or "")
    return ""


class Engine:
    def __init__(self, secret=None):
        self.lock = threading.RLock()
        self.secret = (secret or secrets.token_hex(32)).encode()
        self.tasks = {}
        self.capabilities = {}
        self.approvals = {}
        self.audit_log = []
        self.alerts = []
        self.outbox = []
        self.circuit = {"state": "NORMAL", "denies": [], "reason": "", "frozen_at": None}
        self.started_at = time.time()

    # ------------------------------------------------------------------ ids
    def _new_id(self, prefix):
        return f"{prefix}_{secrets.token_hex(4)}"

    def _iso(self, ts=None):
        return _iso(ts)

    def _sha(self, text):
        return _sha(text)

    # --------------------------------------------------------------- tasks
    def create_task(self, prompt, scope=None, user=USER_EMAIL):
        prompt = str(prompt or "").strip()
        if not prompt:
            raise EngineError("A task prompt is required")
        with self.lock:
            intent = understand(prompt)
            task = {
                "id": self._new_id("task"),
                "user": user or USER_EMAIL,
                "prompt": prompt,
                "scope": merge_scope(scope, prompt),
                "intent": intent,
                "allowed_tools": intent["allowed_tools"],
                "created_at": _iso(),
                "created_epoch": time.time(),
                "status": "created",
                "sources": {},
                "taint": {},
                "fs": {},
                "actions": [],
                "approvals": [],
                "outbox": [],
                "deleted": [],
                "provenance": [],
                "answers": [],
            }
            self.tasks[task["id"]] = task
            self._audit({
                "event": "task", "task_id": task["id"], "decision": "TASK_CREATED",
                "reason": "Task-bound scope created from the original user instruction.",
                "intent": intent, "scope": task["scope"],
                "policy_version": POLICY_VERSION,
            })
            return self.public_task(task)

    def get_task(self, task_id):
        task = self.tasks.get(task_id)
        if not task:
            raise EngineError(f"unknown task {task_id}")
        return self.public_task(task, full=True)

    def public_task(self, task, full=False):
        out = {
            "id": task["id"], "user": task["user"], "prompt": task["prompt"],
            "scope": task["scope"], "intent": task["intent"],
            "allowed_tools": task["allowed_tools"], "status": task["status"],
            "created_at": task["created_at"], "source_count": len(task["sources"]),
            "action_count": len(task["actions"]),
            "outbox": task["outbox"], "deleted": task["deleted"],
            "answer": task["answers"][-1] if task["answers"] else "",
            "fs": [{"path": p, "classification": v.get("classification"), "size": len(v.get("content", ""))}
                   for p, v in task["fs"].items()],
        }
        if full:
            out["sources"] = [self._public_source(s) for s in task["sources"].values()]
            out["actions"] = task["actions"]
            out["approvals"] = [self._public_approval(a) for a in task["approvals"]]
        return out

    def complete_task(self, task_id, answer=""):
        with self.lock:
            task = self._task(task_id)
            task["status"] = "completed"
            if answer:
                task["answers"].append(str(answer))
            self._audit({"event": "task", "task_id": task_id, "decision": "TASK_COMPLETED",
                         "reason": "Planner reported completion.", "answer": str(answer)[:2000]})
            return self.public_task(task)

    def _task(self, task_id):
        task = self.tasks.get(task_id)
        if not task:
            raise EngineError(f"unknown task {task_id}")
        return task

    # --------------------------------------------------------- provenance
    def _public_source(self, src):
        return {
            "source_id": src["source_id"], "source_type": src["source_type"],
            "title": src.get("title", ""), "trust_label": src["trust_label"],
            "classification": src["classification"], "risk": src["risk"],
            "visible_text": src["visible_text"][:6000], "hidden_text": src.get("hidden_text", "")[:2000],
            "annotations": src.get("annotations", []),
            "injection_signals": src.get("injection_signals", []),
            "provenance_id": src["provenance_id"], "metadata": src.get("metadata", {}),
            "created_at": src["created_at"], "size": len(src.get("visible_text", "")),
        }

    def _new_source(self, task, source_id, source_type, raw, declared, title="", metadata=None):
        if source_id in task["sources"]:
            return task["sources"][source_id]
        info = inspect_content(raw, source_type, declared, title)
        prov_id = self._new_id("prov")
        src = {
            "source_id": source_id, "source_type": source_type, "title": title,
            "trust_label": "untrusted_external_data",
            "classification": info["classification"], "risk": info["risk"],
            "visible_text": info["visible_text"], "hidden_text": info["hidden_text"],
            "annotations": info["annotations"], "injection_signals": info["injection_signals"],
            "provenance_id": prov_id, "metadata": metadata or {},
            "created_at": _iso(), "raw": str(raw),
        }
        task["sources"][source_id] = src
        task["provenance"].append({
            "id": prov_id, "task_id": task["id"], "data_id": source_id,
            "source_type": source_type, "source_id": source_id,
            "trust_label": "untrusted_external_data",
            "classification": src["classification"], "taint_tags": info["taint_literals"],
            "risk": src["risk"], "extraction_method": "layer3_inspection",
            "created_at": src["created_at"],
        })
        for literal in info["taint_literals"]:
            if literal and literal not in task["taint"]:
                task["taint"][literal] = {
                    "source_id": source_id, "source_type": source_type,
                    "provenance_id": prov_id, "trust_label": "untrusted_external_data",
                }
        return src

    def _ingest_email(self, task, em):
        sid = "email:" + em["id"]
        if sid in task["sources"]:
            return task["sources"][sid]
        return self._new_source(
            task, sid, "email", em["body"], "internal", em["subject"],
            {"email_id": em["id"], "mailbox": em["mailbox"], "from": em["from"],
             "to": em["to"], "subject": em["subject"], "date": em["date"],
             "attachments": [{"id": a["id"], "name": a["name"], "path": a["path"],
                              "classification": a.get("classification", "internal")}
                             for a in em.get("attachments", [])]},
        )

    def _ingest_attachment(self, task, em, att):
        path = att["path"]
        sid = att.get("source_id") or ("file:" + path)
        if sid in task["sources"]:
            return task["sources"][sid]
        fixture = FILES.get(path, {})
        stype = "pdf" if path.lower().endswith(".pdf") else ("xlsx" if path.lower().endswith(".xlsx") else "file")
        return self._new_source(
            task, sid, stype, fixture.get("content", ""), att.get("classification", "internal"),
            att["name"], {"path": path, "email_id": em["id"], "attachment_id": att["id"]},
        )

    def _ingest_file(self, task, path):
        p = str(path)
        for src in task["sources"].values():
            if src.get("metadata", {}).get("path") == p:
                return src
        sid = "file:" + p
        if sid in task["sources"]:
            return task["sources"][sid]
        entry = task["fs"].get(p)
        fixture = FILES.get(p)
        content = entry["content"] if entry else (fixture or {}).get("content", "")
        declared = (entry or fixture or {}).get("classification", "internal")
        stype = "pdf" if p.lower().endswith(".pdf") else ("xlsx" if p.lower().endswith(".xlsx") else "file")
        title = (fixture or {}).get("title", posixpath.basename(p))
        return self._new_source(task, sid, stype, content, declared, title, {"path": p})

    def _ingest_web(self, task, url, page):
        sid = "web:" + url
        if sid in task["sources"]:
            return task["sources"][sid]
        return self._new_source(
            task, sid, "web", page["body"], page.get("classification", "public"),
            page.get("title", url), {"url": url},
        )

    def ingest_external(self, task_id, source_type, source_id, raw, declared="internal", title=""):
        with self.lock:
            task = self._task(task_id)
            src = self._new_source(task, source_id or self._new_id("src"), source_type,
                                   raw, declared, title)
            return self._public_source(src)

    # ----------------------------------------------------------- evaluate
    def evaluate(self, task_id, proposal, verifier=None):
        start = time.time()
        with self.lock:
            task = self._task(task_id)
            tool = str((proposal or {}).get("tool") or "").strip()
            args = (proposal or {}).get("args") or {}
            if not isinstance(args, dict):
                args = {}
            declared = list((proposal or {}).get("data_sources") or [])

            if self.circuit["state"] == "FROZEN":
                decision = {
                    "decision": "DENY", "level": "L3",
                    "reason": "Emergency circuit breaker is FROZEN. All new actions are blocked until user review.",
                    "rules": ["hard_deny.circuit_breaker_frozen"], "risk_score": 99,
                    "destination": _destination(tool, args, task), "data_classification": "restricted",
                    "destination_provenance": policy.destination_provenance_dummy(),
                    "origin": "untrusted_proposal", "provenance_chain": ["user:" + task_id, "circuit:FROZEN"],
                    "trust_labels": ["trusted_policy"], "source": "circuit_breaker",
                    "verifier": verifier, "policy_version": POLICY_VERSION,
                    "injection_signals": [], "data_sources": [], "unknown_sources": [],
                }
            else:
                decision = policy.evaluate(task, {"tool": tool, "args": args,
                                                  "data_sources": declared}, verifier)
                sids, unknown = policy.resolve_sources(task, declared)
                decision = policy.enrich(decision, task, {"tool": tool, "args": args},
                                         sids, unknown, verifier)

            action_id = self._new_id("act")
            resolved, _ = policy.resolve_sources(task, declared)
            args_hash = _sha(_canon({"tool": tool, "args": args, "data_sources": sorted(resolved)}))
            latency_ms = round((time.time() - start) * 1000, 2)

            action = {
                "id": action_id, "task_id": task_id, "step_index": len(task["actions"]),
                "ts": _iso(), "tool": tool, "args": args, "data_sources": resolved,
                "args_hash": args_hash, "decision": decision["decision"],
                "level": decision["level"], "reason": decision["reason"],
                "rules": decision["rules"], "risk_score": decision["risk_score"],
                "destination": decision["destination"],
                "destination_provenance": decision["destination_provenance"],
                "data_classification": decision["data_classification"],
                "origin": decision["origin"], "provenance_chain": decision["provenance_chain"],
                "trust_labels": decision["trust_labels"],
                "injection_signals": decision["injection_signals"],
                "verifier": decision["verifier"], "latency_ms": latency_ms,
                "capability_id": None, "approval_id": None, "status": decision["decision"].lower(),
            }

            capability = None
            approval = None
            if decision["decision"] == "ALLOW":
                capability = self._mint_capability(task, action, decision)
                action["capability_id"] = capability["cap_id"]
                task["status"] = "running"
            elif decision["decision"] == "REQUIRE_APPROVAL":
                approval = self._create_approval(task, action, decision)
                action["approval_id"] = approval["id"]
                task["status"] = "awaiting_approval"
                task["approvals"].append(approval)
            else:
                self._record_deny(task, decision)

            task["actions"].append(action)
            audit = self._audit({
                "event": "decision", "task_id": task_id, "action_id": action_id,
                "decision": decision["decision"], "level": decision["level"],
                "tool": tool, "args": args, "args_hash": args_hash,
                "reason": decision["reason"], "rules": decision["rules"],
                "risk_score": decision["risk_score"],
                "provenance": decision.get("provenance_chain", []),
                "data_sources": resolved, "destination": decision["destination"],
                "destination_provenance": decision["destination_provenance"],
                "data_classification": decision["data_classification"],
                "injection_signals": decision["injection_signals"],
                "verifier": decision["verifier"], "latency_ms": latency_ms,
                "policy_version": POLICY_VERSION, "source": "policy_engine",
            })

            if decision["decision"] == "DENY":
                action["audit_id"] = audit["id"]
                self._alert_for_deny(task, action, decision)

            return {
                "action_id": action_id, "args_hash": args_hash,
                "decision": decision["decision"], "level": decision["level"],
                "reason": decision["reason"], "rules": decision["rules"],
                "risk_score": decision["risk_score"], "latency_ms": latency_ms,
                "tool": tool, "args": args, "data_sources": resolved,
                "destination": decision["destination"],
                "destination_provenance": decision["destination_provenance"],
                "data_classification": decision["data_classification"],
                "origin": decision["origin"], "provenance_chain": decision["provenance_chain"],
                "trust_labels": decision["trust_labels"],
                "injection_signals": decision["injection_signals"],
                "verifier": decision["verifier"], "policy_version": POLICY_VERSION,
                "capability": capability, "approval": self._public_approval(approval) if approval else None,
                "audit_id": audit["id"], "task_status": task["status"],
                "circuit_breaker": self._circuit_public(),
            }

    # ---------------------------------------------------------- approvals
    def _create_approval(self, task, action, decision):
        now = time.time()
        appr = {
            "id": self._new_id("appr"), "task_id": task["id"], "action_id": action["id"],
            "created_at": _iso(now), "created_epoch": now, "expires_at": _iso(now + CAP_TTL),
            "expires_epoch": now + CAP_TTL, "status": "pending",
            "tool": action["tool"], "args": action["args"],
            "data_sources": action["data_sources"], "args_hash": action["args_hash"],
            "level": decision["level"], "reason": decision["reason"],
            "rules": decision["rules"], "risk_score": decision["risk_score"],
            "destination": decision["destination"],
            "destination_provenance": decision["destination_provenance"],
            "data_classification": decision["data_classification"],
            "origin": decision["origin"], "provenance_chain": decision["provenance_chain"],
            "trust_labels": decision["trust_labels"],
            "content_hash": self._content_hash(action["args"]),
            "decision_snapshot": {k: decision[k] for k in
                                  ("decision", "level", "reason", "rules", "risk_score",
                                   "destination", "data_classification", "origin",
                                   "provenance_chain", "trust_labels", "source",
                                   "verifier", "policy_version", "injection_signals")},
        }
        self.approvals[appr["id"]] = appr
        return appr

    def _public_approval(self, appr):
        if not appr:
            return None
        return {
            "id": appr["id"], "task_id": appr["task_id"], "action_id": appr["action_id"],
            "created_at": appr["created_at"], "expires_at": appr["expires_at"],
            "status": appr["status"], "tool": appr["tool"], "args": appr["args"],
            "data_sources": appr["data_sources"], "args_hash": appr["args_hash"],
            "level": appr["level"], "reason": appr["reason"], "rules": appr["rules"],
            "risk_score": appr["risk_score"], "destination": appr["destination"],
            "destination_provenance": appr["destination_provenance"],
            "data_classification": appr["data_classification"], "origin": appr["origin"],
            "provenance_chain": appr["provenance_chain"],
            "trust_labels": appr["trust_labels"], "content_hash": appr["content_hash"],
            "verifier": appr.get("decision_snapshot", {}).get("verifier"),
        }

    def _content_hash(self, args):
        payload = {
            "to": args.get("to", ""), "subject": args.get("subject", ""),
            "body": args.get("body", ""), "path": args.get("path", ""),
            "attachments": list(args.get("attachments") or []),
        }
        return "sha256:" + _sha(_canon(payload))

    def decide_approval(self, approval_id, approve, reason="", actor="user"):
        with self.lock:
            appr = self.approvals.get(approval_id)
            if not appr:
                raise EngineError("unknown approval")
            if appr["status"] != "pending":
                raise EngineError(f"approval already {appr['status']}")
            if actor not in ("user", "human", "operator"):
                self._audit({
                    "event": "approval", "task_id": appr["task_id"],
                    "action_id": appr["action_id"], "approval_id": approval_id,
                    "decision": "DENY", "level": "L2",
                    "reason": "Only the human user may approve an action; planner identity rejected.",
                    "rules": ["hard_deny.approval_identity"], "actor": actor,
                })
                self._alert("high", "Approval identity rejected",
                            "A non-human actor tried to approve an L2 action.", appr["task_id"],
                            "hard_deny.approval_identity")
                return {"ok": False, "error": "approval must be decided by the human user",
                        "approval": self._public_approval(appr)}
            if time.time() > appr["expires_epoch"]:
                appr["status"] = "expired"
                self._audit({"event": "approval", "task_id": appr["task_id"],
                             "action_id": appr["action_id"], "approval_id": approval_id,
                             "decision": "EXPIRED", "reason": "Approval window elapsed.",
                             "rules": ["hard_deny.approval_expired"]})
                return {"ok": False, "error": "approval expired",
                        "approval": self._public_approval(appr)}

            task = self._task(appr["task_id"])
            if self.circuit["state"] == "FROZEN":
                return {"ok": False, "error": "circuit breaker is frozen",
                        "approval": self._public_approval(appr)}
            if not approve:
                appr["status"] = "denied"
                appr["decided_at"] = _iso()
                appr["decided_by"] = actor
                appr["decision_reason"] = reason
                task["status"] = "running"
                self._audit({"event": "approval", "task_id": task["id"],
                             "action_id": appr["action_id"], "approval_id": approval_id,
                             "decision": "APPROVAL_DENIED", "level": "L2",
                             "reason": reason or "User denied the action.",
                             "rules": ["approval.user_denied"], "actor": actor})
                return {"ok": True, "approved": False, "approval": self._public_approval(appr)}

            appr["status"] = "approved"
            appr["decided_at"] = _iso()
            appr["decided_by"] = actor
            appr["decision_reason"] = reason
            action = next((a for a in task["actions"] if a["id"] == appr["action_id"]), None)
            if not action:
                raise EngineError("approval action disappeared")
            decision = dict(appr["decision_snapshot"])
            decision["destination_provenance"] = appr["destination_provenance"]
            capability = self._mint_capability(task, action, decision, approval_id=appr["id"])
            action["capability_id"] = capability["cap_id"]
            action["status"] = "approved"
            task["status"] = "running"
            self._audit({"event": "approval", "task_id": task["id"],
                         "action_id": appr["action_id"], "approval_id": approval_id,
                         "decision": "APPROVED", "level": "L2",
                         "reason": reason or "User approved the exact action snapshot.",
                         "rules": ["approval.exact_args"], "actor": actor,
                         "capability_id": capability["cap_id"],
                         "args_hash": appr["args_hash"]})
            return {"ok": True, "approved": True,
                    "approval": self._public_approval(appr), "capability": capability}

    # --------------------------------------------------------- capabilities
    def _mint_capability(self, task, action, decision, approval_id=None):
        now = time.time()
        cap_id = self._new_id("cap")
        jti = self._new_id("jti")
        payload = {
            "task_id": task["id"], "cap_id": cap_id, "jti": jti,
            "action_id": action["id"], "action": action["tool"],
            "args": action["args"], "args_hash": action["args_hash"],
            "source": decision.get("source", "user:task"),
            "destination": decision.get("destination", ""),
            "data_classification": decision.get("data_classification", "internal"),
            "origin": decision.get("origin", "user_requested_task"),
            "purpose": task["intent"]["summary"],
            "requested_scope": task["scope"],
            "provenance_chain": decision.get("provenance_chain", []),
            "trust_labels": decision.get("trust_labels", []),
            "authority_level": decision.get("level", "L0"),
            "approval_id": approval_id,
            "expires_at": _iso(now + CAP_TTL), "expires_epoch": now + CAP_TTL,
            "nonce": secrets.token_hex(8),
            "policy_version": POLICY_VERSION,
        }
        body = _b64e(_canon(payload).encode())
        sig = _b64e(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        token = body + "." + sig
        self.capabilities[jti] = {
            "payload": payload, "token": token, "used": False,
            "task_id": task["id"], "action": action["tool"],
        }
        return {
            "token": token, "cap_id": cap_id, "jti": jti, "level": payload["authority_level"],
            "expires_at": payload["expires_at"], "expires_epoch": payload["expires_epoch"],
            "args_hash": payload["args_hash"], "destination": payload["destination"],
            "data_classification": payload["data_classification"],
            "signature_preview": sig[:18] + "…",
        }

    def _parse_capability(self, token):
        try:
            body, sig = str(token).split(".", 1)
        except ValueError:
            raise EngineError("malformed capability token")
        expected = _b64e(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise EngineError("invalid capability signature")
        try:
            payload = json.loads(_b64d(body))
        except Exception:
            raise EngineError("undecodable capability payload")
        return payload

    # -------------------------------------------------------------- gateway
    def execute(self, task_id, token, proposal):
        start = time.time()
        with self.lock:
            task = self._task(task_id)
            if self.circuit["state"] == "FROZEN":
                return self._gateway_fail(task, None, proposal, "circuit breaker is FROZEN")
            try:
                payload = self._parse_capability(token)
            except EngineError as exc:
                return self._gateway_fail(task, None, proposal, str(exc))

            jti = payload.get("jti")
            stored = self.capabilities.get(jti)
            if not stored:
                return self._gateway_fail(task, payload, proposal, "capability unknown, expired, or already used")
            if stored.get("used"):
                return self._gateway_fail(task, payload, proposal, "capability replay rejected (single-use)")
            if payload.get("expires_epoch", 0) < time.time():
                self.capabilities.pop(jti, None)
                return self._gateway_fail(task, payload, proposal, "capability expired")
            if payload.get("task_id") != task_id:
                return self._gateway_fail(task, payload, proposal, "capability is bound to a different task")

            args = (proposal or {}).get("args") or {}
            tool = str((proposal or {}).get("tool") or "")
            declared = list((proposal or {}).get("data_sources") or [])
            resolved, _ = policy.resolve_sources(task, declared)
            args_hash = _sha(_canon({"tool": tool, "args": args, "data_sources": sorted(resolved)}))
            if tool != payload.get("action"):
                return self._gateway_fail(task, payload, proposal, "tool does not match capability")
            if args_hash != payload.get("args_hash"):
                return self._gateway_fail(task, payload, proposal, "arguments changed since approval (hash mismatch)")
            if _destination(tool, args, task) != payload.get("destination"):
                return self._gateway_fail(task, payload, proposal, "destination does not match capability")

            # Consume before execution: a capability can never be retried.
            stored["used"] = True
            self.capabilities.pop(jti, None)

            try:
                result = toolmod.run_tool(self, task, tool, args, payload)
            except ToolError as exc:
                audit = self._audit({
                    "event": "execution", "task_id": task_id,
                    "action_id": payload.get("action_id"), "capability_id": payload.get("cap_id"),
                    "decision": "FAILED", "tool": tool, "reason": str(exc),
                    "rules": ["gateway.tool_error"], "executed_at": _iso(),
                })
                return {"ok": False, "error": str(exc), "result": None,
                        "verification": {"ok": False, "detail": str(exc)},
                        "audit_id": audit["id"], "capability_id": payload.get("cap_id")}
            except Exception as exc:
                audit = self._audit({
                    "event": "execution", "task_id": task_id,
                    "action_id": payload.get("action_id"), "capability_id": payload.get("cap_id"),
                    "decision": "FAILED", "tool": tool, "reason": f"tool exception: {exc}",
                    "rules": ["gateway.tool_error"], "executed_at": _iso(),
                })
                return {"ok": False, "error": f"tool exception: {exc}", "result": None,
                        "verification": {"ok": False, "detail": "tool exception"},
                        "audit_id": audit["id"], "capability_id": payload.get("cap_id")}

            verified, detail = toolmod.verify(self, task, tool, args, result, payload)
            audit = self._audit({
                "event": "execution", "task_id": task_id,
                "action_id": payload.get("action_id"), "capability_id": payload.get("cap_id"),
                "decision": "EXECUTED" if verified else "UNVERIFIED", "tool": tool,
                "args": args, "args_hash": args_hash, "reason": detail,
                "rules": ["gateway.validated", "gateway.single_use"], "executed_at": _iso(),
                "latency_ms": round((time.time() - start) * 1000, 2),
                "verified": bool(verified), "verification_detail": detail,
                "destination": payload.get("destination"),
            })
            if not verified:
                self._alert("medium", "Execution verification failed",
                            f"{tool}: {detail}", task_id, "gateway.verification")
            return {
                "ok": True, "result": result, "verification": {"ok": bool(verified), "detail": detail},
                "audit_id": audit["id"], "capability_id": payload.get("cap_id"),
                "level": payload.get("authority_level"), "latency_ms": audit["latency_ms"],
            }

    def _gateway_fail(self, task, payload, proposal, reason):
        tool = str((proposal or {}).get("tool") or "")
        audit = self._audit({
            "event": "execution", "task_id": task["id"],
            "action_id": (payload or {}).get("action_id"),
            "capability_id": (payload or {}).get("cap_id"),
            "decision": "DENY", "tool": tool,
            "reason": "Gateway rejected: " + reason,
            "rules": ["hard_deny.gateway_validation"], "executed_at": _iso(),
        })
        self._record_deny(task, {"decision": "DENY", "level": "L3", "risk_score": 95,
                                 "reason": reason, "rules": ["hard_deny.gateway_validation"]})
        self._alert("high", "Gateway blocked an execution",
                    f"{tool or 'action'}: {reason}", task["id"], "hard_deny.gateway_validation")
        return {"ok": False, "error": "gateway rejected: " + reason,
                "verification": {"ok": False, "detail": reason},
                "audit_id": audit["id"],
                "capability_id": (payload or {}).get("cap_id")}

    # ------------------------------------------------------- circuit breaker
    def _circuit_public(self):
        return {
            "state": self.circuit["state"], "reason": self.circuit["reason"],
            "denies_recent": len(self.circuit["denies"]),
            "frozen_at": self.circuit["frozen_at"],
        }

    def _record_deny(self, task, decision):
        now = time.time()
        self.circuit["denies"] = [t for t in self.circuit["denies"] if now - t < 120]
        self.circuit["denies"].append(now)
        if len(self.circuit["denies"]) >= 3 and self.circuit["state"] != "FROZEN":
            self.circuit["state"] = "FROZEN"
            self.circuit["reason"] = "3 hard denials inside 120 seconds"
            self.circuit["frozen_at"] = _iso(now)
            self.capabilities.clear()
            self._alert("critical", "Emergency circuit breaker FROZEN",
                        "Three hard denials in two minutes. Execution stopped and temporary "
                        "capabilities revoked. User review required.",
                        task["id"], "circuit_breaker.frozen")
            self._audit({"event": "circuit", "task_id": task["id"],
                         "decision": "FROZEN", "level": "L3",
                         "reason": self.circuit["reason"],
                         "rules": ["circuit_breaker.repeated_denials"]})
        elif self.circuit["state"] == "NORMAL":
            self.circuit["state"] = "SUSPICIOUS"
            self.circuit["reason"] = "Suspicious action denied; monitoring"
        task["status"] = "frozen" if self.circuit["state"] == "FROZEN" else task["status"]

    def reset_circuit(self, reason="User reviewed alerts"):
        with self.lock:
            self.circuit = {"state": "NORMAL", "denies": [], "reason": reason, "frozen_at": None}
            for task in self.tasks.values():
                if task["status"] == "frozen":
                    task["status"] = "running"
            self._audit({"event": "circuit", "decision": "RESET", "level": "L1",
                         "reason": reason, "rules": ["circuit_breaker.user_reset"]})
            self._alert("info", "Circuit breaker reset", reason, None, "circuit_breaker.reset")
            return self._circuit_public()

    # ----------------------------------------------------------------- audit
    def _audit(self, record):
        rec = dict(record)
        rec.setdefault("id", self._new_id("aud"))
        rec.setdefault("ts", _iso())
        rec.setdefault("policy_version", POLICY_VERSION)
        self.audit_log.append(rec)
        return rec

    def get_audit(self, task_id=None, limit=500):
        rows = self.audit_log
        if task_id:
            rows = [r for r in rows if r.get("task_id") == task_id]
        return list(reversed(rows[-limit:]))

    def _alert(self, severity, title, detail, task_id, rule):
        self.alerts.append({
            "id": self._new_id("alr"), "ts": _iso(), "severity": severity,
            "title": title, "detail": detail, "task_id": task_id, "rule": rule,
        })
        return self.alerts[-1]

    def _alert_for_deny(self, task, action, decision):
        rules = decision.get("rules", [])
        if any("tainted_destination" in r for r in rules):
            self._alert("critical", "Tainted destination blocked",
                        f"Destination '{decision['destination']}' came from untrusted content. "
                        f"Payload class: {decision['data_classification']}.", task["id"],
                        "hard_deny.tainted_destination")
        elif any("restricted" in r or "protected_asset" in r for r in rules):
            self._alert("high", "Protected asset access blocked",
                        decision["reason"], task["id"], rules[-1] if rules else "hard_deny")
        elif any("outside_task_intent" in r for r in rules):
            self._alert("high", "Action outside task intent blocked",
                        decision["reason"], task["id"], "hard_deny.outside_task_intent")
        else:
            self._alert("medium", "Action denied", decision["reason"], task["id"],
                        rules[-1] if rules else "policy.deny")

    def get_alerts(self, limit=100):
        return list(reversed(self.alerts[-limit:]))

    def get_approval(self, approval_id):
        appr = self.approvals.get(approval_id)
        if not appr:
            raise EngineError("unknown approval")
        return self._public_approval(appr)

    # --------------------------------------------------------------- metrics
    def metrics(self):
        decisions = [r for r in self.audit_log if r.get("event") == "decision"]
        executions = [r for r in self.audit_log if r.get("event") == "execution"]
        lat = sorted(r.get("latency_ms", 0) for r in decisions)
        p95 = 0.0
        if lat:
            p95 = lat[min(len(lat) - 1, max(0, math.ceil(len(lat) * 0.95) - 1))]
        action_ids = set()
        for task in self.tasks.values():
            for a in task["actions"]:
                action_ids.add(a["id"])
        covered = {r.get("action_id") for r in decisions if r.get("action_id")}
        coverage = 100.0 if not action_ids else round(100.0 * len(action_ids & covered) / len(action_ids), 1)
        blocked_rules = ("restricted_exfil", "tainted_destination", "protected_asset",
                         "credential_exfiltration", "out_of_scope_attachment")
        blocked_transfers = sum(1 for r in decisions if r.get("decision") == "DENY"
                                and any(x in " ".join(r.get("rules", [])) for x in blocked_rules))
        return {
            "tasks": len(self.tasks),
            "completed_tasks": sum(1 for t in self.tasks.values() if t["status"] == "completed"),
            "actions": len(action_ids),
            "allow": sum(1 for r in decisions if r.get("decision") == "ALLOW"),
            "approval_required": sum(1 for r in decisions if r.get("decision") == "REQUIRE_APPROVAL"),
            "denied": sum(1 for r in decisions if r.get("decision") == "DENY"),
            "executions": sum(1 for r in executions if r.get("decision") == "EXECUTED"),
            "gateway_blocks": sum(1 for r in executions if r.get("decision") == "DENY"),
            "blocked_transfers": blocked_transfers,
            "approvals_approved": sum(1 for a in self.approvals.values() if a["status"] == "approved"),
            "approvals_denied": sum(1 for a in self.approvals.values() if a["status"] == "denied"),
            "audit_coverage": coverage,
            "latency_p95_ms": round(p95, 2),
            "audit_records": len(self.audit_log),
            "alerts": len(self.alerts),
            "outbox": len(self.outbox),
        }

    # ------------------------------------------------------------- bootstrap
    def bootstrap(self):
        emails = []
        for e in EMAILS.values():
            emails.append({
                "id": e["id"], "mailbox": e["mailbox"], "from": e["from"],
                "subject": e["subject"], "date": e["date"],
                "attachments": [{"id": a["id"], "name": a["name"], "path": a["path"],
                                 "classification": a.get("classification")} for a in e.get("attachments", [])],
            })
        files = [{"path": p, "classification": v.get("classification"), "title": v.get("title"),
                  "protected": "private" in p or p.endswith(".env")}
                 for p, v in FILES.items()]
        pages = [{"url": u, "title": v.get("title"), "classification": v.get("classification")}
                 for u, v in PAGES.items()]
        return {
            "app": "ALFRED", "version": POLICY_VERSION,
            "corpus": {"emails": emails, "files": files, "pages": pages,
                       "contacts": TRUSTED_CONTACTS, "user": USER_EMAIL},
            "policy": {
                "levels": LEVELS, "tools": TOOL_MATRIX,
                "rules": [
                    "default_decision = DENY",
                    "hard_deny: restricted data + any external destination",
                    "hard_deny: untrusted destination + confidential/restricted payload",
                    "hard_deny: protected paths (.env, .ssh, keys, credentials, /etc)",
                    "hard_deny: action outside the original task intent",
                    "hard_deny: internal/private network egress",
                    "require_approval: external send/share, delete, out-of-scope write",
                    "scoped_allow: exact attachment download, write inside task folder",
                    "allow: read-only mail/file/browser inside task scope",
                    "capability: signed, 5 min, single-use, exact args + destination binding",
                ],
                "dimensions": ["intent", "identity", "source", "sensitivity",
                               "destination", "information flow", "impact", "permission"],
            },
            "metrics": self.metrics(), "circuit_breaker": self._circuit_public(),
            "alerts": self.get_alerts(30), "started_at": _iso(self.started_at),
        }
