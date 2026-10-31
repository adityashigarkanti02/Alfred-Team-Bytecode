#!/usr/bin/env python3
"""
Layer 5 — independent authority & policy engine.

Deterministic.  No model, no prompt, no detector can grant authority here.
Every proposal is converted into a structured action request and evaluated on
the eight PRD dimensions: intent, identity, source, sensitivity, destination,
information flow, impact and permission.

The result is one of:
  ALLOW            -> a signed, single-use, args-bound capability (L0/L1)
  REQUIRE_APPROVAL -> a frozen approval snapshot (L2)
  DENY             -> a hard denial, audited (L3)
"""
from __future__ import annotations

import re
import urllib.parse

from corpus import (
    FILES, LEVELS, PRIVILEGED_TOOLS, READ_TOOLS, TRUSTED_CONTACTS,
    in_scope, is_internal_url, is_protected_path, norm_path, understand,
)
from detect import SECRET_RE, classify_content, max_class, looks_secret

LEVEL_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


# ---------------------------------------------------------------------------
# provenance helpers
# ---------------------------------------------------------------------------
def resolve_source(task, token):
    """Match 'em_101', 'email:em_101', '/path', 'file:/path' to a real source."""
    if not token:
        return None
    token = str(token).strip()
    sources = task["sources"]
    if token in sources:
        return token
    for prefix in ("email:", "file:", "pdf:", "xlsx:", "web:", "html:", "attachment:"):
        if prefix + token in sources:
            return prefix + token
    low = token.lower()
    for sid in sources:
        if sid.lower() == low or sid.lower().endswith(":" + low):
            return sid
    # paths may be normalised differently
    p, _ = norm_path(token)
    for sid in sources:
        if sid.startswith("file:") and norm_path(sid[5:])[0] == p:
            return sid
    return None


def resolve_sources(task, tokens):
    good, bad = [], []
    for t in tokens or []:
        sid = resolve_source(task, t)
        if sid:
            if sid not in good:
                good.append(sid)
        else:
            bad.append(str(t))
    return good, bad


def source_class(task, sid):
    src = task["sources"].get(sid)
    return src["classification"] if src else "internal"


def source_risk(task, sids):
    return max([task["sources"].get(s, {}).get("risk", 0) for s in sids] or [0])


def source_record(task, sid):
    src = task["sources"].get(sid) or {}
    return {
        "source_id": sid,
        "source_type": src.get("source_type", "unknown"),
        "trust_label": src.get("trust_label", "untrusted_external_data"),
        "classification": src.get("classification", "internal"),
        "risk": src.get("risk", 0),
        "provenance_id": src.get("provenance_id"),
        "title": src.get("title", ""),
    }


def file_class(task, path):
    p, unsafe = norm_path(path)
    if unsafe or is_protected_path(p):
        return "restricted"
    entry = task["fs"].get(p)
    if entry:
        return entry.get("classification", "internal")
    fixture = FILES.get(p)
    if fixture:
        return fixture.get("classification", "internal")
    return "internal"


def file_exists(task, path):
    p, unsafe = norm_path(path)
    return (not unsafe) and (p in task["fs"] or p in FILES)


def _taint(task, value):
    if not value:
        return None
    v = str(value).strip().lower()
    if v in task["taint"]:
        return task["taint"][v]
    # URLs may have trailing punctuation in extracted literals
    v2 = v.rstrip(".,);")
    if v2 in task["taint"]:
        return task["taint"][v2]
    return None


def destination_provenance(task, dest):
    """Where did this destination come from? Trusted instruction or tainted data?"""
    value = str(dest or "").strip()
    low = value.lower()
    prompt = task["prompt"].lower()

    if value and (low in prompt or value in task["scope"].get("contacts", [])):
        return {
            "value": value, "trust": "authorized_user_instruction",
            "source": "user:task", "source_type": "user_prompt",
            "reason": "Destination was named by the user or is an allowlisted contact.",
        }
    for c in TRUSTED_CONTACTS + task["scope"].get("contacts", []):
        if low == c.lower():
            return {
                "value": value, "trust": "authorized_user_instruction",
                "source": "user:contacts", "source_type": "contact_allowlist",
                "reason": "Destination is on the trusted contact allowlist.",
            }
    t = _taint(task, value)
    if t:
        return {
            "value": value, "trust": "untrusted_external_data",
            "source": t.get("source_id"), "source_type": t.get("source_type", "external"),
            "reason": f"Destination was extracted from {t.get('source_id')} (untrusted external data).",
        }
    return {
        "value": value, "trust": "unknown_source",
        "source": None, "source_type": "unknown",
        "reason": "Destination did not come from the user, a trusted contact, or tracked context.",
    }


def _body_classification(task, body, sids, attachments):
    cls = "internal"
    for sid in sids:
        cls = max_class(cls, source_class(task, sid))
    for att in attachments or []:
        cls = max_class(cls, file_class(task, att))
    if looks_secret(body):
        return "restricted"
    # Detect verbatim leakage of confidential/restricted source text.
    body_low = str(body or "").lower()
    if body_low:
        for sid, src in task["sources"].items():
            if src.get("classification") not in ("confidential", "restricted"):
                continue
            visible = src.get("visible_text", "")
            for i in range(0, max(0, len(visible) - 60), 60):
                chunk = visible[i:i + 60].strip().lower()
                if len(chunk) > 40 and chunk in body_low:
                    return max_class(cls, src.get("classification"))
    return cls


def _valid_email(value):
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", str(value or "").strip()))


def _valid_url(value):
    try:
        u = urllib.parse.urlparse(str(value or ""))
        return u.scheme in ("http", "https") and bool(u.netloc)
    except Exception:
        return False


def _rule(name):
    return name


def _deny(reason, rule, risk, dest="", cls="restricted", dprov=None, rules=None, origin="untrusted_proposal"):
    return {
        "decision": "DENY", "level": "L3", "reason": reason,
        "rules": (rules or []) + [_rule(rule)],
        "risk_score": min(99, risk), "destination": dest,
        "data_classification": cls,
        "destination_provenance": dprov or destination_provenance_dummy(dest),
        "origin": origin,
    }


def destination_provenance_dummy(dest=""):
    return {"value": dest, "trust": "unknown_source", "source": None,
            "source_type": "unknown", "reason": "No destination provenance available."}


def _approval(reason, rule, risk, dest, cls, dprov, rules=None, origin="user_requested_task"):
    return {
        "decision": "REQUIRE_APPROVAL", "level": "L2", "reason": reason,
        "rules": (rules or []) + [_rule(rule)],
        "risk_score": min(96, risk), "destination": dest,
        "data_classification": cls,
        "destination_provenance": dprov,
        "origin": origin,
    }


def _allow(level, reason, rule, risk, dest, cls, dprov, rules=None, origin="user_requested_task"):
    return {
        "decision": "ALLOW", "level": level, "reason": reason,
        "rules": (rules or []) + [_rule(rule)],
        "risk_score": max(0, min(80, risk)), "destination": dest,
        "data_classification": cls,
        "destination_provenance": dprov,
        "origin": origin,
    }


# ---------------------------------------------------------------------------
# main policy evaluation
# ---------------------------------------------------------------------------
def evaluate(task, proposal, verifier=None):
    tool = str(proposal.get("tool") or "").strip()
    args = proposal.get("args") or {}
    if not isinstance(args, dict):
        args = {}
    declared_sources = proposal.get("data_sources") or []
    sids, unknown_sources = resolve_sources(task, declared_sources)
    verifier = verifier if isinstance(verifier, dict) else None

    if tool not in READ_TOOLS and tool not in PRIVILEGED_TOOLS:
        return _deny(f"Unknown tool '{tool}' cannot be proposed.", "hard_deny.unknown_tool", 90)
    if tool in PRIVILEGED_TOOLS and tool not in task["allowed_tools"]:
        return _deny(
            f"'{tool}' is outside the original task intent ({task['intent']['summary']}).",
            "hard_deny.outside_task_intent", 95,
        )

    # ---- tool-specific evaluation ----------------------------------------
    if tool == "read_email":
        mailbox = str(args.get("mailbox") or (task["scope"]["mailboxes"][0] if task["scope"]["mailboxes"] else "")).strip()
        if not mailbox:
            return _deny("No mailbox scope exists for this task.", "hard_deny.out_of_scope_mailbox", 70)
        if mailbox not in task["scope"]["mailboxes"]:
            return _deny(
                f"Mailbox '{mailbox}' is outside the task-bound mailbox scope.", "hard_deny.out_of_scope_mailbox", 85,
            )
        return _allow("L0", "Read-only access to a mailbox inside task scope.",
                      "allow.read_only_mailbox", 8, mailbox, "internal",
                      {"value": mailbox, "trust": "authorized_user_instruction",
                       "source": "user:task", "source_type": "task_scope",
                       "reason": "Mailbox granted by the original task scope."})

    if tool == "download_attachment":
        email_id = str(args.get("email_id") or "").strip()
        att_id = str(args.get("attachment_id") or args.get("name") or "").strip()
        email = _fixture_email(email_id)
        if not email:
            return _deny(f"Unknown email '{email_id}'.", "hard_deny.unknown_source", 75)
        sid = resolve_source(task, "email:" + email_id)
        if not sid:
            return _deny("Email must be read before its attachment can be downloaded.",
                         "hard_deny.unread_attachment", 80)
        if email["mailbox"] not in task["scope"]["mailboxes"]:
            return _deny("Attachment belongs to a mailbox outside task scope.",
                         "hard_deny.out_of_scope_mailbox", 85)
        att = next((a for a in email.get("attachments", [])
                    if att_id in (a["id"], a["name"], a["path"])), None)
        if not att:
            return _deny(f"Attachment '{att_id}' is not part of this email.",
                         "hard_deny.attachment_not_authorized", 85)
        if is_protected_path(att["path"]) or att.get("classification") == "restricted":
            return _deny("Attachment resolves to a protected asset.", "hard_deny.protected_asset", 98)
        return _allow("L1", "Exact attachment download, bound to one named file.",
                      "scoped_allow.exact_attachment", 14, att["path"], att.get("classification", "internal"),
                      {"value": att["path"], "trust": "authorized_user_instruction",
                       "source": sid, "source_type": "email_attachment",
                       "reason": "Attachment explicitly listed on an in-scope email."})

    if tool in ("read_file", "write_file", "delete_file", "share_file"):
        path = str(args.get("path") or "").strip()
        if not path:
            return _deny("Missing path.", "hard_deny.malformed_action", 70)
        p, unsafe = norm_path(path)
        if unsafe or is_protected_path(p):
            return _deny(
                f"Path '{p}' is a protected asset (credentials / secrets / system path / traversal).",
                "hard_deny.protected_asset", 99, dest=p,
            )

        in_task_scope = in_scope(p, task["scope"]["files"])
        cls = file_class(task, p)

        if tool == "read_file":
            if not file_exists(task, p):
                return _deny(f"File '{p}' does not exist in the sandbox.", "hard_deny.unknown_file", 65, dest=p)
            if cls == "restricted":
                return _deny("Restricted file read is a hard deny.", "hard_deny.restricted_read", 98, dest=p)
            if not in_task_scope:
                return _deny("File is outside the task-bound file scope.",
                             "hard_deny.out_of_scope_path", 90, dest=p)
            return _allow("L0", "Read-only access inside task scope.",
                          "allow.read_only_file", 8, p, cls,
                          {"value": p, "trust": "authorized_user_instruction",
                           "source": "user:task", "source_type": "task_scope",
                           "reason": "Path is inside the task-bound project folder."})

        if tool == "write_file":
            content = str(args.get("content") or "")
            content_cls = classify_content(content, "internal")
            if declared_sources and unknown_sources:
                return _deny("Provenance references unknown sources.",
                             "hard_deny.unverifiable_provenance", 88, dest=p)
            if content_cls == "restricted":
                return _deny("Writing credential material is a protected operation.",
                             "hard_deny.restricted_write", 97, dest=p, cls="restricted")
            if in_task_scope:
                if cls == "restricted":
                    return _deny("Target path is restricted.", "hard_deny.protected_asset", 98, dest=p)
                return _allow("L1", "Scoped local write inside the project folder.",
                              "scoped_allow.task_scope", 18, p, max_class(cls, content_cls),
                              {"value": p, "trust": "authorized_user_instruction",
                               "source": "user:task", "source_type": "task_scope",
                               "reason": "Write target is inside the task-bound folder."})
            if cls == "restricted":
                return _deny("Write outside scope targets a restricted path.",
                             "hard_deny.protected_asset", 98, dest=p)
            return _approval("Write outside the task-bound folder requires human approval.",
                             "require_approval.out_of_scope_write", 48, p,
                             max_class(cls, content_cls),
                             {"value": p, "trust": "unknown_source", "source": None,
                              "source_type": "unknown",
                              "reason": "Target is outside the scope named by the user."})

        if tool == "delete_file":
            if not in_task_scope:
                return _deny("Destructive action outside the task-bound folder.",
                             "hard_deny.out_of_scope_delete", 97, dest=p)
            if cls == "restricted":
                return _deny("Deleting a restricted asset is a hard deny.",
                             "hard_deny.protected_asset", 99, dest=p)
            return _approval("Delete is destructive and requires human approval.",
                             "require_approval.destructive_action", 58, p, cls,
                             {"value": p, "trust": "authorized_user_instruction",
                              "source": "user:task", "source_type": "task_scope",
                              "reason": "Path is inside task scope but deletion is irreversible in effect."})

        if tool == "share_file":
            to = str(args.get("to") or "").strip()
            if not _valid_email(to):
                return _deny("Invalid share destination.", "hard_deny.malformed_action", 70, dest=to)
            dprov = destination_provenance(task, to)
            if cls == "restricted":
                return _deny("Restricted asset cannot be shared externally.",
                             "hard_deny.restricted_exfil", 99, to, cls, dprov)
            if dprov["trust"] == "untrusted_external_data" and cls in ("confidential", "restricted"):
                return _deny(
                    f"Tainted destination: '{to}' came from untrusted data and the payload is {cls}.",
                    "hard_deny.tainted_destination", 97, to, cls, dprov)
            return _approval("External share requires human approval.",
                             "require_approval.external_side_effect", 52, to, cls, dprov,
                             origin="untrusted_external_data" if dprov["trust"] == "untrusted_external_data" else "user_requested_task")

    if tool == "browse":
        url = str(args.get("url") or "").strip()
        if not _valid_url(url):
            return _deny("Invalid URL.", "hard_deny.malformed_action", 70, dest=url)
        if is_internal_url(url):
            return _deny("Browser egress to an internal/private address is a hard deny.",
                         "hard_deny.internal_network", 98, dest=url)
        return _allow("L0", "Public page fetched in an isolated, egress-filtered sandbox.",
                      "allow.isolated_browser", 10, url, "public",
                      {"value": url, "trust": "authorized_user_instruction",
                       "source": "user:task", "source_type": "web_sandbox",
                       "reason": "Public URL, read-only sandbox with no filesystem or env access."})

    if tool == "summarize":
        return _allow("L0", "Local extraction of already-authorized context.",
                      "allow.local_processing", 6, "", "internal",
                      destination_provenance_dummy(""))

    if tool == "send_email":
        to = str(args.get("to") or "").strip()
        body = str(args.get("body") or "")
        attachments = [str(a) for a in (args.get("attachments") or [])]
        if not _valid_email(to):
            return _deny("Invalid recipient address.", "hard_deny.malformed_action", 72, dest=to)
        if unknown_sources:
            return _deny("Provenance references unknown sources; destination cannot be verified.",
                         "hard_deny.unverifiable_provenance", 92, dest=to)
        dprov = destination_provenance(task, to)
        cls = _body_classification(task, body, sids, attachments)
        rules = []
        if looks_secret(body):
            return _deny("Message body contains credential material.", "hard_deny.credential_exfiltration",
                         99, to, "restricted", dprov)
        for att in attachments:
            ap, unsafe = norm_path(att)
            if unsafe or is_protected_path(ap) or file_class(task, ap) == "restricted":
                return _deny(f"Attachment '{ap}' is a protected asset.", "hard_deny.protected_asset",
                             99, to, "restricted", dprov)
            if not in_scope(ap, task["scope"]["files"]):
                return _deny(f"Attachment '{ap}' is outside the task-bound folder.",
                             "hard_deny.out_of_scope_attachment", 96, to, "confidential", dprov)
            cls = max_class(cls, file_class(task, ap))
        if cls == "restricted":
            return _deny("Restricted data cannot leave the trust boundary, even with approval.",
                         "hard_deny.restricted_exfil", 99, to, cls, dprov)
        if dprov["trust"] == "untrusted_external_data":
            if cls in ("confidential", "restricted"):
                return _deny(
                    f"Blocked unauthorized transfer: destination '{to}' came from untrusted content "
                    f"and the payload is {cls}.", "hard_deny.tainted_destination", 98, to, cls, dprov)
            rules.append("warn.tainted_destination")
            return _approval(
                f"Destination '{to}' originated in untrusted data. Approval is required with a warning.",
                "require_approval.tainted_destination", 74, to, cls, dprov, rules,
                origin="untrusted_external_data")
        if dprov["trust"] == "unknown_source":
            rules.append("warn.unknown_destination")
        if len(sids) == 0 and task["sources"]:
            rules.append("warn.missing_provenance")
        return _approval("External send is an L2 side effect; exact args and body hash require approval.",
                         "require_approval.external_side_effect", 44, to, cls, dprov, rules)

    return _deny("No policy path exists for this action.", "hard_deny.no_policy", 80)


def _fixture_email(email_id):
    from corpus import EMAILS
    return EMAILS.get(str(email_id or "").strip())


# ---------------------------------------------------------------------------
# post-decision enrichment
# ---------------------------------------------------------------------------
def enrich(decision, task, proposal, sids, unknown_sources, verifier):
    tool = proposal.get("tool", "")
    base_risk = decision["risk_score"]
    srisk = source_risk(task, sids)
    risk = base_risk + int(srisk * 0.45)

    if verifier:
        vrisk = verifier.get("risk", 0)
        try:
            vrisk = float(vrisk)
        except (TypeError, ValueError):
            vrisk = 0.0
        if vrisk > 1:
            vrisk = vrisk / 100.0
        risk += int(max(0.0, min(1.0, vrisk)) * 18)

        # The verifier is a signal, never authority. It can escalate, not allow.
        if decision["decision"] == "ALLOW" and tool in PRIVILEGED_TOOLS:
            mismatch = verifier.get("matches_task") is False
            unsafe = vrisk >= 0.6
            if mismatch or unsafe:
                decision.update({
                    "decision": "REQUIRE_APPROVAL",
                    "level": "L2",
                    "reason": (decision["reason"] + " Independent verifier raised a concern; "
                               "escalated for human review."),
                    "rules": decision["rules"] + ["escalate.verifier_mismatch"],
                    "origin": "untrusted_external_data",
                })

    decision["risk_score"] = max(0, min(99, risk))
    if unknown_sources:
        decision["rules"].append("warn.unverifiable_sources")

    chain = ["user:" + task["id"]] + list(sids)
    if not sids and task["sources"]:
        chain += [sid for sid in list(task["sources"])[:3]]
    chain.append("action:" + tool)
    decision["provenance_chain"] = chain
    decision["data_sources"] = sids
    decision["unknown_sources"] = unknown_sources
    decision["trust_labels"] = ["authorized_user_instruction", "untrusted_proposal"]
    if sids or decision["destination_provenance"].get("trust") == "untrusted_external_data":
        decision["trust_labels"].append("untrusted_external_data")
    decision["source"] = (sids[0] if sids else
                          (decision["destination_provenance"].get("source") or "user:task"))
    decision["verifier"] = verifier
    decision["policy_version"] = "TB-DAS/1.0"
    decision["injection_signals"] = _signals_for_sources(task, sids)
    return decision


def _signals_for_sources(task, sids):
    seen, out = set(), []
    for sid in sids:
        for sig in task["sources"].get(sid, {}).get("injection_signals", []):
            key = (sig.get("id"), sig.get("excerpt"))
            if key not in seen:
                seen.add(key)
                out.append(sig)
    return out
