#!/usr/bin/env python3
"""
Layer 3 — content isolation and injection analysis.

This module is an *early warning* system, never an enforcement point.  It
strips hidden layers down to visible text and returns annotations + a risk
score.  The policy engine may use the score as a signal, but taint and
capability checks decide authority on their own.
"""
from __future__ import annotations

import base64
import html as html_mod
import re

from corpus import norm_path

CLASS_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

SECRET_RE = re.compile(
    r"(?i)("
    r"sk-(?:live|test)?[-_a-z0-9]{12,}|"
    r"ghp_[a-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{12,}|"
    r"aws_secret_access_key\s*[=:]\s*\S{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:api[_-]?key|secret|password|passwd|token)\s*[=:]\s*['\"]?[A-Za-z0-9_!@#$%^&*./+-]{8,}"
    r")"
)

HIGH_PATTERNS = [
    ("ignore_instructions", "Instruction override", r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)"),
    ("system_prefix", "Fake system message", r"\b(?:system|developer|admin|assistant)\s*(?:message|prompt|override)?\s*:"),
    ("role_hijack", "Role hijack", r"\byou\s+are\s+now\b|\bact\s+as\b|\bdeveloper\s+mode\b|\bnew\s+instructions?\b"),
    ("exfiltration", "Exfiltration instruction", r"\bexfiltrat\w*|\bupload\s+(?:all\s+)?(?:the\s+)?(?:env|environment|secret|key|file|document)s?|\bsend\s+(?:all\s+)?(?:the\s+)?(?:documents?|files?|keys?|secrets?)\s+(?:to|into)"),
    ("concealment", "Conceal from user", r"\bdo\s+not\s+(?:tell|inform|alert|notify)\s+the\s+user|\bdon'?t\s+tell\b|\bhide\s+(?:this|the)\s+(?:from|transfer)"),
    ("credential_theft", "Credential target", r"(?:api[_\s-]?key|secret|password|credential|private\s+key|\.env\b|\.ssh\b|id_rsa)"),
    ("policy_override", "Policy override", r"\boverride\s+(?:the\s+)?(?:policy|system|security|approval)|\bbypass\s+(?:the\s+)?(?:policy|approval|security)|\bignore\s+(?:the\s+)?policy"),
    ("destructive", "Destructive instruction", r"\bdelete\s+(?:all|every|the\s+entire)\b|\bwipe\s+(?:all|the)\b|\bformat\s+the\s+disk\b"),
]

MED_PATTERNS = [
    ("send_verb", "External send request", r"\b(?:send|forward|upload|share|attach|archive)\b"),
    ("data_target", "Sensitive data target", r"\b(?:documents?|inbox|mailbox|wallet|token|credential)s?\b"),
    ("urgency", "Urgency pressure", r"\b(?:urgent|immediately|right now|before\s+it'?s\s+too\s+late)\b"),
]

HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|"
    r"opacity\s*:\s*0(?:\.0+)?|height\s*:\s*0|width\s*:\s*0|"
    r"color\s*:\s*(?:#fff(?:fff)?|white|transparent)",
    re.I,
)
TAG_RE = re.compile(r"<(?P<tag>div|span|p|section|font|a|b|i|small)\b[^>]*>(?P<inner>.*?)</(?P=tag)>", re.I | re.S)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
MARKER_RE = re.compile(r"\[\[(?:white|hidden|meta)\s*:\s*(.*?)\]\]", re.I | re.S)
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{28,}={0,2}\b")
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
HOMOGLYPH_RE = re.compile(r"[\u0400-\u04ff\u0370-\u03ff]")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
PATH_RE = re.compile(r"(?:~|/)[A-Za-z0-9._@%+~/-]{2,}")


def classify_content(text, declared="internal"):
    """Max of declared class and evidence found in the bytes."""
    cls = declared if declared in CLASS_RANK else "internal"
    if SECRET_RE.search(str(text or "")):
        return "restricted"
    return cls


def max_class(*values):
    best = "public"
    for v in values:
        if v in CLASS_RANK and CLASS_RANK[v] > CLASS_RANK[best]:
            best = v
    return best


def looks_secret(text):
    return bool(SECRET_RE.search(str(text or "")))


def _excerpt(text, limit=140):
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    return s[:limit] + ("…" if len(s) > limit else "")


def _decode_base64(text):
    out = []
    for m in BASE64_RE.finditer(text or ""):
        raw = m.group(0)
        if len(raw) % 4:
            raw += "=" * (4 - len(raw) % 4)
        try:
            dec = base64.b64decode(raw).decode("utf-8", "replace")
        except Exception:
            continue
        printable = sum(c.isprintable() or c.isspace() for c in dec) / max(1, len(dec))
        if printable > 0.92 and len(dec) >= 16:
            out.append(dec.strip())
    return out


def _signals(text):
    """Return deduped injection signals in `text`."""
    found = {}
    for sid, label, pattern in HIGH_PATTERNS:
        m = re.search(pattern, text, re.I)
        if m:
            found[sid] = {
                "id": sid, "label": label, "severity": "high",
                "excerpt": _excerpt(text[max(0, m.start() - 40): m.end() + 90]),
            }
    for sid, label, pattern in MED_PATTERNS:
        m = re.search(pattern, text, re.I)
        if m:
            found.setdefault(sid, {
                "id": sid, "label": label, "severity": "medium",
                "excerpt": _excerpt(text[max(0, m.start() - 30): m.end() + 70]),
            })
    return list(found.values())


def _strip_html(text):
    s = str(text or "")
    s = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"</(?:p|div|li|h[1-6]|tr|section)>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html_mod.unescape(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def inspect_content(raw, source_type="file", declared="internal", title=""):
    """
    Split a document into:
      visible_text  — the only thing a planner is allowed to see
      hidden        — hidden layers, kept for the audit/UI
      annotations   — human-readable security notes
      signals       — injection detector output (a signal, not authority)
      risk          — 0..100 early-warning score
      taint_literals— addresses/URLs/paths harvested from *all* layers
    """
    original = str(raw or "")
    working = original
    annotations = []
    hidden_parts = []

    # 1. HTML comments
    for m in COMMENT_RE.finditer(working):
        payload = m.group(1).strip()
        if payload:
            hidden_parts.append(payload)
            annotations.append({
                "kind": "hidden_html", "layer": "html_comment", "severity": "high",
                "detail": "Instruction inside an HTML comment", "excerpt": _excerpt(payload),
            })
    working = COMMENT_RE.sub(" ", working)

    # 2. Invisible / white-on-white elements
    hidden_spans = []
    for m in TAG_RE.finditer(working):
        open_tag = m.group(0).split(">", 1)[0] + ">"
        inner = m.group("inner")
        if HIDDEN_STYLE_RE.search(open_tag) or re.search(r"aria-hidden\s*=\s*[\"']true", open_tag, re.I):
            payload = _strip_html(inner)
            if payload:
                hidden_parts.append(payload)
                layer = "white_on_white" if re.search(r"color\s*:\s*(?:#fff|white)", open_tag, re.I) else "invisible_html"
                annotations.append({
                    "kind": "hidden_html", "layer": layer, "severity": "high",
                    "detail": "Hidden HTML layer (" + layer.replace("_", " ") + ")",
                    "excerpt": _excerpt(payload),
                })
            hidden_spans.append((m.start(), m.end()))
    for start, end in reversed(hidden_spans):
        working = working[:start] + " " + working[end:]

    # 3. PDF / document white-text markers
    for m in MARKER_RE.finditer(working):
        payload = m.group(1).strip()
        hidden_parts.append(payload)
        annotations.append({
            "kind": "hidden_pdf", "layer": "pdf_white_text", "severity": "high",
            "detail": "Text layer invisible on the rendered page", "excerpt": _excerpt(payload),
        })
    working = MARKER_RE.sub(" ", working)

    # 4. Base64 / encoded payloads
    decoded = []
    for payload in _decode_base64(working):
        decoded.append(payload)
        if _signals(payload):
            hidden_parts.append(payload)
            annotations.append({
                "kind": "encoded_payload", "layer": "base64", "severity": "high",
                "detail": "Base64 payload decodes to an instruction",
                "excerpt": _excerpt(payload),
            })

    # 5. Unicode tricks
    zw = ZERO_WIDTH_RE.findall(working)
    if zw:
        annotations.append({
            "kind": "unicode", "layer": "zero_width", "severity": "medium",
            "detail": f"{len(zw)} zero-width characters removed", "excerpt": "U+200B…",
        })
    working = ZERO_WIDTH_RE.sub("", working)
    bidi = BIDI_RE.findall(working)
    if bidi:
        annotations.append({
            "kind": "unicode", "layer": "bidi_override", "severity": "high",
            "detail": f"{len(bidi)} bidirectional override characters removed", "excerpt": "U+202E…",
        })
    working = BIDI_RE.sub("", working)
    homoglyphs = HOMOGLYPH_RE.findall(working)
    if homoglyphs and re.search(r"[A-Za-z]", working):
        annotations.append({
            "kind": "unicode", "layer": "homoglyph", "severity": "high",
            "detail": f"{len(homoglyphs)} Cyrillic/Greek characters mixed into Latin text", "excerpt": "".join(homoglyphs[:8]),
        })

    visible = _strip_html(working)
    combined_hidden = "\n".join(hidden_parts)
    combined = "\n".join(x for x in [visible, combined_hidden] + decoded if x)

    all_signals = _signals(combined)
    visible_signals = _signals(visible)
    hidden_signals = _signals(combined_hidden + "\n" + "\n".join(decoded))

    high_hidden = any(s["severity"] == "high" for s in hidden_signals)
    high_visible = any(s["severity"] == "high" for s in visible_signals)
    medium = any(s["severity"] == "medium" for s in all_signals)

    if source_type == "user_prompt":
        risk = 0
    elif high_hidden:
        risk = 92
    elif high_visible:
        risk = 78
    elif annotations:
        risk = 52
    elif medium:
        risk = 26
    else:
        risk = 2

    # Harvest taint literals from every layer, including hidden + decoded.
    taint_source = "\n".join([original, combined_hidden] + decoded)
    literals = set()
    for m in EMAIL_RE.finditer(taint_source):
        literals.add(m.group(0).lower())
    for m in URL_RE.finditer(taint_source):
        literals.add(m.group(0).lower().rstrip(".,);"))
    for m in PATH_RE.finditer(taint_source):
        p, unsafe = norm_path(m.group(0))
        if not unsafe and len(p) > 3 and not p.startswith("//"):
            literals.add(p.lower())

    return {
        "visible_text": visible,
        "hidden_text": combined_hidden,
        "annotations": annotations,
        "injection_signals": all_signals,
        "risk": risk,
        "taint_literals": sorted(literals),
        "classification": classify_content(original, declared),
        "title": title,
        "source_type": source_type,
    }
