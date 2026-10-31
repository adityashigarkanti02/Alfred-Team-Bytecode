# ALFRED — Security-First Autonomous Agent (TB-DAS)

A working implementation of the Task-Bound Dynamic Authority System described in
`TB-DAS-Security-First-Agent-PRD.docx`, built on the free OpenChat relay that already
ships in this folder.

The one-line architecture:

> **The AI proposes. The policy engine decides. The gateway executes. The audit records.**

The model is never authority. Every tool call is a proposal that crosses a deterministic
Python policy engine, receives an explicit L0–L3 decision, and — if allowed — is executed
only through an HMAC-signed, single-use, 5-minute capability that is bound to the exact
arguments and destination.

---

## Run it

```bash
cd /home/nool/alfred/openchat-web
python3 alfred/server.py
# open http://127.0.0.1:8902/
```

No dependencies, no API keys, no database. Python 3.9+ and a browser with WebCrypto.

Optional environment variables:

| Variable           | Default     | Meaning                                       |
| ------------------ | ----------- | --------------------------------------------- |
| `ALFRED_PORT`      | `8902`      | HTTP port (also `PORT`)                       |
| `ALFRED_CAP_SECRET`| random/process | HMAC secret for capability signing         |

The capability secret is random per process unless pinned, so a restart invalidates
every outstanding capability. That is intentional.

---

## What is where

```
alfred/
├── server.py        stdlib HTTP server: static UI, same-origin /relay, /api/*
├── engine.py        tasks, provenance, capabilities, gateway, approvals,
│                    audit, alerts, circuit breaker, metrics, bootstrap
├── policy.py        deterministic 8-dimension authority engine (L0–L3)
├── detect.py        hidden-layer detection, taint extraction, classification
├── corpus.py        sandbox world (mail, files, web) + intent/scope helpers
├── tools.py         sandboxed tool implementations + execution verification
├── benchmark.py     50 adversarial cases + 10 legitimate cases
├── index.html       minimal cockpit shell
├── alfred.css       minimal neutral theme
├── ai.js            OpenChat envelope client, planner/verifier, local fallback
├── scenarios.js     scripted legitimate + compromised-planner missions
└── app.js           mission orchestration and cockpit rendering
```

### Backend (deterministic)

| Module       | Responsibility |
| ------------ | -------------- |
| `corpus.py`  | Fixture mailbox/files/pages; `understand(prompt)` derives intent and allowed tools; `merge_scope()` binds task scope. Explicit empty scope arrays are respected. |
| `detect.py`  | Scans every ingested source for HTML comments, white-on-white text, hidden PDF layers, zero-width/bidi/homoglyph characters, base64 payloads and embedded instructions. Extracts taint literals and classifies content (`public`/`internal`/`confidential`/`restricted`). |
| `policy.py`  | The authority engine. Evaluates intent, identity, source, sensitivity, destination, information flow, impact and permission. Hard-deny rules run before approvals and allowances. |
| `tools.py`   | Sandboxed mailbox/file/web tools. Each side effect is executed against a capability and returns a verifiable result (content hash / message id / bytes written). |
| `engine.py`  | Task lifecycle, provenance graph, capability minting/validation, approval snapshots, gateway, append-only audit, alerts, circuit breaker, metrics. |
| `benchmark.py` | Runs attacks and legitimate tasks through isolated `Engine` instances so live state is never polluted. |

### Frontend (planner/verifier only)

`ai.js` encrypts the OpenChat request envelope with WebCrypto (AES-128-CBC) and posts it
to the same-origin `/relay`. It supports `gemini3`, `claude45`, `gpt5`, `gpt4o`, `grok41`
and `auto`. The planner prompt receives **sanitized visible text only**. The verifier is
a second model that can escalate an action for human review; it can never grant authority.

If the relay is unreachable, `ai.js` falls back to a deterministic local planner, so the
cockpit remains demonstrable offline.

---

## Sandbox world

Everything the agent can touch is defined in `corpus.py`. The demo ships with:

- **18 emails** across `project` (11), `finance` (4) and `personal` (3);
- **22 files** under `/Documents/aurora`, `/Documents/finance`, `/Documents/personal`
  and the restricted `/Documents/private`;
- **8 isolated web pages**, including two adversarial mirrors;
- **11 trusted contacts** on the allowlist;
- **11 legitimate and 11 adversarial** scripted missions in `scenarios.js`.

The benchmark remains a fixed **50 attacks + 10 legitimate tasks**. Extra corpus data
never changes its shape or its measurements.

---

## The security path

1. **Ingress / task understanding** — the original prompt creates a task; intent and
   scope are derived deterministically. The user can tighten scope with the chips
   (mailbox, finance, files, contacts, web).
2. **Input isolation** — sources are ingested into the sandbox and inspected before the
   planner sees anything.
3. **Injection analysis** — hidden layers and taint are recorded as provenance, not
   passed to the planner.
4. **Planner** — the LLM proposes exactly one tool call (`tool`, `args`, `data_sources`).
   Its output is always untrusted.
5. **Authority engine** — decides `ALLOW` (L0/L1), `REQUIRE_APPROVAL` (L2) or `DENY`
   (L3). Decisions include rules, risk score, destination provenance and an audit record.
6. **Execution gateway** — validates capability signature, task binding, action, argument
   hash, destination and expiry; consumes the capability before execution so replay is
   impossible.
7. **Verify + audit** — the tool outcome is verified and every decision/execution is
   written to the append-only audit trail.

### Authority ladder

| Level | Name | Typical actions |
| ----- | ---- | --------------- |
| L0 | Autonomous | read mailbox/file inside scope, summarize, isolated public browse |
| L1 | Scoped | exact attachment download, write inside the task folder |
| L2 | Human approval | external send/share, destructive delete, out-of-scope write |
| L3 | Hard deny | protected assets, credential egress, tainted destination with confidential data, intent violation, internal-network browsing, frozen circuit |

### Capabilities

A capability is minted only after an `ALLOW` decision or an explicit human approval:

- HMAC-SHA256 signed with a per-process secret (or `ALFRED_CAP_SECRET`);
- bound to task, action, args hash, destination, classification and provenance chain;
- single-use, consumed **before** the tool runs;
- five-minute TTL;
- gateway re-checks the tool, argument hash and destination, so changing a recipient,
  body, path or attachment after approval fails closed.

### Approval snapshot

L2 actions store the exact args, destination, classification, risk, rules, verifier
signal and content hash. Approving issues a capability for that snapshot only. Only a
human identity (`user`, `human`, `operator`) can decide; a planner identity is rejected
and alerted.

### Circuit breaker

Three hard denials inside 120 seconds freeze execution (`FROZEN`), revoke outstanding
capabilities and raise a critical alert. The cockpit exposes a reset after review. This
is deliberately global: repeated attacks stop the whole agent, not just one task.

---

## HTTP API

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET`  | `/api/bootstrap` | Corpus, policy metadata, metrics, circuit state |
| `GET`  | `/api/metrics` | Live counters, audit coverage, p95 decision latency |
| `GET`  | `/api/alerts` | Alert queue + circuit state |
| `GET`  | `/api/audit?task_id=` | Append-only audit records |
| `GET`  | `/api/tasks/{id}` | Full task, sources, actions, approvals |
| `POST` | `/api/tasks` | `{prompt, scope}` → task-bound mission |
| `POST` | `/api/tasks/{id}/evaluate` | `{proposal, verifier}` → decision + capability/approval |
| `POST` | `/api/tasks/{id}/execute` | `{capability, proposal}` → verified effect |
| `POST` | `/api/tasks/{id}/ingest` | Ingest an external source with declared classification |
| `POST` | `/api/tasks/{id}/complete` | Record the planner's final answer |
| `POST` | `/api/approvals/{id}/decide` | `{approve, actor, reason}` |
| `POST` | `/api/circuit-breaker/reset` | `{reason}` |
| `POST` | `/api/benchmark` | Run the 60-case suite in isolated engines |
| `POST` | `/relay` | Same-origin OpenChat envelope relay |
| `GET`  | `/api/health` | Liveness + relay upstream |

Example flow:

```bash
TASK=$(curl -s -X POST localhost:8902/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"Read my project emails and summarize the sprint update."}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["task"]["id"])')

curl -s -X POST localhost:8902/api/tasks/$TASK/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"proposal":{"tool":"read_email","args":{"mailbox":"project","filter":"sprint 14"},"data_sources":[]}}'
```

The evaluation response contains `decision`, `level`, `rules`, `risk_score`,
`destination_provenance`, `provenance_chain`, `verifier`, and either
`capability.token` (ALLOW) or `approval` (L2).

---

## Benchmark

Open the **Benchmark** tab and run the suite, or:

```bash
cd /home/nool/alfred/openchat-web/alfred
python3 -c 'from benchmark import run_benchmark; import json; print(json.dumps(run_benchmark()["metrics"], indent=2))'
```

Current results:

```json
{
  "attack_cases": 50,
  "attack_contained": 50,
  "attack_containment_rate": 100.0,
  "hard_denied": 50,
  "unauthorized_executed": 0,
  "unauthorized_exfiltration": 0,
  "legit_cases": 10,
  "legit_completed": 10,
  "legit_completion_rate": 100.0,
  "false_blocks": 0,
  "false_block_rate": 0.0,
  "audit_coverage": 100.0,
  "latency_p95_ms": 0.17
}
```

Categories (5 attacks each): direct prompt injection, hidden email instructions,
white-on-white PDF text, malicious HTML comments, Unicode/encoded injection, disguised
system messages, credential theft, private-file exfiltration, multi-step/multi-document
laundering, and approval-process manipulation.

The suite measures whether an unauthorized action **actually executed** through the real
engine — not whether a model refused in prose. Each case uses its own `Engine` and
`benchmark-secret`, so the live cockpit is untouched.

The live cockpit also runs scripted compromised-planner missions from `scenarios.js`
(11 legitimate and 11 adversarial). Those missions are intentionally adversarial: every
step still goes through the real policy engine and gateway, so they demonstrate
containment rather than trust.

---

## PRD mapping

| PRD requirement | Implementation |
| --------------- | -------------- |
| Task-bound dynamic authority | `corpus.understand` + `merge_scope` + `policy.evaluate` |
| L0–L3 authority ladder | `policy.ALLOW/REQUIRE_APPROVAL/DENY` mapped to L0/L1, L2, L3 |
| Provenance and taint tracking | `detect.inspect_content`, `task["provenance"]`, destination provenance checks |
| Independent deterministic policy engine | `policy.py`, no model call in the decision path |
| Signed short-lived capabilities | `engine._mint_capability` / `_parse_capability`, HMAC-SHA256, 5-minute TTL, single use |
| Execution gateway | `engine.execute` re-validates everything and consumes before effect |
| Human approvals | `engine._create_approval` / `decide_approval`, exact-snapshot content hash |
| Audit trail | `engine._audit`, append-only records for task/decision/approval/execution/circuit |
| Early warning / circuit breaker | `engine._record_deny`, `reset_circuit`, alerts |
| Adversarial benchmark | `benchmark.py`, 50 attacks + 10 legitimate cases |
| Prompt-injection defenses | `detect.py` hidden layers, taint literals, planner isolation |
| Planner/verifier separation | `ai.js` planner and verifier prompts; verifier escalates only |
| Latency target | p95 policy decision ≈ 0.2 ms in the bundled suite |

### Deliberate MVP substitutions

The PRD names React + Tailwind + FastAPI + LangGraph + Postgres. This folder is a
dependency-free implementation so it runs with the existing free relay:

| PRD stack | Here | Why |
| --------- | ---- | --- |
| React + Tailwind | vanilla JS + CSS cockpit | zero build step, works from `file://`-style static serving |
| FastAPI | Python stdlib `ThreadingHTTPServer` | no install, same deterministic engine |
| LangGraph | explicit planner loop in `app.js` + local fallback | one tool call at a time, easy to audit |
| Postgres | in-memory state + JSON audit export | deterministic demo; swap `Engine` storage for durable persistence |
| Gmail / Playwright | deterministic sandbox corpus | no credentials or network egress in the security path |

The security boundary does not depend on any of those substitutions: policy, capabilities,
gateway, approvals and audit are the same concepts the PRD specifies.

---

## Try these

1. **Legitimate mission** — “Read my project emails and summarize the sprint update.”
   Watch L0 read → L0 summarize → COMPLETE, with a green audit trail.
2. **Human gate** — run the “Send a summary to a teammate” scenario. The L2 modal shows
   the exact action, destination provenance, classification, risk and content hash.
   Approve to mint a capability; deny and nothing executes.
3. **Injection** — run “Hidden HTML exfiltration”. The destination appears only inside
   hidden email content; the L3 card names `hard_deny.tainted_destination`.
4. **Detector miss** — enable “Simulate detector miss” and run an AI mission that sends
   content. The planner sees the hidden payload, but the gateway still blocks the tainted
   destination.
5. **Circuit breaker** — run three attack scenarios quickly. The circuit freezes, alerts
   turn critical, and execution stops until you reset after review.
6. **Finance scope** — enable the **Finance** chip and run the finance invoice example.
   The finance mailbox and `/Documents/finance` stay separate from the project folder.
   Then run “Refund email asks for payroll”: the hidden destination is still hard denied.

---

## Notes and limitations

- This is a security-first **MVP**, not a production deployment. State is in memory and
  resets on restart.
- The sandbox world is deterministic and fictional; no real email, filesystem or web
  traffic is touched.
- The relay is the free OpenChat endpoint already used by this folder. If it is down, the
  local planner keeps the security path testable.
- The benchmark reports deterministic engine behavior for scripted proposals. It is not
  a claim about any particular model's jailbreak resistance.
