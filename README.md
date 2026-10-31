# ALFRED — Security-First Autonomous Agent (TB-DAS)

A working implementation of the Task-Bound Dynamic Authority System (TB-DAS) described in `TB-DAS-Security-First-Agent-PRD.docx`.

> **The AI proposes. The policy engine decides. The gateway executes. The audit records.**

The model is never authority. Every tool call is a proposal that crosses a deterministic Python policy engine, receives an explicit L0–L3 decision, and — if allowed — is executed only through an HMAC-signed, single-use, 5-minute capability token bound to the exact arguments and destination.

---

## Architecture Overview

1. **Layer 1: Task Understanding & Ingress** — Prompt decomposition into intent and bounded task scope.
2. **Layer 2: Untrusted Input Isolation** — Content labeled `untrusted_external_data` with source provenance tracking.
3. **Layer 3: Ingestion & Injection Inspection** — Hidden comments, PDF text layers, zero-width chars, base64 payload scanning and risk scoring.
4. **Layer 4: Planner / Proposal Generation** — Receives visible sanitized text only; produces untrusted proposals.
5. **Layer 5: Independent Authority & Policy Engine** — Evaluates 8 dimensions (Intent, Identity, Source, Sensitivity, Destination, Information Flow, Impact, Permission).
6. **Layer 6: Secure Execution Gateway** — Validates capability signature, expiration, single-use nonce, and argument hash before calling tools.
7. **Layer 7: Execution & Verification** — Verifies post-execution state, produces audit record.

---

## Quickstart

```bash
cd openchat-web
python3 alfred/server.py
# Open http://127.0.0.1:8902/ in your browser
```

### Environment Variables
- `ALFRED_PORT` / `PORT`: HTTP port (default: `8902`)
- `ALFRED_CAP_SECRET`: HMAC capability signing secret (random per process if unset)

---

## Repository Structure

```
├── openchat-web/
│   ├── alfred/               # TB-DAS core engine, policy, detect, tools, cockpit UI
│   │   ├── server.py         # HTTP server & relay
│   │   ├── engine.py         # Task state, capabilities, gateway, audit, circuit breaker
│   │   ├── policy.py         # Deterministic L0–L3 authority engine
│   │   ├── detect.py         # Content classification & hidden-layer detector
│   │   ├── tools.py          # Sandboxed & verified tool implementations
│   │   ├── corpus.py         # Mock world & scope definitions
│   │   ├── benchmark.py      # 50-attack + 10-legitimate test suite
│   │   ├── index.html        # Cockpit dashboard
│   │   ├── alfred.css        # Minimal theme
│   │   ├── ai.js             # Planner / verifier client
│   │   ├── scenarios.js      # Scripted test scenarios
│   │   └── app.js            # Frontend cockpit controller
│   ├── arena/                # Arena interface
│   ├── server.py             # OpenChat web server
│   └── PROTO.md              # OpenChat protocol spec
└── TB-DAS-Security-First-Agent-PRD.docx  # Full Product Requirements Document
```
