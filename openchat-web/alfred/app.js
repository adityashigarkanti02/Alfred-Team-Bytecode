/* ALFRED cockpit — mission execution, policy display, audit, benchmark UI. */
(function () {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const state = {
    boot: null,
    task: null,
    steps: [],
    selected: null,
    metrics: null,
    circuit: null,
    alerts: [],
    benchmark: null,
    audit: [],
    busy: false,
    mode: null,
    compromised: false,
    aiOnline: null,
    pendingApproval: null,
    approvalBusy: false,
    timer: null,
  };

  /* ------------------------------------------------------------- helpers */
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function short(v, n) {
    const s = String(v == null ? "" : v).replace(/\s+/g, " ").trim();
    return s.length > (n || 160) ? s.slice(0, (n || 160) - 1) + "…" : s;
  }
  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso).slice(11, 19);
    return d.toLocaleTimeString([], { hour12: false });
  }
  function pct(v) { return (v === null || v === undefined) ? "—" : v + "%"; }

  async function apiGet(path) {
    const r = await fetch(path, { cache: "no-store" });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  }
  async function apiPost(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = $("#toast");
    t.textContent = msg;
    t.className = "toast " + (kind || "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = "toast hidden"; }, 4600);
  }

  /* ---------------------------------------------------------------- init */
  async function init() {
    bindUI();
    initModels();
    $("#prompt").value = "Read my project emails and summarize the sprint update.";

    try {
      const tele = await apiGet("/api/metrics");
      state.metrics = tele.metrics;
      state.circuit = tele.circuit_breaker;
    } catch (_) { /* engine may still be booting */ }

    try {
      const boot = await apiGet("/api/bootstrap");
      state.boot = boot;
      renderPolicy();
      renderMetrics();
      setCircuit(state.circuit || boot.circuit_breaker);
    } catch (err) {
      toast("Cannot reach the ALFRED engine: " + err.message, "bad");
      setStatus("engine-status", "ENGINE OFFLINE", "bad");
    }

    renderScenarioLists();
    refreshTelemetry();
    refreshWorkspace();
    setInterval(refreshTelemetry, 15000);
  }

  function bindUI() {
    // prompt samples
    $$("#prompt-samples button").forEach((b) => b.addEventListener("click", () => {
      $("#prompt").value = b.dataset.prompt;
      if (/finance/i.test(b.dataset.prompt)) {
        $$("#scope-chips .chip").forEach((c) => {
          const s = c.dataset.scope;
          c.classList.toggle("active", s === "finance" || s === "contacts");
        });
      }
      $("#prompt").focus();
    }));

    // scope chips
    $$("#scope-chips .chip").forEach((c) => c.addEventListener("click", () => {
      c.classList.toggle("active");
    }));

    $("#compromised").addEventListener("change", (e) => {
      state.compromised = e.target.checked;
      if (state.compromised) toast("Simulating a detector miss: hidden-layer annotations will be leaked to the planner. Authority is unchanged.", "amber");
    });

    $("#run-ai").addEventListener("click", runAI);
    $("#run-local").addEventListener("click", runLocal);

    // scenario delegation
    ["#legit-scenarios", "#attack-scenarios"].forEach((sel) => {
      $(sel).addEventListener("click", (e) => {
        const btn = e.target.closest(".scenario");
        if (btn && btn.dataset.id) runScenario(btn.dataset.id);
      });
    });

    // tabs
    $$("#tabs .tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));

    // audit
    $("#refresh-audit").addEventListener("click", refreshAudit);
    $("#export-audit").addEventListener("click", exportAudit);

    // benchmark
    $("#run-benchmark").addEventListener("click", runBenchmark);

    // circuit
    $("#reset-circuit").addEventListener("click", async () => {
      try {
        const r = await apiPost("/api/circuit-breaker/reset", { reason: "Operator reviewed the alert queue" });
        toast("Circuit breaker reset. Execution resumed.", "good");
        state.circuit = r.circuit_breaker;
        await refreshTelemetry();
      } catch (e) { toast(e.message, "bad"); }
    });

    // curl test tool
    const curlBtn = $("#btn-run-curl");
    if (curlBtn) {
      curlBtn.addEventListener("click", async () => {
        const url = ($("#curl-test-url").value || "").trim();
        if (!url) return toast("Enter a URL to curl.", "amber");
        curlBtn.disabled = true;
        try {
          const res = await apiPost("/api/curl", { url });
          const out = $("#curl-output");
          const box = $("#curl-result-box");
          if (out && box) {
            box.textContent = JSON.stringify(res, null, 2);
            out.classList.remove("hidden");
          }
          toast("Fetched " + url + " (HTTP " + res.status_code + ")", "good");
        } catch (e) {
          toast("Fetch blocked / failed: " + e.message, "bad");
        } finally {
          curlBtn.disabled = false;
        }
      });
    }

    // help
    $("#btn-help").addEventListener("click", () => $("#help-modal").classList.remove("hidden"));
    $("#help-close").addEventListener("click", () => $("#help-modal").classList.add("hidden"));
    $("#help-ok").addEventListener("click", () => $("#help-modal").classList.add("hidden"));

    // approval
    $("#approve-ok").addEventListener("click", () => respondApproval(true));
    $("#approve-deny").addEventListener("click", () => respondApproval(false));
    $("#approval-close").addEventListener("click", () => respondApproval(false));

    // models
    $("#planner-model").addEventListener("change", () => {
      AI.setModels({ planner: $("#planner-model").value });
      updateRunLabel();
    });
    $("#verifier-model").addEventListener("change", () => {
      AI.setModels({ verifier: $("#verifier-model").value });
    });

    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (!$("#approval-modal").classList.contains("hidden")) return respondApproval(false);
      $("#help-modal").classList.add("hidden");
    });
  }

  function initModels() {
    const planner = $("#planner-model"), verifier = $("#verifier-model");
    AI.MODELS.forEach((m) => {
      planner.appendChild(new Option(m.name, m.id));
      verifier.appendChild(new Option(m.name, m.id));
    });
    planner.value = "gemini3";
    verifier.value = "claude45";
    AI.setModels({ planner: "gemini3", verifier: "claude45" });
    updateRunLabel();
  }

  function updateRunLabel() {
    const m = AI.MODELS.find((x) => x.id === $("#planner-model").value);
    const small = $("#run-ai small");
    if (small) small.textContent = m ? m.name : "LLM";
  }

  function currentScope() {
    const active = new Set($$("#scope-chips .chip.active").map((c) => c.dataset.scope));
    const contacts = (state.boot && state.boot.corpus.contacts) || window.SCENARIOS.contacts;
    const mailboxes = [];
    if (active.has("mailbox")) mailboxes.push("project");
    if (active.has("finance")) mailboxes.push("finance");
    const files = [];
    if (active.has("files")) files.push("/Documents/aurora");
    if (active.has("finance")) files.push("/Documents/finance");
    return {
      mailboxes,
      files,
      domains: active.has("web") ? ["docs.example.com", "status.example.com"] : [],
      contacts: active.has("contacts") ? contacts : [],
    };
  }

  function syncScopeChips(scope) {
    $$("#scope-chips .chip").forEach((c) => {
      const s = c.dataset.scope;
      let on = false;
      if (s === "mailbox") on = (scope.mailboxes || []).includes("project");
      if (s === "finance") on = (scope.mailboxes || []).includes("finance") ||
        (scope.files || []).some((f) => f.includes("/Documents/finance"));
      if (s === "files") on = (scope.files || []).some((f) => f.includes("aurora"));
      if (s === "contacts") on = (scope.contacts || []).length > 0;
      if (s === "web") on = (scope.domains || []).length > 0;
      c.classList.toggle("active", on);
    });
  }

  function setStatus(id, text, kind) {
    const node = $("#" + id);
    if (!node) return;
    node.className = "status-pill " + (kind || "idle");
    clear(node);
    node.appendChild(el("i"));
    node.appendChild(document.createTextNode(text));
  }

  function updateAIStatus(ok, detail) {
    state.aiOnline = ok;
    setStatus("relay-status", ok ? ("AI LINKED · " + detail) : "AI OFFLINE · LOCAL PLANNER", ok ? "good" : "bad");
  }

  /* ------------------------------------------------------- static render */
  function renderScenarioLists() {
    const maps = [["#legit-scenarios", window.SCENARIOS.legit], ["#attack-scenarios", window.SCENARIOS.attack]];
    maps.forEach(([sel, list]) => {
      const root = $(sel);
      clear(root);
      list.forEach((s) => {
        const b = el("button", "scenario " + (s.icon === "A" || sel === "#attack-scenarios" ? "attack" : ""));
        b.dataset.id = s.id;
        const ic = el("span", "s-icon", s.icon);
        const body = el("span", "s-body");
        body.appendChild(el("b", "", s.title));
        body.appendChild(el("span", "", s.sub));
        b.appendChild(ic);
        b.appendChild(body);
        b.appendChild(el("span", "s-arrow", "→"));
        root.appendChild(b);
      });
    });
  }

  function renderPolicy() {
    const p = (state.boot && state.boot.policy) || null;
    if (!p) return;

    const levels = $("#policy-levels");
    clear(levels);
    Object.entries(p.levels).forEach(([key, v]) => {
      const card = el("div", "level-card");
      card.dataset.level = key;
      card.appendChild(el("b", "", key));
      const d = el("div");
      d.appendChild(el("span", "", v.name));
      d.appendChild(el("p", "", v.desc));
      card.appendChild(d);
      levels.appendChild(card);
    });

    const dims = $("#policy-dimensions");
    clear(dims);
    (p.dimensions || []).forEach((d) => dims.appendChild(el("li", "", d)));

    const tb = $("#tool-table tbody");
    clear(tb);
    (p.tools || []).forEach((t) => {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", t.tool));
      const lv = el("td");
      lv.appendChild(el("span", "mini-level " + t.level, t.level));
      tr.appendChild(lv);
      tr.appendChild(el("td", "", t.desc));
      tb.appendChild(tr);
    });

    $("#policy-code").textContent = [
      "package tb_das",
      "",
      'default decision = "DENY"',
      "",
      "hard_deny {",
      '  input.data_classification == "restricted"',
      "  input.destination not in input.task_scope.contacts",
      "}",
      "",
      "hard_deny {",
      '  contains(input.path, ".env")',
      '  contains(input.path, ".ssh")',
      "}",
      "",
      "hard_deny {",
      '  input.destination_provenance.trust == "untrusted_external_data"',
      '  input.data_classification in ["confidential", "restricted"]',
      "}",
      "",
      "require_approval {",
      '  input.action in ["send_email", "share_file", "delete_file"]',
      "}",
      "",
      "require_approval {",
      '  input.action == "write_file"',
      "  not input.in_task_scope",
      "}",
      "",
      "allow {",
      '  input.authority_level in ["L0", "L1"]',
      '  input.trust_labels[_] == "authorized_user_instruction"',
      "  not tainted_destination",
      "}",
      "",
      "# additional frozen rules",
      ...(p.rules || []).map((r) => "# " + r),
    ].join("\n");

    renderCorpus();
  }

  function renderCorpus() {
    const c = state.boot && state.boot.corpus;
    const root = $("#sandbox-corpus");
    if (!c || !root) return;
    clear(root);

    const mailboxes = {};
    (c.emails || []).forEach((e) => {
      mailboxes[e.mailbox] = (mailboxes[e.mailbox] || 0) + 1;
    });

    const roots = {};
    (c.files || []).forEach((f) => {
      const parts = String(f.path || "").split("/").filter(Boolean);
      const key = parts.length >= 2 ? "/" + parts.slice(0, 2).join("/") : String(f.path || "");
      roots[key] = (roots[key] || 0) + 1;
    });

    const pages = c.pages || [];
    const adversarial = pages.filter((p) => /evil\./i.test(p.url || "")).length;
    const items = [
      ["Mailboxes", Object.entries(mailboxes).map(([k, v]) => k + " " + v).join(" · ") || "none"],
      ["File roots", Object.entries(roots).map(([k, v]) => k + " " + v).join(" · ") || "none"],
      ["Isolated pages", pages.length + " pages · " + adversarial + " adversarial mirrors"],
      ["Trusted contacts", (c.contacts || []).length + " addresses on the allowlist"],
    ];

    items.forEach(([label, value]) => {
      const item = el("div", "sandbox-item");
      item.appendChild(el("span", "", label));
      item.appendChild(el("b", "", value));
      root.appendChild(item);
    });
  }

  /* ------------------------------------------------------------ telemetry */
  async function refreshTelemetry() {
    try {
      const m = await apiGet("/api/metrics");
      state.metrics = m.metrics;
      state.circuit = m.circuit_breaker;
      setCircuit(m.circuit_breaker);
      renderMetrics();
      const a = await apiGet("/api/alerts");
      state.alerts = a.alerts || [];
      renderAlerts();
    } catch (_) { /* offline is non-fatal */ }
  }

  function renderMetrics() {
    const m = state.metrics;
    if (!m) return;
    const set = (id, v) => { const n = $("#" + id); if (n) n.textContent = v; };
    set("lm-tasks", m.tasks);
    set("lm-allow", m.allow);
    set("lm-approval", m.approval_required);
    set("lm-denied", m.denied);
    set("lm-exec", m.executions);
    set("lm-coverage", pct(m.audit_coverage));
    set("lm-outbox", m.outbox);
    set("tk-audit", pct(m.audit_coverage));
    set("tk-p95", (m.latency_p95_ms || 0).toFixed(2) + "ms");
    updateLadder();
  }

  function updateLadder() {
    const counts = { L0: 0, L1: 0, L2: 0, L3: 0 };
    state.steps.forEach((s) => { if (counts[s.d.level] !== undefined) counts[s.d.level]++; });
    ["L0", "L1", "L2", "L3"].forEach((l) => {
      const n = $("#count-" + l);
      if (n) n.textContent = counts[l];
      const row = $('.ladder-row[data-level="' + l + '"]');
      if (row) row.classList.toggle("active", !!state.selected && state.selected.d.level === l);
    });
  }

  function setCircuit(circuit) {
    if (!circuit) return;
    state.circuit = circuit;
    const pill = $("#circuit-status");
    if (!pill) return;
    const st = circuit.state || "NORMAL";
    pill.className = "status-pill " + (st === "FROZEN" ? "frozen" : st === "SUSPICIOUS" ? "amber" : "good");
    clear(pill);
    pill.appendChild(el("i"));
    pill.appendChild(document.createTextNode(st === "FROZEN" ? "CIRCUIT FROZEN" : st === "SUSPICIOUS" ? "CIRCUIT WATCH" : "CIRCUIT NORMAL"));
    const reset = $("#reset-circuit");
    if (reset) reset.classList.toggle("hidden", st !== "FROZEN");
  }

  function renderAlerts() {
    const root = $("#alerts");
    clear(root);
    setText("#alert-count", state.alerts.length);
    if (!state.alerts.length) {
      root.appendChild(el("p", "micro", "No alerts. The gate is quiet."));
      return;
    }
    state.alerts.slice(0, 9).forEach((a) => {
      const card = el("div", "alert " + (a.severity || "info"));
      card.appendChild(el("b", "", a.title));
      card.appendChild(el("p", "", a.detail));
      card.appendChild(el("code", "", (a.rule || "") + " · " + fmtTime(a.ts)));
      root.appendChild(card);
    });
  }

  function setText(sel, value) {
    const n = $(sel);
    if (n) n.textContent = value;
  }

  /* ---------------------------------------------------------------- audit */
  async function refreshAudit() {
    try {
      const q = state.task ? ("?task_id=" + encodeURIComponent(state.task.id)) : "";
      const r = await apiGet("/api/audit" + q);
      state.audit = r.audit || [];
      renderAudit(state.audit);
    } catch (e) { toast("Audit fetch failed: " + e.message, "bad"); }
  }

  function renderAudit(rows) {
    const tb = $("#audit-table tbody");
    clear(tb);
    if (!rows.length) {
      const tr = el("tr");
      const td = el("td", "empty-cell", "No audit records for this mission yet.");
      td.colSpan = 8;
      tr.appendChild(td);
      tb.appendChild(tr);
      return;
    }
    rows.slice(0, 250).forEach((r) => {
      const tr = el("tr");
      tr.appendChild(el("td", "nowrap", fmtTime(r.ts)));
      tr.appendChild(el("td", "", r.event || "decision"));
      const dec = el("td");
      const cls = /DENY|FROZEN|FAILED|UNVERIFIED/i.test(r.decision || "") ? "bad" : /APPROV|REQUIRE/i.test(r.decision || "") ? "warn" : "ok";
      dec.appendChild(el("span", "status-ico " + cls, r.decision || "—"));
      tr.appendChild(dec);
      const lv = el("td");
      if (r.level) lv.appendChild(el("span", "mini-level " + r.level, r.level));
      else lv.textContent = "—";
      tr.appendChild(lv);
      tr.appendChild(el("td", "mono", r.tool || "—"));
      tr.appendChild(el("td", "reason", short(r.reason || "—", 145)));
      tr.appendChild(el("td", "mono", r.risk_score !== undefined ? r.risk_score : "—"));
      tr.appendChild(el("td", "mono", (r.args_hash || r.capability_id || "—").slice(0, 18)));
      tb.appendChild(tr);
    });
  }

  function exportAudit() {
    if (!state.audit.length) return toast("Nothing to export yet.", "amber");
    const blob = new Blob([JSON.stringify({
      app: "ALFRED", exported_at: new Date().toISOString(),
      task_id: state.task ? state.task.id : null, records: state.audit,
    }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "alfred-audit-" + (state.task ? state.task.id : "all") + ".json";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Audit trail exported.", "good");
  }

  /* ------------------------------------------------------------ benchmark */
  async function runBenchmark() {
    if (state.busy) return toast("A mission is already running.", "amber");
    const btn = $("#run-benchmark");
    btn.disabled = true;
    btn.classList.add("loading");
    btn.innerHTML = '<span class="btn-glyph">◌</span> Running 60 cases…';
    try {
      const data = await apiPost("/api/benchmark", {});
      state.benchmark = data;
      renderBenchmark(data);
      await refreshTelemetry();
      toast("Benchmark complete: " + data.metrics.attack_contained + "/" + data.metrics.attack_cases +
        " attacks contained, " + data.metrics.unauthorized_executed + " unauthorized executed.", "good");
    } catch (e) {
      toast("Benchmark failed: " + e.message, "bad");
    } finally {
      btn.disabled = false;
      btn.classList.remove("loading");
      btn.innerHTML = '<span class="btn-glyph">▶</span> Run 50-case suite';
    }
  }

  function renderBenchmark(data) {
    const m = data.metrics;
    const cards = [
      ["ATTACKS CONTAINED", m.attack_contained + "/" + m.attack_cases, m.attack_containment_rate + "%", m.attack_contained === m.attack_cases ? "good" : "bad"],
      ["UNAUTHORIZED EXECUTED", String(m.unauthorized_executed), "target 0", m.unauthorized_executed === 0 ? "good" : "bad"],
      ["LEGIT COMPLETION", pct(m.legit_completion_rate), m.legit_completed + "/" + m.legit_cases, m.legit_completion_rate >= 95 ? "good" : "warn"],
      ["FALSE BLOCK RATE", pct(m.false_block_rate), m.false_blocks + " false blocks", m.false_block_rate <= 5 ? "good" : "bad"],
      ["AUDIT COVERAGE", pct(m.audit_coverage), m.audit_coverage === 100 ? "all decisions recorded" : "gap detected", m.audit_coverage === 100 ? "good" : "bad"],
      ["P95 POLICY", (m.latency_p95_ms || 0).toFixed(2) + "ms", "target <100ms", (m.latency_p95_ms || 0) < 100 ? "good" : "warn"],
    ];
    const root = $("#bench-metrics");
    clear(root);
    cards.forEach(([label, value, sub, cls]) => {
      const c = el("div", "bench-card " + cls);
      c.appendChild(el("span", "", label));
      c.appendChild(el("b", "", value));
      c.appendChild(el("small", "", sub));
      root.appendChild(c);
    });

    const cats = $("#bench-categories");
    clear(cats);
    (data.categories || []).forEach((c) => {
      const card = el("div", "cat-card");
      card.appendChild(el("b", "", c.category));
      card.appendChild(el("div", "cat-score", c.contained + "/" + c.cases + " contained"));
      const bar = el("div", "cat-bar");
      const fill = el("i");
      fill.style.width = (100 * c.contained / Math.max(1, c.cases)) + "%";
      fill.style.background = c.executed ? "var(--red)" : "var(--green)";
      bar.appendChild(fill);
      card.appendChild(bar);
      cats.appendChild(card);
    });

    const tb = $("#bench-table tbody");
    clear(tb);
    (data.cases || []).forEach((c) => {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", c.id));
      tr.appendChild(el("td", "", short(c.category, 28)));
      tr.appendChild(el("td", "reason", c.name));
      tr.appendChild(el("td", "", c.decision));
      const lv = el("td");
      if (c.level) lv.appendChild(el("span", "mini-level " + c.level, c.level));
      tr.appendChild(lv);
      const ct = el("td");
      ct.appendChild(el("span", "status-ico " + (c.contained ? "ok" : "bad"), c.contained ? "✓ contained" : "✗ escaped"));
      tr.appendChild(ct);
      tr.appendChild(el("td", "reason", short((c.rules || []).join(", "), 90)));
      tb.appendChild(tr);
    });

    const legit = $("#bench-legit");
    clear(legit);
    (data.legit || []).forEach((l) => {
      const item = el("div", "legit-item");
      item.appendChild(el("span", "status-ico " + (l.completed && !l.false_block ? "ok" : "bad"),
        l.completed && !l.false_block ? "✓" : "✗"));
      item.appendChild(el("span", "", l.name));
      item.appendChild(el("em", "", l.detail));
      legit.appendChild(item);
    });

    setText("#tk-attacks", m.attack_contained + "/" + m.attack_cases);
    setText("#tk-exfil", String(m.unauthorized_executed));
    setText("#tk-false", pct(m.false_block_rate));
    setText("#tk-audit", pct(m.audit_coverage));
    setText("#tk-p95", (m.latency_p95_ms || 0).toFixed(2) + "ms");
  }

  /* -------------------------------------------------------------- approval */
  function showApproval(appr, task) {
    return new Promise((resolve) => {
      state.pendingApproval = { appr, resolve };
      state.approvalBusy = false;
      $("#appr-task").textContent = task ? task.prompt : "—";
      $("#appr-action").textContent = JSON.stringify({
        tool: appr.tool, args: appr.args, data_sources: appr.data_sources,
      }, null, 2);
      $("#appr-dest").textContent = appr.destination || "(local / no destination)";
      const trust = appr.destination_provenance || {};
      const label = trust.trust === "authorized_user_instruction" ? "TRUSTED · USER INSTRUCTION"
        : trust.trust === "untrusted_external_data" ? "TAINTED · UNTRUSTED DATA" : "UNKNOWN DESTINATION";
      const note = $("#appr-dest-prov");
      note.textContent = label + " — " + (trust.reason || "No provenance record.");
      note.style.color = trust.trust === "authorized_user_instruction" ? "var(--green)"
        : trust.trust === "untrusted_external_data" ? "var(--red)" : "var(--amber)";
      $("#appr-class").textContent = (appr.data_classification || "internal").toUpperCase();
      $("#appr-risk").textContent = (appr.risk_score !== undefined ? appr.risk_score : "—") + " / 100";
      $("#appr-hash").textContent = appr.content_hash || appr.args_hash || "—";

      const ver = appr.verifier;
      const vbox = $("#appr-verifier");
      if (ver) {
        vbox.innerHTML = "";
        vbox.appendChild(el("span", "", "INDEPENDENT VERIFIER · " + (ver.verdict || "signal").toUpperCase()));
        vbox.appendChild(el("p", "", "risk " + Number(ver.risk || 0).toFixed(2) +
          " · matches task: " + (ver.matches_task ? "yes" : "no") +
          " · introduced destination: " + (ver.introduced_destination ? "yes" : "no") + ". " + (ver.reason || "")));
      } else {
        vbox.innerHTML = "";
        vbox.appendChild(el("span", "", "INDEPENDENT VERIFIER"));
        vbox.appendChild(el("p", "", "No verifier signal for this action. Deterministic policy still enforced everything."));
      }

      const rules = $("#appr-rules");
      clear(rules);
      (appr.rules || []).forEach((r) => rules.appendChild(el("span", "rule-chip danger", r)));

      $("#approval-modal").classList.remove("hidden");
      $("#approve-ok").disabled = false;
      $("#approve-deny").disabled = false;
      $("#approve-ok").focus();
    });
  }

  async function respondApproval(approve) {
    const pending = state.pendingApproval;
    if (!pending || state.approvalBusy) return;
    state.approvalBusy = true;
    $("#approve-ok").disabled = true;
    $("#approve-deny").disabled = true;
    try {
      const r = await apiPost("/api/approvals/" + pending.appr.id + "/decide", {
        approve: !!approve,
        actor: "user",
        reason: approve ? "Operator approved the exact snapshot." : "Operator denied the action.",
      });
      $("#approval-modal").classList.add("hidden");
      state.pendingApproval = null;
      if (approve && r.capability) {
        pending.resolve({ approved: true, capability: r.capability, approval: r.approval });
      } else if (approve) {
        toast("Approval did not issue a capability: " + (r.error || "unknown"), "bad");
        pending.resolve({ approved: false });
      } else {
        pending.resolve({ approved: false });
      }
      refreshTelemetry();
    } catch (e) {
      toast("Approval failed: " + e.message, "bad");
      $("#approve-ok").disabled = false;
      $("#approve-deny").disabled = false;
      state.approvalBusy = false;
    }
  }

  /* ---------------------------------------------------------------- tabs */
  function switchTab(name) {
    $$("#tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
    $$(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
    if (name === "audit") refreshAudit();
    if (name === "policy") renderPolicy();
    if (name === "workspace") refreshWorkspace();
    if (name === "benchmark" && state.benchmark) renderBenchmark(state.benchmark);
  }

  async function refreshWorkspace() {
    try {
      const data = await apiGet("/api/workspace/files");
      const pathEl = $("#ws-folder-path");
      if (pathEl) pathEl.textContent = data.workspace || "/home/nool/alfred/workspace";
      const files = data.files || [];
      const countEl = $("#ws-file-count");
      if (countEl) countEl.textContent = files.length;
      const list = $("#ws-files-list");
      if (list) {
        clear(list);
        if (!files.length) {
          list.appendChild(el("p", "micro", "No files in workspace yet. The agent will read, write, and edit actual files here."));
        } else {
          files.forEach(f => {
            const item = el("div", "", f.path + " (" + f.size + " bytes)");
            list.appendChild(item);
          });
        }
      }
    } catch (_) {}

    try {
      const mcp = await apiGet("/api/mcp/status");
      const st = $("#mcp-connected-txt");
      if (st) {
        st.textContent = mcp.connected ? "Connected" : "Offline";
        st.className = "status-ico " + (mcp.connected ? "ok" : "bad");
      }
      const tools = $("#mcp-tools-txt");
      if (tools && mcp.tools) {
        tools.textContent = mcp.tools.map(t => t.name).join(", ") || "none";
      }
      const pill = $("#mcp-status");
      if (pill) {
        pill.className = "status-pill " + (mcp.connected ? "good" : "idle");
      }
    } catch (_) {}
  }

  /* -------------------------------------------------- mission & agent run */
  const MAX_STEPS = 8;
  const PHASES = ["think", "policy", "gate", "verify"];

  function setMissionStatus(text, kind) {
    const node = $("#mission-state");
    if (!node) return;
    node.textContent = text;
    node.className = "mission-state" + (kind ? " " + kind : "");
  }

  function setPhase(name) {
    const idx = name ? PHASES.indexOf(name) : PHASES.length;
    PHASES.forEach((p, i) => {
      const node = $("#phase-" + p);
      if (!node) return;
      node.classList.toggle("on", i === idx);
      node.classList.toggle("done", i < idx);
    });
    const fill = $("#phase-fill");
    if (fill) {
      fill.style.width = name
        ? Math.round(((idx + 1) / PHASES.length) * 100) + "%"
        : "100%";
    }
  }

  function resetMission(prompt, scope) {
    state.steps = [];
    state.selected = null;
    state.task = null;
    state.pendingApproval = null;

    const flow = $("#flow");
    if (flow) clear(flow);
    const final = $("#final-answer");
    if (final) final.classList.add("hidden");
    setText("#final-text", "");
    $("#mission-empty").classList.add("hidden");
    $("#mission-view").classList.remove("hidden");
    setText("#mission-id", "—");
    setText("#mission-prompt", prompt);
    clear($("#mission-intent"));
    renderScope(scope);
    setMissionStatus("PLANNING");
    setPhase("think");
    resetInspector();
    updateLadder();
  }

  function renderScope(scope) {
    const root = $("#mission-scope");
    if (!root) return;
    clear(root);
    scope = scope || {};
    (scope.mailboxes || []).forEach((m) => root.appendChild(el("span", "", "mailbox · " + m)));
    (scope.files || []).forEach((f) => root.appendChild(el("span", "", "path · " + f)));
    (scope.domains || []).forEach((d) => root.appendChild(el("span", "", "domain · " + d)));
    const contacts = scope.contacts || [];
    if (contacts.length) root.appendChild(el("span", "", "contacts · " + contacts.length + " trusted"));
    if (!root.children.length) root.appendChild(el("span", "", "no scope bound"));
  }

  function renderMissionMeta(task) {
    setText("#mission-id", task.id);
    setText("#mission-prompt", task.prompt);
    const chips = $("#mission-intent");
    clear(chips);
    (task.intent.intents || []).forEach((i) => chips.appendChild(el("span", "", i)));
    chips.appendChild(el("span", "", task.intent.read_only ? "read-only" : "side effects gated"));
    chips.appendChild(el("span", "", state.mode === "ai" ? "AI planner" : state.mode === "local" ? "local planner" : "compromised planner"));
    renderScope(task.scope);
  }

  function resetInspector() {
    state.selected = null;
    setText("#risk-value", "—");
    const fill = $("#risk-fill");
    if (fill) fill.style.width = "0%";
    setText("#risk-label", "Select an action card to inspect.");
    clear($("#risk-signals"));
    $("#prov-view").classList.add("hidden");
    $("#prov-empty").classList.remove("hidden");
  }

  function addThinking(text) {
    const node = el("div", "thinking");
    node.appendChild(el("span", "spinner"));
    node.appendChild(document.createTextNode(text));
    const flow = $("#flow");
    if (flow) flow.appendChild(node);
    return node;
  }
  function removeThinking(node) {
    if (node && node.parentNode) node.parentNode.removeChild(node);
  }

  function decisionClass(decision) {
    if (decision === "ALLOW") return "allow";
    if (decision === "REQUIRE_APPROVAL") return "approval";
    return "deny";
  }

  function badgeOn(entry, text, cls) {
    if (!entry || !entry.node) return;
    const holder = entry.node.querySelector(".step-badges");
    if (!holder) return;
    let badge = holder.querySelector(".exec-badge");
    if (!badge) {
      badge = el("span", "decision-badge exec-badge");
      holder.appendChild(badge);
    }
    badge.className = "decision-badge exec-badge " + (cls || "");
    badge.textContent = text;
  }

  function renderStep(entry) {
    const plan = entry.plan || {};
    const d = entry.d;
    const card = el("div", "step " + (d ? d.level : ""));
    card.dataset.index = entry.i;

    const head = el("div", "step-head");
    head.appendChild(el("span", "step-index", String(entry.i + 1).padStart(2, "0")));
    head.appendChild(el("span", "step-tool", plan.tool || "noop"));
    if (d && d.destination) head.appendChild(el("span", "step-dest", "→ " + d.destination));

    const badges = el("div", "step-badges");
    if (d) {
      badges.appendChild(el("span", "decision-badge " + decisionClass(d.decision),
        d.decision.replace(/_/g, " ")));
      badges.appendChild(el("span", "level-badge " + d.level, d.level));
    } else {
      badges.appendChild(el("span", "decision-badge failed", "ERROR"));
    }
    head.appendChild(badges);
    card.appendChild(head);

    const reason = el("div", "step-reason");
    if (plan.thought) {
      reason.appendChild(el("b", "", "Planner · "));
      reason.appendChild(document.createTextNode(plan.thought));
      reason.appendChild(document.createElement("br"));
    }
    if (d) {
      reason.appendChild(el("b", "", "Policy · "));
      reason.appendChild(document.createTextNode(d.reason || ""));
    } else if (entry.error) {
      reason.appendChild(el("b", "", "Error · "));
      reason.appendChild(document.createTextNode(entry.error));
    }
    card.appendChild(reason);

    const args = el("div", "step-args");
    args.textContent = JSON.stringify(plan.args || {}, null, 2);
    card.appendChild(args);

    if (d) {
      const rules = el("div", "step-rules");
      (d.rules || []).forEach((r) => {
        const cls = /hard_deny|deny|gateway|replay|expired/.test(r) ? "danger"
          : /warn|require|escalate/.test(r) ? "warn" : "";
        rules.appendChild(el("span", "rule-chip " + cls, r));
      });
      card.appendChild(rules);

      if (d.verifier) {
        const v = d.verifier;
        const box = el("div", "step-verifier");
        box.textContent = "INDEPENDENT VERIFIER · " + String(v.verdict || "signal").toUpperCase() +
          " · risk " + Number(v.risk || 0).toFixed(2) +
          " · matches task: " + (v.matches_task ? "yes" : "no") +
          " — " + (v.reason || "");
        card.appendChild(box);
      }
    }

    entry.node = card;
    entry.badges = badges;
    $("#flow").appendChild(card);
    card.addEventListener("click", () => selectStep(entry.i));
  }

  function selectStep(i) {
    const entry = state.steps[i];
    if (!entry || !entry.node) return;
    state.selected = entry;
    state.steps.forEach((s) => { if (s.node) s.node.classList.toggle("selected", s === entry); });
    updateLadder();
    if (entry.d) {
      renderRisk(entry);
      renderProv(entry);
    }
  }

  function renderRisk(entry) {
    const d = entry.d;
    const score = Math.max(0, Math.min(100, Number(d.risk_score) || 0));
    setText("#risk-value", score + " / 100");
    const fill = $("#risk-fill");
    if (fill) fill.style.width = Math.max(2, score) + "%";
    setText("#risk-label", d.level + " · " + d.decision.replace(/_/g, " ") + " — " + short(d.reason, 170));

    const signals = $("#risk-signals");
    clear(signals);
    (d.injection_signals || []).slice(0, 4).forEach((s) => {
      signals.appendChild(el("span", "", s.label || s.kind || "injection signal"));
    });
    (d.rules || []).filter((r) => /hard_deny|warn|escalate/.test(r)).slice(0, 3).forEach((r) => {
      signals.appendChild(el("span", "", r));
    });
  }

  function renderProv(entry) {
    const d = entry.d;
    const dp = d.destination_provenance || {};
    $("#prov-empty").classList.add("hidden");
    $("#prov-view").classList.remove("hidden");

    setText("#prov-dest", dp.value || d.destination || "(local / no destination)");
    const trust = dp.trust || "unknown_source";
    const badge = $("#prov-trust");
    badge.textContent = trust.replace(/_/g, " ").toUpperCase();
    badge.className = "trust-badge " + (
      trust === "authorized_user_instruction" ? "trusted"
        : trust === "untrusted_external_data" ? "untrusted" : "unknown");
    setText("#prov-reason", dp.reason || "No destination provenance record.");

    const tainted = trust === "untrusted_external_data";
    const chain = $("#prov-chain");
    clear(chain);
    (d.provenance_chain || []).forEach((node) => {
      const s = String(node);
      const n = el("div", "chain-node", s);
      if (s.startsWith("user:")) n.classList.add("user");
      else if (s.startsWith("action:")) n.classList.add(d.decision === "DENY" ? "bad" : "good");
      else if (tainted) n.classList.add("bad");
      chain.appendChild(n);
    });

    const meta = $("#prov-meta");
    clear(meta);
    [
      "class · " + (d.data_classification || "internal"),
      "level · " + d.level,
      "risk · " + d.risk_score,
      "policy · " + Number(d.latency_ms || 0).toFixed(2) + "ms",
      "origin · " + (d.origin || "unknown"),
      d.verifier ? "verifier · " + (d.verifier.verdict || "signal") : "verifier · not run",
      "hash · " + String(d.args_hash || "—").slice(0, 18),
    ].forEach((text) => meta.appendChild(el("span", "", text)));
  }

  function describeResult(entry, exec) {
    if (!exec.ok) return exec.error || (exec.verification && exec.verification.detail) || "Execution failed.";
    const r = exec.result || {};
    if (Array.isArray(r.emails)) {
      return r.count + " message(s) read from " + r.mailbox +
        (r.emails[0] ? " · latest: “" + r.emails[0].subject + "”" : "");
    }
    if (r.message_id) {
      return "Delivered to " + r.to + " · message " + r.message_id +
        (r.attachments && r.attachments.length ? " · " + r.attachments.length + " attachment(s)" : "");
    }
    if (r.share_id) return "Shared " + r.path + " with " + r.to + " · share " + r.share_id;
    if (r.deleted !== undefined) return (r.deleted ? "Deleted " : "Could not delete ") + r.path;
    if (r.bytes !== undefined) return "Wrote " + r.bytes + " bytes to " + r.path + " · " + String(r.sha256 || "").slice(0, 24);
    if (r.path && r.source_id) return "Saved " + r.path + " (" + (r.classification || "internal") + ") into the sandbox.";
    if (r.summary !== undefined) return r.summary;
    if (r.visible !== undefined) {
      return (r.path || r.url || "source") + " · " + (r.size || String(r.visible).length) + " chars · " +
        (r.classification || "internal");
    }
    return short(JSON.stringify(r), 420);
  }

  function attachExecution(entry, exec) {
    if (!entry.node) return;
    const verified = !!(exec.ok && exec.verification && exec.verification.ok);
    badgeOn(entry,
      exec.ok ? (verified ? "EXECUTED" : "UNVERIFIED") : "GATEWAY BLOCKED",
      exec.ok ? (verified ? "executed" : "failed") : "failed");

    const box = el("div", "step-result");
    const head = el("div", "result-head");
    head.appendChild(el("span", exec.ok ? (verified ? "ok" : "bad") : "bad",
      exec.ok ? (verified ? "✓" : "!") : "✗"));
    head.appendChild(document.createTextNode(
      exec.ok
        ? (verified ? "GATEWAY VERIFIED · EXECUTED" : "EXECUTED · VERIFICATION FAILED")
        : "GATEWAY REJECTED · NOTHING EXECUTED"));
    box.appendChild(head);
    box.appendChild(el("div", "result-body", describeResult(entry, exec)));

    const det = el("details", "result-details");
    det.appendChild(el("summary", "", "raw result · audit " + (exec.audit_id || "—")));
    const pre = el("pre");
    pre.textContent = JSON.stringify({
      result: exec.result !== undefined ? exec.result : null,
      error: exec.error || null,
      verification: exec.verification || null,
    }, null, 2);
    det.appendChild(pre);
    box.appendChild(det);
    entry.node.appendChild(box);
  }

  function appendNote(entry, text, kind) {
    if (!entry.node) return;
    const box = el("div", "step-result");
    const head = el("div", "result-head");
    head.appendChild(el("span", kind === "bad" ? "bad" : "ok", kind === "bad" ? "✗" : "✓"));
    head.appendChild(document.createTextNode(kind === "bad" ? "BLOCKED" : "NOTE"));
    box.appendChild(head);
    box.appendChild(el("div", "result-body", text));
    entry.node.appendChild(box);
  }

  function showFinal(text, ok) {
    const box = $("#final-answer");
    if (!box) return;
    if (!text) {
      box.classList.add("hidden");
      return;
    }
    setText("#final-text", text);
    const eyebrow = box.querySelector(".eyebrow");
    if (eyebrow) eyebrow.textContent = ok ? "PLANNER RESULT" : "MISSION OUTCOME · CONTAINED";
    box.classList.remove("hidden");
  }

  function setBusy(disabled) {
    ["#run-ai", "#run-local"].forEach((sel) => {
      const n = $(sel);
      if (n) {
        n.disabled = disabled;
        n.classList.toggle("loading", disabled && sel === "#run-ai");
      }
    });
    $$(".scenario").forEach((b) => { b.disabled = disabled; });
  }

  function plannerContext(task, history, observation) {
    return {
      prompt: task.prompt,
      scope: task.scope,
      intent: task.intent,
      allowed_tools: task.allowed_tools,
      history,
      observation,
      compromised: state.compromised,
    };
  }

  async function startAgentRun(opts) {
    opts = opts || {};
    if (state.busy) return toast("A mission is already in flight.", "amber");

    const scenario = opts.scenario || null;
    const mode = opts.mode || (scenario ? "scenario" : "ai");
    const prompt = String(opts.prompt || $("#prompt").value || "").trim();
    if (!prompt) {
      $("#prompt").focus();
      return toast("Describe the mission first.", "amber");
    }
    const scope = opts.scope || currentScope();

    if (scenario) {
      $("#prompt").value = prompt;
      syncScopeChips(scope);
    }

    state.busy = true;
    state.mode = mode;
    state.compromised = (mode === "ai" && !!$("#compromised").checked) ||
      !!(scenario && window.SCENARIOS.attack.some((s) => s.id === scenario.id));

    resetMission(prompt, scope);
    setBusy(true);
    if (scenario) {
      $$(".scenario").forEach((b) => b.classList.toggle("running", b.dataset.id === scenario.id));
    }

    let task = null;
    let answer = "";
    let blocked = false;
    let observation = null;
    let planner = mode === "scenario" ? "scenario" : mode === "local" ? "local" : "ai";
    const history = [];

    try {
      const created = await apiPost("/api/tasks", { prompt, scope });
      task = created.task;
      state.task = task;
      renderMissionMeta(task);

      for (let stepNo = 1; stepNo <= MAX_STEPS; stepNo++) {
        setMissionStatus("PLANNING");
        setPhase("think");
        const think = addThinking(
          mode === "scenario"
            ? "Compromised planner is choosing its next move…"
            : planner === "ai"
              ? "Planner is reasoning over sanitized context — one proposal at a time…"
              : "Deterministic local planner is selecting the next step…");

        let plan = null;
        try {
          if (mode === "scenario") {
            await sleep(650);
            const scripted = scenario.steps[stepNo - 1];
            plan = scripted
              ? {
                done: false, tool: scripted.tool, args: scripted.args || {},
                data_sources: scripted.data_sources || [],
                thought: "Compromised planner proposes the next step toward the hidden instruction.",
                source: "scenario",
              }
              : { done: true, answer: scenario.finish || "Task complete.", source: "scenario" };
          } else if (planner === "local") {
            await sleep(480);
            plan = AI.localPlan(plannerContext(task, history, observation));
          } else {
            plan = await AI.plan(plannerContext(task, history, observation));
            const chosen = AI.MODELS.find((m) => m.id === AI.getModels().planner);
            updateAIStatus(true, chosen ? chosen.name.toUpperCase() : "MODEL");
          }
        } catch (err) {
          if (planner === "ai") {
            updateAIStatus(false);
            toast("Planner unreachable — switching to the deterministic local planner.", "amber");
            planner = "local";
            plan = AI.localPlan(plannerContext(task, history, observation));
          } else {
            throw err;
          }
        } finally {
          removeThinking(think);
        }

        if (!plan || plan.done) {
          answer = (plan && plan.answer) || (scenario && scenario.finish) || "Task complete.";
          break;
        }

        const proposal = {
          tool: plan.tool,
          args: plan.args || {},
          data_sources: plan.data_sources || [],
        };
        const entry = {
          i: state.steps.length, plan, proposal, d: null, exec: null, status: "proposed",
        };
        state.steps.push(entry);

        setMissionStatus("EVALUATING");
        setPhase("policy");
        let verifier = null;
        if (mode === "ai" && ["send_email", "share_file", "delete_file"].includes(plan.tool)) {
          try {
            verifier = await AI.verify({ prompt, proposal, observation });
          } catch (_) {
            verifier = null;
          }
        }

        let d;
        try {
          d = await apiPost("/api/tasks/" + task.id + "/evaluate", { proposal, verifier });
        } catch (err) {
          entry.error = err.message;
          renderStep(entry);
          answer = "Policy evaluation failed: " + err.message;
          blocked = true;
          setMissionStatus("ERROR", "denied");
          break;
        }
        entry.d = d;
        renderStep(entry);
        selectStep(entry.i);

        if (d.decision === "DENY") {
          entry.status = "denied";
          blocked = true;
          history.push({ tool: plan.tool, args: plan.args, decision: "DENY", executed: false, result: null });
          answer = "Authority engine denied " + plan.tool + ". " + d.reason;
          setMissionStatus("BLOCKED", "denied");
          break;
        }

        if (d.decision === "REQUIRE_APPROVAL") {
          setMissionStatus("AWAITING APPROVAL", "approval");
          setPhase("gate");
          const decided = await showApproval(d.approval, task);
          if (!decided.approved) {
            entry.status = "user_denied";
            badgeOn(entry, "USER DENIED", "failed");
            appendNote(entry, "Human approval was denied. The capability was never minted and nothing left the sandbox.", "bad");
            blocked = true;
            history.push({
              tool: plan.tool, args: plan.args, decision: "APPROVAL_DENIED",
              executed: false, result: null,
            });
            answer = "The human operator denied the " + plan.tool + " action. Nothing was executed.";
            setMissionStatus("BLOCKED", "denied");
            break;
          }
          d = Object.assign({}, d, {
            capability: decided.capability,
            approval: decided.approval || d.approval,
          });
          entry.d = d;
          setMissionStatus("EXECUTING");
          markStepApproved(entry);
        }

        setPhase("gate");
        const exec = await apiPost("/api/tasks/" + task.id + "/execute", {
          capability: d.capability ? d.capability.token : "",
          proposal,
        });
        entry.exec = exec;
        entry.status = exec.ok ? "executed" : "failed";
        attachExecution(entry, exec);
        history.push({
          tool: plan.tool, args: plan.args, decision: d.decision,
          executed: !!exec.ok, result: exec.result || null,
        });
        observation = exec.ok ? exec.result : null;

        setPhase("verify");
        if (!exec.ok) {
          blocked = true;
          answer = "The execution gateway rejected the action: " +
            (exec.error || (exec.verification && exec.verification.detail) || "unknown");
          setMissionStatus("BLOCKED", "denied");
          break;
        }
      }

      if (!answer) {
        answer = "Step budget reached (" + MAX_STEPS + " actions). The planner stopped without a final answer.";
      }
    } catch (err) {
      blocked = true;
      setMissionStatus("ERROR", "denied");
      answer = "Mission stopped: " + err.message;
      toast("Mission stopped: " + err.message, "bad");
    } finally {
      if (task) {
        if (answer) {
          try {
            await apiPost("/api/tasks/" + task.id + "/complete", { answer });
          } catch (_) { /* audit record is best-effort here */ }
        }
        try {
          const fresh = await apiGet("/api/tasks/" + task.id);
          state.task = fresh.task;
        } catch (_) { /* keep the local snapshot */ }
      }
      if (!blocked) setMissionStatus("COMPLETE", "done");
      setPhase(null);
      showFinal(answer, !blocked);
      state.busy = false;
      setBusy(false);
      if (scenario) $$(".scenario").forEach((b) => b.classList.remove("running"));
      await refreshTelemetry();
      if ($("#tab-audit") && $("#tab-audit").classList.contains("active")) refreshAudit();
      if (blocked && state.circuit && state.circuit.state === "FROZEN") {
        toast("Circuit breaker is FROZEN after repeated denials. Review the alerts, then reset to resume execution.", "bad");
      }
    }
  }

  function markStepApproved(entry) {
    badgeOn(entry, "APPROVED · BOUND", "allow");
    appendNote(entry, "Human approved this exact snapshot. A single-use capability was minted and bound to the args hash.", "ok");
  }

  function runAI() {
    return startAgentRun({ mode: "ai" });
  }

  function runLocal() {
    return startAgentRun({ mode: "local" });
  }

  function runScenario(id) {
    const all = (window.SCENARIOS.legit || []).concat(window.SCENARIOS.attack || []);
    const scenario = all.find((s) => s.id === id);
    if (!scenario) return toast("Unknown scenario: " + id, "bad");
    return startAgentRun({
      mode: "scenario",
      scenario,
      prompt: scenario.prompt,
      scope: scenario.scope,
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
