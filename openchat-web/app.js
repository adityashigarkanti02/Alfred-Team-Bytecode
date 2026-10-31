/* OpenChat replicator — working config hardcoded (see PROTO.md).
   auto → aq/chat (SSE stream); picked model → chat/common_question with model set.
   Envelope: POST form {pkg, version, modetype:"1", data:AES_CBC_B64(json)},
   key=MD5(orig cert hex)[0:16], iv=[16:32]; JSON adds gp_token/firebase_uid/sign. */
const BASE = "https://gptapi.rotech.dev/api/v5/";
const PKG = "open.chat.gpt.aichat.bot.free.app", VER = "1.4.0";
const KEY = "8a678654d5872049", IV = "60f88b97a8896ec5";
const $ = id => document.getElementById(id);
const log = $("log"), te = new TextEncoder(), td = new TextDecoder();
const UUID = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
let SIGN = UUID + "_" + Date.now(), TURNS = 0; // one conversation: same sign every turn (app: ChatViewModel.D(F()))
const turnId = () => (TURNS === 0 ? {} : { id: 0 }); // follow-ups chain with id:0 (verified live)

function say(txt, cls) { const d = document.createElement("div"); d.className = "msg " + cls; d.textContent = txt; log.appendChild(d); log.scrollTop = 1e9; return d; }
async function aes(what, b64, k = KEY, iv = IV) {
  const key = await crypto.subtle.importKey("raw", te.encode(k), "AES-CBC", false, ["encrypt", "decrypt"]);
  const ivb = te.encode(iv).slice(0, 16);
  if (what === "enc") {
    const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivb }, key, te.encode(b64));
    const b = new Uint8Array(ct); let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  const raw = atob(b64.replace(/\s+/g, "")), b = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) b[i] = raw.charCodeAt(i);
  return td.decode(await crypto.subtle.decrypt({ name: "AES-CBC", iv: ivb }, key, b));
}
const relay = (url, form) => fetch("/relay", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, form }) }).then(r => r.json());
const sign = () => String(Date.now()) + String(10000 + Math.floor(Math.random() * 90000));
const common = o => (o.gp_token = "", o.firebase_uid = "", o.sign = sign(), o);

async function handleChunk(chunk, box) {
  const em = (chunk.match(/event:\s*(\w+)/) || [])[1], dm = (chunk.match(/data:\s*(\S+)/) || [])[1];
  if (!dm) return;
  try {
    const o = JSON.parse(await aes("dec", dm)), inner = typeof o.data === "string" ? JSON.parse(o.data) : o.data;
    if (box.dataset.init) { box.textContent = ""; delete box.dataset.init; }
    if (em === "end") box.textContent += `\n— done (${inner.duration_ms ?? "?"} ms)`;
    else if (inner && inner.block_name === "final_answer" && inner.content != null) box.textContent += inner.content;
  } catch { /* skip undecodable chunk */ }
  log.scrollTop = 1e9;
}
async function sendSSE(q, box) {
  const body = common({ conversation_sign: SIGN, msg_type: 0, msg: q, language: "en", ...turnId() });
  const form = { pkg: PKG, version: VER, modetype: "1", data: await aes("enc", JSON.stringify(body)) };
  box.dataset.init = "1";
  const r = await fetch("/relay-stream", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: BASE + "aq/chat", form }) });
  const reader = r.body.getReader(), dec8 = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    buf += dec8.decode(value || new Uint8Array(), { stream: !done });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) { const c = buf.slice(0, i); buf = buf.slice(i + 2); await handleChunk(c, box); }
    if (done) { if (buf.trim()) await handleChunk(buf, box); break; }
  }
  if (!box.textContent.trim() || box.textContent.trim() === "…") box.textContent = "(empty reply)";
}
async function sendModel(q, model, box) {
  const ts = Date.now();
  const isDP = model === "deepseek"; // chat/question-dp takes {question, conversation_sign} (cu0:0)
  const body = isDP
    ? common({ question: q, conversation_sign: SIGN, ...turnId() })
    : common({ uuid: UUID, conversation_sign: SIGN, timestamp: ts, question: q, lang: "en", model, length: "auto", style: "auto", ...turnId() });
  const form = { pkg: PKG, version: VER, modetype: "1", data: await aes("enc", JSON.stringify(body)) };
  const { body: raw } = await relay(BASE + (isDP ? "chat/question-dp" : "chat/common_question"), form);
  const j = JSON.parse(await aes("dec", raw.trim())), d = j.data ?? j;
  box.textContent = (d && (d.content ?? d.msg)) ?? "(empty reply)";
}

$("send").onclick = async () => {
  const q = $("q").value.trim(); if ((!q && !ATTACH) || $("send").disabled) return;
  if (ATTACH) { const f = ATTACH; ATTACH = null; $("attach").classList.remove("on"); await sendImage(f, q || "Describe this image in detail."); $("q").value = ""; return; }
  say(q, "me"); $("q").value = ""; $("send").disabled = true;
  const box = say("…", "ai typing");
  try {
    const m = $("model").value;
    if (m === "auto") await sendSSE(q, box);
    else await sendModel(q, m, box);
  } catch (e) { box.textContent = "Error: " + e; }
  box.classList.remove("typing"); $("send").disabled = false; $("q").focus();
  TURNS++;
};
$("newchat").onclick = () => { SIGN = UUID + "_" + Date.now(); TURNS = 0; ATTACH = null; $("attach").classList.remove("on"); log.innerHTML = ""; say("New chat started. What's on your mind?", "ai"); };
/* Docs overlay: tiny markdown renderer, loads DOCUMENTATION.md live */
function mdrender(src) {
  const esc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = s => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = []; let inpre = false, intable = false;
  for (let line of src.split("\n")) {
    if (/^```/.test(line)) { out.push(inpre ? "</pre>" : "<pre>"); inpre = !inpre; if (intable) { out.push("</table>"); intable = false; } continue; }
    if (inpre) { out.push(esc(line)); continue; }
    if (/^\|.+\|$/.test(line)) {
      if (!intable) { out.push("<table>"); intable = true; }
      if (/^\|[\s:-|]+\|$/.test(line)) continue;
      out.push("<tr>" + line.slice(1, -1).split("|").map(c => `<td>${inline(c.trim())}</td>`).join("") + "</tr>");
      continue;
    }
    if (intable) { out.push("</table>"); intable = false; }
    let m;
    if (m = line.match(/^(#{1,3})\s+(.*)/)) out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`);
    else if (/^---+$/.test(line)) out.push("<hr>");
    else if (m = line.match(/^[-*]\s+(.*)/)) out.push(`• ${inline(m[1])}<br>`);
    else if (m = line.match(/^(\d+)\.\s+(.*)/)) out.push(`${m[1]}. ${inline(m[2])}<br>`);
    else if (line.trim() === "") out.push("");
    else out.push(inline(line) + "<br>");
  }
  if (intable) out.push("</table>");
  if (inpre) out.push("</pre>");
  return out.join("\n");
}
$("docs").onclick = async () => {
  $("docwrap").style.display = "block";
  try { $("docbody").innerHTML = mdrender(await (await fetch("DOCUMENTATION.md")).text()); }
  catch (e) { $("docbody").textContent = "Could not load docs: " + e; }
};
$("docclose").onclick = () => $("docwrap").style.display = "none";
$("q").addEventListener("keydown", e => { if (e.key === "Enter") $("send").click(); });
/* Image Q&A: get_upload_url → PUT to S3 → images/analysis → poll analysis_pull (verified live) */
let ATTACH = null;
$("attach").onclick = () => $("file").click();
$("file").onchange = e => { ATTACH = e.target.files[0] || null; $("attach").classList.toggle("on", !!ATTACH); if (ATTACH) say("📎 " + ATTACH.name + " attached — type a question (or send for a description).", "sys"); e.target.value = ""; };
const b64 = buf => { const b = new Uint8Array(buf); let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
async function sendImage(file, q) {
  say(q, "me"); $("send").disabled = true;
  const box = say("uploading…", "ai typing");
  try {
    const up = await relay(BASE + "chat/file/get_upload_url", { pkg: PKG, version: VER, modetype: "1", data: await aes("enc", JSON.stringify(common({ filenames: [file.name] }))) });
    const item = JSON.parse(await aes("dec", up.body.trim())).data.url_list[0];
    const put = await (await fetch("/relay-raw", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: item.url, method: "PUT", headers: { "Content-Type": file.type || "image/jpeg", "x-amz-acl": "public-read" }, bodyB64: b64(await file.arrayBuffer()) }) })).json();
    if (put.status !== 200) throw "upload failed: HTTP " + put.status + " " + put.body.slice(0, 120);
    box.textContent = "analyzing…";
    const sub = await relay(BASE + "chat/images/analysis", { pkg: PKG, version: VER, modetype: "1", data: await aes("enc", JSON.stringify(common({ conversation_sign: SIGN, type: "1", text: q, img_url: item.s3_url }))) });
    JSON.parse(await aes("dec", sub.body.trim())); // {status:processing}
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const p = await relay(BASE + "chat/images/analysis_pull", { pkg: PKG, version: VER, modetype: "1", data: await aes("enc", JSON.stringify(common({ conversation_sign: SIGN, type: "1" }))) });
      const d = JSON.parse(await aes("dec", p.body.trim())).data || {};
      if (d.content) { box.innerHTML = ""; if (URL.createObjectURL) { const im = document.createElement("img"); im.src = item.s3_url; box.appendChild(im); } const t = document.createElement("div"); t.textContent = d.content; box.appendChild(t); break; }
      box.textContent = "analyzing… (" + ((i + 1) * 5) + "s)";
      if (i === 11) box.textContent = "(still processing — try again in a bit)";
    }
  } catch (e) { box.textContent = "Error: " + e; }
  box.classList.remove("typing"); $("send").disabled = false; TURNS++;
}
say("Hi! Pick a model up top (or Auto) and ask away.", "ai");
