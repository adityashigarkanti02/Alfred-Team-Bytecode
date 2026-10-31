# OpenChat — Full Reverse-Engineering Documentation

How the OpenChat Android app talks to its server, and how `openchat-web/` replicates it.
Target: **OpenChat v1.4.0 (Premium mod)**, package `open.chat.gpt.aichat.bot.free.app`.

---

## 1. Target intel

| item | value |
|---|---|
| Package | `open.chat.gpt.aichat.bot.free.app` |
| Version | 1.4.0 (versionCode 58), targetSdk 36, minSdk 29 |
| Developer (original) | AceTools Team (Play Store; mod re-signed by `CN=Foxmoddz`) |
| App type | Native Kotlin shell + WebView chat UI + OkHttp network layer (NOT Flutter: `libflutter.so` present but chat/AI traffic is native Kotlin) |
| API base | `https://gptapi.rotech.dev/api/v5/` |
| Companion hosts | `gpay.rotech.dev` (billing), `fcm-chatgpt-api.rotech.dev` (push), `chatgpt.rotech.dev` (terms/privacy) |

## 2. How it was decompiled

1. `aapt dump badging` → package name, version, permissions, entry activity (`page.splash.LauncherActivity`).
2. `apktool d` → `AndroidManifest.xml`, resources, and smali (`smali_classes2/3/4`).
3. `strings classes*.dex` → URL harvest. Interesting hosts filtered out of ad/analytics noise:
   `gptapi.rotech.dev/api/v5/`, `gpay.rotech.dev`, `fcm-chatgpt-api.rotech.dev`, `pastebin.com/raw/SgKuNqew` (modder lock → t.me/modderme, ignore), `update.9mod.com`, `liteapks.com` (mod spam, ignore).
4. Traced network layer in smali: `j5.k/h` (generic POST dispatcher) → `g10:pswitch_9` (form builder) → `gz2.a` (OkHttp `FormBody` POST) → `vd2.onResponse` → `zi4.l` (decrypt) → per-endpoint parsers (`s70.f`, …).
5. All endpoint paths + JSON keys recovered from builder classes (`s70`, `cu0`, `o60`, `rp1`, `p70`, `r70`, `kv1`, …) and delegate callers (`ChatViewModel`, `ChatActivity`, `*DelegateImpl`).

## 3. The request protocol (identical for every endpoint)

### 3.1 Envelope

```http
POST https://gptapi.rotech.dev/api/v5/{endpoint}
Content-Type: application/x-www-form-urlencoded
User-Agent: okhttp/4.12.4

pkg=open.chat.gpt.aichat.bot.free.app   # jq1.a → Context.getPackageName()
version=1.4.0                           # jq1.a → versionName
modetype=1                              # jq1.a → hardcoded "1"
data={AES-128-CBC, Base64 NO_WRAP, of JSON body}
```

### 3.2 Encryption (`zi4.o` encrypt / `zi4.l` decrypt, `lf45.w` = MD5, `zi4.w` = cert)

```
sigHex  = lowercase hex of APK signer certificate DER
          (PackageInfo.signatures[i].toCharsString(), last entry wins)
md5hex  = MD5(sigHex)                      # 32 hex chars
key     = md5hex[0:16]   (UTF-8 bytes)     # AES-128 key
iv      = md5hex[16:32]  (UTF-8 bytes)     # AES-CBC IV
data    = Base64(AES_CBC_PKCS5Padding(json_utf8))   # Android Base64 flag 2 = NO_WRAP
```

Response bodies are the same scheme in reverse (whole body is one Base64 blob).

### 3.3 Signing keys (both derived by parsing the APK Signing Block)

| APK | cert sha256 | MD5(sigHex) | key | iv | server accepts? |
|---|---|---|---|---|---|
| Premium mod (Foxmoddz) | `aa786374…f87ea7` | `81c54a16…6d6d84` | `81c54a1660d877e1` | `c9addb772d6d6d84` | requests: yes (HTTP 200) but payloads undecryptable (`event: error`) |
| Original 1.3.8 (APKPure) | `270df108…65a62eb` | `8a678654…896ec5` | `8a678654d5872049` | `60f88b97a8896ec5` | **yes — full clear answers (webapp default)** |

### 3.4 Auto-added JSON fields (`k44.v`, present in every body)

```json
{ "gp_token": "", "firebase_uid": "", "sign": "<currentMillis><5 random digits>" }
```
(`gp_token`/`firebase_uid` are device tokens; empty strings are accepted.)

### 3.5 Identity fields

- `uuid` — random v4 persisted as `ps_uuid` (`oi4.C`). Any fresh UUID works.
- `conversation_sign` — `{uuid}_{timestampMillis}` (`ChatViewModel.D`; separator byte is `_`, base64 `Xw==` in smali).
- `timestamp` — current millis. `language`/`lang` — locale (`en`, `zh_CN`, …; `s70.e`).

## 4. Endpoint reference

### 4.1 `aq/chat` — main chat, SSE stream (smali `g10` aq/chat builder, `zz3`/`a04` flow)

Request JSON: `conversation_sign`, `msg_type` int (`0` = text, `1` = file attached), `msg`, optional `id` int (history answer id), optional `language`, + §3.4.

Response: `text/event-stream`:
```
event: message
data: <b64 AES {"code":200,"data":"{\"id\":0,\"block_name\":\"…\",\"content\":\"…\",\"is_last\":\"no\"}"}>
... (one event per delta; concatenate content) ...
event: end
data: <b64 AES {"code":200,"data":{"duration_ms":2560,…}}>
```

### 4.2 `chat/common_question` — single-shot chat (`s70.b/c`, `p70`, `l70`, `n70`→`s70.f`)

Request JSON: `uuid, conversation_sign, timestamp, question, [id], [id_list], lang, model, length, style` + §3.4.
Response (decrypted): `{"code":200,"data":{"code":0,"content":"…","id":0,…}}` → display `data.content`.

Model IDs (`e6`, defaults all `auto` in `f70`):
model: `auto, gpt4o, gpt5, claude45, gemini3, grok41` · length (`oj3`): `auto, detail, short` · style (`pj3`): `academic, auto, creativity, humor, major, popular`.

### 4.3 `chat/question-dp` — DeepSeek R1 (`eu0` + `cu0` case 0, `DeepSeekR1DelegateImpl`)

Request JSON: **`question`, `conversation_sign`** + §3.4. (Note: despite neighboring code, fields are NOT `conversation_id`/`text` — `cu0` switch case 0 maps to `question` + `conversation_sign`.) Response shape = §4.2.

### 4.4 `chat/role_question` — role characters (`s70.d`, `r70`)

Same family as §4.2 plus role descriptors (role id/prompt fields); list of roles ships in `assets/ec/role/{lang}`.

### 4.5 Media / tool endpoints (same envelope; bodies from builders)

| endpoint(s) | body highlights | smali |
|---|---|---|
| `chat/web_analysis` (+`_title`) | `web_url, conversation_id, text` | `ko4`+`o60:6` |
| `chat/web_search` | web query + conversation | title/body pair pattern |
| `chat/video_analysis` (+`_title`) | video url + text | `zq1` |
| `chat/images/analysis` → `chat/images/analysis_pull` | 4-string image job (`kv1`) | `h02` |
| `chat/images/edit` → `chat/images/edit_pull` | edit job | `s32` |
| `chat/images/exchange_url` | image URL exchange | — |
| `chat/email-assistant` | `conversation_sign, text, …` | `ChatType$EmailAssistant` |
| `chat/file/get_upload_url` → `chat/file/upload_server` → `chat/file/upload_server_pull` | `FileInfo{uri…}` staged upload | `rh4`, `vh4` |
| `file/analysis_sse` | SSE file analysis | `g10` |
| `text2img/gen_image` → `text2img/get_task_by_id` | `content_text, conversation_id, uuid, preset_id, is_plus, style_id, aspect_ratio` | `sp1`+`rp1`, `zh2` |

### 4.6 Non-AI hosts

Billing: `https://gpay.rotech.dev/api/v1/android/ack`, `/api/v1/subscription/pay`, `/api/v4/user/subscription/info` · Push: `https://fcm-chatgpt-api.rotech.dev/fcmbull/closemsg|delaymsg` · Legal: `https://chatgpt.rotech.dev/{terms,privacypolicy}.html?pkg=…`.

## 5. Live verification (original key)

- `chat/common_question` `{"question":"Hello…"}` → `{"code":200,"data":{"code":0,"content":"Hi there!","id":0,…}}` ✔
- `aq/chat` `{"msg":"Reply with exactly: HI THERE"}` → `event: message` ×5 + `event: end`, all chunks decrypt to `content` deltas ✔
- `chat/question-dp` `{"question":"Say hi…"}` → `{"code":200,"data":{"code":0,"content":"Hi there! 👋",…}}` ✔
- Same requests with mod key → HTTP 200 but `event: error` / undecryptable blobs (server keys off mod signature) ✔ (explains the old "decrypt failed" message)

## 6. The webapp (`openchat-web/`) — how it works

```
browser  ──POST /relay {url, form}──▶  server.py  ──POST form (okhttp UA)──▶  gptapi.rotech.dev
browser  ◀── {status, body} ──  server.py  ◀── raw (encrypted/SSE) ──  server
browser: AES + JSON + SSE parsing in-page (WebCrypto AES-CBC, SubtleCrypto)
```

### Files

- **`server.py`** (stdlib only, no pip deps). Serves the frontend on `http://127.0.0.1:8901`, relays `POST /relay` (forwards form with `User-Agent: okhttp/4.12.4`, returns `{status, body}` verbatim so SSE streams pass through), and `POST /md5` (hash helper for APK key derivation). Run: `python3 server.py` (env `PORT` optional).
- **`index.html`** — mobile-first chat UI: header + model `<select>`, message column (`.me`/`.ai` bubbles), sticky bottom input bar with safe-area padding, `100dvh` layout, ≥700px widening. No settings UI; working config is hardcoded.
- **`app.js`** — the replication core:
  - `aes("enc"/"dec", …)` — WebCrypto AES-CBC with hardcoded working `KEY`/`IV`, Base64 NO_WRAP compatible.
  - `common()` — injects §3.4 fields; `UUID` — per-load `ps_uuid` equivalent.
  - `sendSSE()` — builds §4.1 body, parses SSE, AES-decrypts each `data:`, JSON-unwraps outer+inner, appends `content`, prints `duration_ms` on `end`.
  - `sendModel()` — `deepseek` → §4.3 (`question`+`conversation_sign`); other models → §4.2 with `model` set (`length`/`style` fixed `auto`).
  - Model routing: `auto` → streaming `aq/chat`; named model → single-shot endpoint.
- **`PROTO.md`** — condensed protocol cheat-sheet. **`DOCUMENTATION.md`** (this file) — full findings.

### Request flow example (Auto → `a
...[truncated 668 chars]
## 8. Input length limits
None enforced. No `maxLength`/`LengthFilter` on the chat input in layouts or smali; a live 15,000-char `common_question` was accepted with HTTP 200 and a normal answer.

## 9. Streaming output
`Auto` mode streams token-by-token: `POST /relay-stream` pipes the server's SSE bytes
through as they arrive (chunked reads, verified: first bytes in ~5s, multiple progressive
reads), and the page decrypts + appends each `event: message` payload incrementally via
`ReadableStream`. Named models use single-shot `chat/common_question` (one reply, no stream).

## 10. Conversational context (verified live)
One conversation = one `conversation_sign` (`{uuid}_{startTs}`, fixed for all turns —
was a bug: webapp v1 minted a fresh sign per message). Follow-up turns (2nd+)
add `"id": 0`. Verified: 3-turn memory works on `aq/chat` and `chat/common_question`
(e.g. remembers planted words across turns; occasional server-side amnesia on single
turns exists upstream). `＋` button resets sign/counter. Streaming renders only
`block_name == "final_answer"` chunks (hides `subject`/`solution_steps` reasoning blocks).

## 11. Model availability (probed live)
`common_question.model` accepts exactly: `auto, gpt4o, gpt5, claude45, gemini3, grok41`
(all → outer code 200). Everything else tried (`gpt4o-mini, gpt5-nano, gpt4, gpt-4o,
claude35, claude3, gemini15, gemini2, llama, mistral, qwen, gpt35, o1, gpt4-turbo,
deepseek, deepseek-r1, grok4`) → `code 10000 "param error"`. DeepSeek R1 lives only
behind the separate `chat/question-dp` endpoint. Display names in-app: GPT-4o(-mini),
GPT-5(-nano), Claude 4.5, Gemini 3, Grok 4.1, DeepSeek R1 — minis/nanos share the base id.

## 12. Image Q&A + file upload (verified live end-to-end)
Pipeline (mirrors `rh4`/`vh4`/`h02` + `ImageAnalysisDelegateImpl`):
1. `chat/file/get_upload_url` `{filenames:[name]}` → `data.url_list[{url, s3_url}]`
   (`url` = presigned S3 PUT target, `s3_url` = public CDN URL used as `img_url`).
2. `PUT` bytes → `url` with `Content-Type` + `x-amz-acl: public-read` (plain S3, no app crypto).
3. `chat/images/analysis` `{conversation_id, type:"1", text, img_url:s3_url}` → `{status:"processing"}`.
4. Poll `chat/images/analysis_pull` `{conversation_id, type:"1"}` every ~5s → `{content}` (test: red PNG correctly described).
`type` default is base64 `MQ==`→`"1"` (`ImageAnalysisDelegateImpl.B`); multi-image `img_url`s join with `|` (`fA==`). Webapp: 📎 button → upload via `/relay-raw` → auto analysis Q&A with thumbnail.

## 13. Image support vs models
Vision is NOT per-model: `images/analysis` takes no model field — one fixed vision
backend, with numeric task presets in `type` (`ChatType$PremiumFeature$ImageTools.*`):
1=ImageAnalysis/Others, 2=CodeParsing, 3=TextExtraction, 4=ImageQA, 5=InteriorDesign,
6=HealthyDiet, 7=ImageToCode (base64 ids `MQ==`…`Nw==`, verified 1–3 accepted live).
Webapp sends type 1 (general analysis/Q&A).

## 14. Possessed Butler arena (built on this relay)
`arena/` is a playable game that uses the same protocol and relay, with no extra keys:
- **Butler** call → `chat/common_question` (default `gemini3`): base Victorian-butler
  directive + Blue ward + Red curse, asks for one in-character action + line.
- **Arbiter** call → `chat/common_question` (default `claude45`): same three inputs plus
  the butler's reply, returns strict JSON `{verdict,title,butler_action,reason}`.
  Points are assigned locally from the verdict (`attack`/`defense`/`parry`/`neutral`).
- If either call fails, `arena/ai.js` uses a local heuristic and labels the verdict
  "house rules" instead of silently faking an AI ruling.
- Run with the same server: `python3 server.py` → `http://127.0.0.1:8901/arena/`.
  See `arena/README.md` for controls, scoring and the fatality mechanic.
