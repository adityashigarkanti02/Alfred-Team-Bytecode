# OpenChat v1.4.0 — replicated request protocol

Package: `open.chat.gpt.aichat.bot.free.app` (modded "Premium" APK analyzed; orig dev: AceTools Team)
Base: `https://gptapi.rotech.dev/api/v5/` (smali `s70`, `g10`, `jq1`)

## Envelope — identical for EVERY endpoint (smali `g10:pswitch_9`, `gz2.a`, `j5.k/h`)
`POST {BASE}{endpoint}`, `Content-Type: application/x-www-form-urlencoded`, UA `okhttp/4.12.4`
```
pkg=open.chat.gpt.aichat.bot.free.app   # jq1.a: package name
version=1.4.0                           # jq1.a: versionName
modetype=1                              # jq1.a: hardcoded
data=<Base64-NO_WRAP(AES-128-CBC-PKCS5(json))>   # zi4.o
```
AES (`zi4.o` encrypt / `zi4.l` decrypt): `md5hex = MD5(sigHex)` (`lf45.w`),
`key = md5hex[0:16]`, `iv = md5hex[16:32]`, UTF-8 bytes.
`sigHex` = lowercase hex of APK signer cert DER (`zi4.w`: `PackageInfo.signatures → toCharsString`).
Mod-APK cert sha256 `aa786374…f87ea7` → md5 `81c54a1660d877e1c9addb772d6d6d84`
→ key `81c54a1660d877e1`, iv `c9addb772d6d6d84`.
**Server answers only to the ORIGINAL signature** (APKPure 1.3.8, cert sha256
`270df108…65a62eb` → md5 `8a678654d587204960f88b97a8896ec5`):
→ **working key `8a678654d5872049`, iv `60f88b97a8896ec5`** (verified live, prefilled in webapp).

Common JSON fields auto-added (`k44.v`): `gp_token`, `firebase_uid`, `sign = <millis><rand10000-99999>`.

## Endpoints (path → body fields → smali source)
| endpoint | fields (+common) | notes |
|---|---|---|
| `aq/chat` | `conversation_sign, msg_type:int(0=text,1=file), msg, [id:int], [language]` | MAIN chat, **SSE stream** (`zz3` flow). `conversation_sign = uuid_ts` (`ChatViewModel.D`: uuid + native-sep(likely `_`) + ts) |
| `chat/common_question` | `uuid, conversation_sign, timestamp, question, [id], [id_list], lang, model, length, style` | single-shot → enc JSON `{code, content, id}` (`s70.b/c/f`) |
| `chat/role_question` | role variant of above | (`s70.d`, `r70`) |
| `chat/question-dp` | `conversation_id, text` | DeepSeek (`eu0`+`cu0`) |
| `chat/web_analysis` | `web_url, conversation_id, text` | (`ko4`+`o60:6`); `chat/web_analysis_title` starts job |
| `chat/web_search` | web search | title/body pair like video |
| `chat/video_analysis` / `chat/video_analysis_title` | video url + text | (`zq1`) |
| `chat/images/analysis` → `chat/images/analysis_pull` | image + prompt (`kv1`: 4 strings) | (`h02`) |
| `chat/images/edit` → `chat/images/edit_pull` | (`s32`) |
| `chat/images/exchange_url` | | |
| `chat/email-assistant` | `conversation_sign, text, …` | (`ChatType$EmailAssistant`) |
| `chat/file/get_upload_url` → `chat/file/upload_server` → `chat/file/upload_server_pull` | `FileInfo{uri…}` | (`rh4`,`vh4`) |
| `file/analysis_sse` | SSE file analysis | (`g10`) |
| `text2img/gen_image` → `text2img/get_task_by_id` | `content_text, conversation_id, uuid, preset_id, is_plus, style_id, aspect_ratio` | (`sp1`+`rp1`, `zh2`) |
| model values | `auto, claude45, gemini3, gpt4o, gpt5, grok41` (`e6`); length `auto/detail/short` (`oj3`); style `academic/auto/creativity/humor/major/popular` (`pj3`) | defaults all `auto` (`f70`) |

## Side endpoints (different hosts, same FORM style assumed)
- `https://gpay.rotech.dev/api/v1/android/ack`, `/api/v1/subscription/pay`, `/api/v4/user/subscription/info` (billing)
- `https://fcm-chatgpt-api.rotech.dev/fcmbull/closemsg|delaymsg` (push)
- terms/privacy: `https://chatgpt.rotech.dev/{terms,privacypolicy}.html?pkg=…`
- mod-added (ignore): `https://pastebin.com/raw/SgKuNqew` (modder lock → t.me/modderme), `https://update.9mod.com/`, `https://liteapks.com/app.html`

## Live-test result (verified working with original key)
- `chat/common_question` → `{"code":200,"data":{"code":0,"content":"Hi there!","id":0,…}}`
- `aq/chat` → SSE `event: message` chunks, each `data:<b64 AES {"code":200,"data":"{\"id\":0,\"block_name\":\"…\",\"content\":\"…\",\"is_last\":\"no\"}"}>`, closed by `event: end` with `duration_ms`. Concatenate `content` fields.
- With the mod-APK key the server returns `event: error` with an undecryptable blob.
`uuid` = random v4 persisted (`oi4`: `ps_uuid`); `conversation_sign` = `{uuid}_{ts}` (sep base64 `Xw==` = `_`).

## Webapp (`openchat-web/`)
- `server.py` — stdlib-only static server + `POST /relay {url, form}` CORS relay + `POST /md5` (hash helper). Run: `python3 server.py` → http://127.0.0.1:8901
- `index.html` + `app.js` — chat UI, endpoint picker, model/length/style, key fields + APK key extractor, raw request/response inspector, SSE renderer with per-chunk AES-decrypt attempt.
