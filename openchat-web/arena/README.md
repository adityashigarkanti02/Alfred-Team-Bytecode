# Possessed Butler — Hack-O-Lantern Arena

A playable build of the PRD: a prompt-injection duel between a **Red Witch** (attacker)
and a **Blue Paladin** (defender), with an AI butler in the middle. The butler is a real
LLM; a second LLM (the Arbiter) rules on what happened.

No API keys. It uses the OpenChat relay already in `openchat-web/` (`gptapi.rotech.dev`,
see `../PROTO.md`), so the free models in the folder power the whole game.

## Run

```bash
cd openchat-web
python3 server.py
# open http://127.0.0.1:8901/arena/
```

`server.py` must be running: the browser calls its `/relay` endpoint to reach the AI.
Use `127.0.0.1` or `localhost` (the AES envelope needs `crypto.subtle`, which browsers
only expose in a secure context). Opening `index.html` from `file://` will not work.

If the relay or the upstream API is unreachable, the game falls back to **house rules**:
a local heuristic writes the butler's line and scores the round, and the verdict card
says so.

## Play

| Mode | What it is |
|---|---|
| **Quick Play** | You vs. the AI Paladin (or play the Paladin vs. the AI Witch). Best of 5. |
| **Local Duel** | Two players on one keyboard, alternating attack and defense phases. |
| **Training Room** | A dummy butler with no ward. Endless attempts, local scoring. |

Each round: Red writes a **curse** (30s), Blue writes a **ward** (30s), the butler
responds, then the Arbiter rules. `Enter` casts, `Shift+Enter` adds a line.

| Ruling | Points |
|---|---|
| Curse lands (`attack`) | Red +10 |
| Ward holds (`defense`) | Blue +10 |
| Parry — ward turns the curse back on Red | Blue +15 |
| Butler ignores both and serves tea | Both +2 |

Reach **50 points before round 5** to unlock a **Fatality**: the winning side writes one
final curse/ward that deforms the loser's interface for the rest of the match (red tint +
mirrored blue log, or an icy blue tint + spaced-out red text). Ties after round 5 go to
sudden death.

## How the AI is wired

All of it is in `ai.js`, using the same envelope as the OpenChat webapp:

```
form = { pkg, version, modetype:"1", data: AES-128-CBC(base64(json)) }
POST /relay  ->  POST https://gptapi.rotech.dev/api/v5/chat/common_question
```

Per round there are two calls:

1. **Butler** (`gemini3` by default) — gets the base directive, the Blue ward, and the Red
   curse, and must reply in character with one action + one line. The prompt explicitly
   makes the butler susceptible to convincing injections, which is what makes attacks
   possible. (Claude 4.5 is the most dramatic alternative; GPT-4o tends to resist too
   hard, which makes Red's life unfair.)
2. **Arbiter** (`claude45` by default) — gets the same three inputs plus the butler's
   actual response, and returns strict JSON:
   `{verdict, title, butler_action, reason}`. Points are computed locally from the
   verdict, not trusted from the model.

Both models are selectable on the title screen. The prompt pipeline follows PRD §6.2
(base prompt → ward appended → curse as the guest message → separate arbiter check).

## Files

| File | Purpose |
|---|---|
| `index.html` | Title screen, HUD, verdict/fatality/game-over modals |
| `arena.css` | Gothic arcade skin, responsive layout, fatality deformations |
| `arena.js` | Round state machine, scoring, bot pools, timer, UI |
| `ai.js` | OpenChat envelope, butler/arbiter prompts, JSON parsing, house-rules fallback |
| `sprites.js` | Canvas scene: mansion, moon window, 16×16 pixel sprites, particles, lightning, rings |
| `audio.js` | WebAudio chiptune organ, SFX, speech-synthesis announcer |

Sprites are drawn from 16×16 character grids in `sprites.js` (no image assets), baked to
offscreen canvases and animated with bobs, glows and particle effects.

## Scope

Built: the full core loop, Quick Play vs. bots (either side), Local Duel, Training Room,
the point system, best-of-five + sudden death, the Fatality UI deformation, the AI
butler/arbiter pipeline, and the canvas arena with sprites, VFX and chiptune audio.

Not built: 3v3 team chat, the Coven of Hospitals campaign, spectator betting, and
cosmetic unlocks. Those are listed in the PRD as extra modes/future scope.

## Notes

- The relay is a reverse-engineered free service; it can rate-limit or go down. The
  fallback keeps the game playable, and the verdict card is honest about it.
- Content is kept PG-13: plates are thrown, tea is spilled, nobody is actually hurt.
- Sound starts on the first click (browser autoplay rules). Toggle it on the title screen.
- Add `?debug=1` to expose `window.__pb` (state, HUD helpers) for poking at the game.
