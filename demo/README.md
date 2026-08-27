# Hunt Engine demo

Local arena for exercising The Hunt Engine (Live Assets, Reveal Hidden Layers,
Cipher Clipboard, Redirect Log, hunt-base probes).

## Run

```bash
cd hunt-engine/demo
python server.py
```

Open:

- Arena stations: http://127.0.0.1:8765/
- **Practice Hunt (simulated):** http://127.0.0.1:8765/practice/

Load the extension via `about:debugging`, then use the sidebar on these pages.
Pin `http://127.0.0.1:8765` as hunt base when probing paste-style tokens.

## What’s here

| Path | Purpose |
|------|---------|
| `/` | Feature stations (Base64, hidden CSS, redirects, ciphers, iframe) |
| `/practice/` | **Neon Rook** multi-step practice hunt |
| `/r/start` | 3-hop HTTP 302 → `/final.html` |
| `/raw/{id}`, `/p/{id}`, `/paste/{id}`, `/{id}` | Paste hits + soft-404 misses |
| `/practice/{id}`, `/practice/raw/{id}`, … | Same templates under practice (HTML pages or paste) |
| `/robots.txt`, `/sitemap.xml` | For **Fetch robots.txt** / light sitemap UI |
| `/pin/{id}` | Local pin stub (not real Pinterest) |

Soft-404 responses intentionally return **HTTP 200** with “Not Found (#404)” /
“does not exist” body text so probes can classify misses.

---

## Neon Rook — developer solve path (spoilers)

Original fiction only. Do not treat these as answers to any live hunt.

1. **Trailhead** `/practice/`  
   - HTML comment Base64 `c2lnbmFsLmh0bWw=` → `signal.html`  
   - Canonical already points at `/practice/signal.html`  
   - Near-white CSS + zero-width letters also nudge “signal”  
   - Path-aware ID probe of `signal` (with Hunt Base pinned to host) also hits `/practice/signal`

2. **Signal** `/practice/signal.html`  
   - Image file `corridor-nr00k7px.svg` → token **`nr00k7px`**  
   - Atbash `Gsv glpvm rh mi00p7kc` → `The token is nr00k7px`  
   - Optional Base64 clipboard sample confirms “probe on hunt base”

3. **Hunt-base probe** (pin `http://127.0.0.1:8765`)  
   - Hit: `/raw/nr00k7px` or `/p/nr00k7px` or `/nr00k7px` (plain text drop)  
   - Miss practice: any other id (e.g. `zzzzMiss9`) → soft-404 HTML

4. **Paste body** points at geohash-lookalike path `/practice/9v6kph00.html`

5. **Grid page**  
   - Base64 `cGluLzg0NzI5MTA1NjM4NDAxMjM0NTY=` → `pin/8472910563840123456`  
   - Redirect chain `/practice/r/alpha` → … → `/practice/nest.html`

6. **Pin stub** `/pin/8472910563840123456` (local only)  
   - Atbash `kizxgrxv/ezfog.sgno` → `practice/vault.html`

7. **Vault** `/practice/vault.html`  
   - Completion: `FLAG{neon-rook-practice-complete}`

---

## Notes

- All Neon Rook tokens/IDs are invented for this demo.
- Do not copy live contest pastebins, pin ids, or level answers into this folder.
