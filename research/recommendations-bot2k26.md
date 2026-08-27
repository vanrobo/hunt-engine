# Hunt Engine recommendations — BOT 2K26 cryptic hunt

Source: [leads index gist](https://gist.github.com/whirlxd/e9f8bbe013ccdee008dbc6a17a9c3a5e) + linked level writeups (saved under this folder).

## What the hunt doc covers

BOT 2K26 (“Cryptic 26”) is a multi-level cryptic OSINT hunt on `cryptic.paradigmclub.dev` with Discord bot **Venandi Dux**. Each level is a research rabbit-hole: media clues → associative search → **site backlink** (`/slug`) → more ciphers / pastebins / social IDs → answer keyword.

Recurring mechanics:

| Mechanic | Where it showed up |
|----------|-------------------|
| Site path backlinks (`/miramax`, `/giraffe`, …) | Almost every level |
| Pastebin (often passworded) + tags as clues | L6, L9, L10, L11 |
| Image / GIF stego (`strings`, Notepad, histogram EQ, steghide) | L3, L4, L5, L7, L10.5, L11 |
| Classic + niche ciphers (Atbash, Caesar, Homophonic, Patristocrat, Gold Bug, HODOR, Morse/BeepCrypt) | L2, L5, L6, L7, L8, L9, L10 |
| Audio (SSTV, Morse, song ID, Geiger) | L1, L2, L9, L10.5 |
| DNS TXT | L4 |
| Geohash | L5, L10 |
| Social / media IDs (YT, IG highlight, Spotify, Letterboxd, Scratch, Genius annotation, Discord snowflake) | L2, L6, L8, L9, L10, L10.5, L11 |
| File hosts (`file.garden`, `catbox.moe`, Drive folders) | L1, L3, L4, L10.5 |
| Zero-width / Unicode stego in comments | L11 |
| External paste sites (`controlc`, `rentry`) | L10 |

---

## What Hunt Engine already covers well

| Feature | Fit to this hunt |
|---------|------------------|
| **Pin hunt base** + path probe | Directly matches paradigmclub-style `/slug` backlinks |
| **Backlink Identifier** (Pastebin, TinyURL, Drive/Docs, YouTube, Discord *invite*, Reddit, Imgur, …) | Core rex.wf-style workflow; L6 Pastebin / L11 YT IDs work today |
| **Live Assets** (comments, Base64, ZW, meta, links, candidates) | L3 hidden HTML (`21 wtc ki maa`), L11 ZW stego, L2 Base64 IG path |
| **Reveal Hidden Layers** | Same class of black-on-black / `[hidden]` pages |
| **Cipher Clipboard** (Base64, hex, binary, ROT13, URL, reverse, **Atbash**) | L5 Atbash→geohash; Base64 paths; ROT13-ish Caesar starter in L6 is close |
| **Redirect Log** | Less central in these writeups, still useful for shortener / hop pages |
| **Image reverse** (Lens / Yandex / TinEye) + probe filename | L3 Thin Blue Line, L5 Bridge of Life painting ID |

---

## Prioritized additions

Ranked by how often they unblock *this* hunt style vs implementation cost.

### P0 — High leverage, moderate scope

1. **Probe host pack: hunt-native pastes & media IDs**  
   - **Why:** L6 Pastebin + ControlC (L10), rentry (L10), Scratch project `403366692` (L9), Genius annotation numbers (L6), Spotify playlist IDs (L9), Letterboxd (L10.5), Instagram highlight /s/ paths (L2), Discord *message* snowflakes (L11 — not invites).  
   - **Scope:** Extend `BACKLINK_TEMPLATES` + Live Assets classifiers; snowflake → open in Discord (or deep-link helper); IG highlight builder from Base64/`/s/` tokens. Skip-confirm where login-walled.

2. **DNS Inspector (TXT / A / MX panel)**  
   - **Why:** L4 answer path is `txt @ medhanshk.com` → TXT = ISBN. Nothing in Hunt Engine does DNS today.  
   - **Scope:** Sidebar: domain input → DoH (e.g. Cloudflare/Google) → list TXT first; one-click “probe selection as domain”.

3. **Geohash + coordinate resolver**  
   - **Why:** L5 `gcf23vys4qp` → Donegal; L10 `9zz1y8` → La Crosse. Cipher → geohash is a repeated hop.  
   - **Scope:** Local decode of geohash → lat/lon + OpenStreetMap / Google Maps link; accept pasted `lat, lon` too.

4. **Media Asset Inspector (filenames, alt, title, `<audio>`/`<video>` src)**  
   - **Why:** L4 `oneword.mp4` + “helicopter”; L3 audio filename “words on the grave”; L4 GIF alt → Pastebin; L10.5 file.garden `10.png`/`10.jpg`.  
   - **Scope:** Content-script harvest of media metadata into Live Assets (or sibling panel); right-click “Send media meta to Hunt Engine”.

### P1 — Strong value, larger or external tooling

5. **Image strings / trailing-payload viewer**  
   - **Why:** L5 “open PNG in Notepad” → `txu23ebh4jk`; L4 GIF `strings`; L7 histogram EQ on Frida image.  
   - **Scope:** Fetch image → show printable trailing strings + hex peek; deep links to 29a.ch / similar for EQ. Not full steghide (keep external).

6. **Cipher Clipboard expansions + “open in solver”**  
   - **Why:** L6 Caesar (`vflhqwrorjBH` → ScientologYE); L8 Homophonic; L7 Patristocrat→quipqiup; L10 Gold Bug; L2 HODOR; L9 Morse.  
   - **Scope (phased):**  
     - Easy local: ROT-N (all shifts), Morse (.-), Caesar auto-score.  
     - Deep links: quipqiup, dcode Gold Bug / Homophonic, BeepCrypt.  
     - Optional later: HODOR decoder.

7. **Pastebin enrichment (password page detect + tags)**  
   - **Why:** Passworded pastes + **tags** (`beepcrypt`, `za`, Google Doc backlinks) are load-bearing in L6/L9.  
   - **Scope:** On Pastebin hit, surface “password protected” + scrape public tags when visible; don’t try passwords automatically.

8. **file.garden / catbox / ibb token awareness**  
   - **Why:** Hosts used “throughout” (L10.5 note); L1 catbox audio; L4 file.garden video.  
   - **Scope:** Classify URLs in Live Assets; optional probe templates for raw file IDs if pattern is stable.

### P2 — Nice-to-have / niche

9. **UUID / ID shape classifier**  
   - **Why:** L9 AP Archive UUID; L10 wifies ARG UUID.  
   - **Scope:** Heuristics (“looks like UUID / snowflake / IG highlight / ISBN”) + suggested probe routes.

10. **Audio helper deep-links**  
    - **Why:** SSTV (L2), Morse audio (L9), song ID (L1/L10.5).  
    - **Scope:** “Open in SSTV decoder / Morse tool / AcoustID” buttons when page has audio — no local DSP required.

11. **Steghide / password-stego checklist UI**  
    - **Why:** L10.5 password `writingsonthewall`; L11 `#rules` ZW + `pass:@nox.11`.  
    - **Scope:** Checklist + external tool links; optional ZW decode already partially covered — improve ZW→plaintext decode (L11).

12. **ISBN / book-cipher helper**  
    - **Why:** L4 ISBN from DNS → book cipher on Pastebin.  
    - **Scope:** Detect ISBN in Live Assets / DNS panel → Open Library / Google Books link; book-cipher UI is out of scope (manual).

---

## Explicit non-goals (from this pass)

- Do not rebuild full steghide / SSTV / Patristocrat solvers in-extension.
- Do not automate social login walls (IG/Spotify Song DNA remains manual).
- Soft-404 / Pinterest work elsewhere — leave alone unless reading for probe patterns.

## Suggested build order

1. Probe pack (ControlC, rentry, Scratch, Genius, Spotify, Letterboxd, Discord snowflake, IG highlight)  
2. DNS TXT panel  
3. Geohash resolver  
4. Media Asset Inspector  
5. Image strings viewer  
6. Cipher ROT-N + Morse + quipqiup/BeepCrypt deep links  

---

## Local copies

| File | Content |
|------|---------|
| `leads-gist.md` | Index + Discord / BL site pointers |
| `bl-list-bot2k25.md` | Prior-year BL list (linked from index) |
| `level-01-…` … `level-11-…` | Per-level walkthroughs |
| `level-10.5-spectre.md` | Spectre / Cambridge Five writeup |
| `recommendations-bot2k26.md` | This doc |

No code implemented in this research pass.
