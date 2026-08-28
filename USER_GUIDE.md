# The Hunt Engine — User Guide

Unified Firefox sidebar for cryptic hunts and light OSINT: live page scanning, backlink/username probing, image reverse-search helpers, DNS, geohash, redirect chains, local cipher decoding, and notes.

---

## Install / reload (temporary add-on)

1. Open Firefox → `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…**.
3. Select `hunt-engine/manifest.json`.
4. Open the sidebar: **View → Sidebar → The Hunt Engine**, or click the toolbar icon (toggles the sidebar).

Temporary add-ons unload when Firefox restarts — load `manifest.json` again after a restart. After code changes, use **Reload** on the extension card in `about:debugging`.

### Heavy media → Hunt CLI

For **full-file strings**, **SSTV**, spectrogram exports, Morse-from-audio, image ELA/LSB without browser limits:

```powershell
cd hunt-cli
pip install -r requirements.txt
python -m hunt_cli analyze path\to\clue.wav
```

**Cipher decode from the sidebar** — one-time native messaging setup (no server to keep running):

```powershell
python -m hunt_cli install-native
```

Reload Hunt Engine in `about:debugging`, then use **CLI decode** in Cipher Clipboard. Hunt-cli runs **Ciphey** when installed, plus HODOR / Morse / Base64 / hex / ROT13. Fallback: `python -m hunt_cli serve` on port **8746** (StegStruck uses **8745**).

See `hunt-cli/README.md`. Deep stego: `stegstruck` (`python -m stegstruck scan …`).

Requires Firefox **121+**. Restricted pages (`about:`, `addons.mozilla.org`, Firefox UI) do not run content scripts — scan and reveal are unavailable there.

---

## Quick start

1. Load the extension and open the Hunt Engine sidebar on a hunt page.
2. Expand **Page → Live Assets** (comments, Base64, links, flags, headers). Hit **Rescan page** if the DOM just changed.
3. Use **Reveal Hidden Layers** once if you suspect white-on-white / `hidden` / low-contrast text.
4. Paste a token into **Hunt → Backlink Identifier** (or right-click selection → **Probe as Backlink ID**). **Pin** the hunt origin (and subpaths as you find them) when the trail uses site-local paste paths.
5. Send suspicious strings to **Decode → Cipher Clipboard** (right-click → **Send to Hunt Engine**) and keep scraps in **Notes**.

Drag the **⋮⋮** handle on a **group** header (Hunt / Page / Media / Decode) to reorder groups; order is saved locally. Nested tools stay inside their group. Hover (or focus) the **?** next to a tool title for that tool’s help — explanations are no longer shown as long paragraphs.

Tools are nested under four accordion groups:

| Group | Tools |
|-------|--------|
| **Hunt** | Backlink Identifier, **ID Router**, **Paste / dead-drop** (Pin + Auto-probe in top chrome) |
| **Page** | Live Assets (artifact chips, **Scan source**, hidden content), Redirect Log |
| **Media** | Image Asset; **Audio Asset**; **Video / comments**; Last download / Archive |
| **Decode** | Cipher Clipboard (incl. **CLI decode** / hunt-cli, quipqiup/dCode/CyberChef links), Notes, **Cryptic checklist**, **Cryptic Guide**, Geohash, DNS |

---

## Top chrome

### Reveal Hidden Layers

**What it does.** Toggles a page-wide “reveal” mode on the active tab: forces high-contrast (neon-green on black) styling, unhides `[hidden]` / `aria-hidden` nodes, and highlights text that was invisible (contrast, visibility, spoiler/hidden class names, etc.). Toggle off to restore the site.

**How to use.** Click **Reveal Hidden Layers** in the sidebar header. Button shows pressed state while active. Revealed snippets appear under Live Assets → **Previously hidden**.

**Tips.** Run reveal before assuming a page is empty. Re-toggle if the site injects more DOM after load. Does not defeat canvas/WebGL stego or encrypted blobs — only CSS/DOM visibility tricks.

### Pin / hunt base

**What it does.** Pins the active tab into a hunt base set used by **ID-mode** probes. Always stores the **origin/root**, plus any **path variants** you pin on that host. Example: pin `https://coreisus.com/Mains` → bases are `coreisus.com` and `coreisus.com/Mains`. Pin another path on the same host (e.g. `/Extra`) to accumulate it. Pinning a **different** host replaces the set. ID probes try paste-style paths under **every** saved base: `/{id}`, `/raw/{id}`, `/p/{id}`, `/a/{id}`, `/file/{id}`, `/paste/{id}` (same paths are also tried on the **current site** origin). When the active tab is under a directory (e.g. `/practice/` or `/practice/index.html`), those same templates are also tried under that directory — even if the hunt base pin is host-only — so you get `/practice/{id}`, `/practice/p/{id}`, etc. Duplicate candidate URLs are skipped.

**How to use.** Navigate to the hunt home or a section URL → **Pin**. Label shows the host, or `host · N bases` when multiple paths are saved (hover for the full list). **×** next to the label clears the whole pinned set. **Clear** (next to Search in Backlink Identifier) stops an in-progress probe and clears results — it does not unpin the hunt base. Same-host **Pin** adds the current path; it does not wipe prior paths.

**Tips.** Pin the contest origin first, then pin important subpaths as you discover them. You cannot pin `about:` / internal URLs. Username mode also probes this-site and hunt-base paths (`/{username}`, `/user/{username}`, `/u/{username}`, `/profile/{username}`, plus the same paste-style templates as ID mode). On local practice under `/practice/`, probe a token without re-pinning — path-aware “this site” / hunt-base probes pick up the directory automatically (status line shows e.g. `7 under /practice`). Directory probes also try `/{id}.html` for static pages. Soft-404 HTML on this-site/hunt-base paths is filtered (not confirmed).

### Auto-probe hunt site

**What it does.** When **Auto-probe hunt** is ON (top chrome, default ON), Hunt Engine checks **only your pinned hunt base** — not Reddit, Wikipedia, the leads bot, or whatever tab you are reading. Triggers:

| Source | Behavior |
|--------|----------|
| **Text selection** | Highlight a single token/word (≥ 2 chars, no spaces) — debounced ~400 ms. Lowercase words like `giraffe` are allowed; common English stopwords are skipped. |
| **HTML comments** | Live Assets comment scan extracts token-like strings (≥ 3 chars, skips IE conditionals) and probes them the same way. |

Uses the same path templates and soft-404 filtering as manual Backlink Identifier (`/{id}`, `/p/{id}`, `/raw/{id}`, …). Each token is probed **once per page per session** (dedup cache).

**On hit.** Sidebar toast: `Hunt hit: /giraffe → cryptic.example/giraffe` (green). Backlink Identifier badge flashes `!`. **Browser notification** when the extension has permission.

**While probing.** Blue toast: `Probing hunt site: /redgod …` (selection only).

**On miss.** Gray toast: `No hunt hit for /redgod on pinned origin` — so silent misses are visible.

**Rapid selections.** Highlight `redgod`, then `giraffe` within a second — both probe in parallel (each token once per page). Trailing `?` / punctuation is stripped (`redgod?` → `redgod`).

**How to use.** **Pin** the real hunt origin first (where `/slug` pages live). Highlight suspect words from context on any page, or rely on comment auto-probe after **Rescan page**. If nothing is pinned, auto-probe does nothing. Turn off **Auto-probe hunt** to disable selection and comment probes.

### Auto-ingest downloads

**What it does.** When a download completes (toggle **Auto-ingest** in the top chrome, default ON), Hunt Engine classifies the file and jumps the sidebar to the matching tool:

| Download | Destination |
|----------|-------------|
| ZIP / JAR / APK (RAR/7z stubbed) | **Media → Last download / Archive** (re-fetch ≤ ~16 MB for EOCD comment + encryption) |
| PNG / JPG / GIF / WEBP / BMP | **Media → Image Asset** (sets the asset; kicks Hex/strings when the URL is http(s)) |
| MP3 / WAV / OGG / M4A / FLAC / AAC / WEBM (audio) | **Media → Audio Asset** (re-fetch ≤ ~16 MB for Strings/ID3; local tools up to ~32 MB) |
| TXT / CSV / JSON / MD / LOG / NFO | **Decode → Cipher Clipboard** (re-fetch ≤ ~512 KB) + a short Notes line |

A toast like `Download: clue.mp3 → Audio` explains the jump. `blob:` / `file:` URLs cannot always be re-fetched — the right panel still focuses with a drop/paste hint. Turn **Auto-ingest** off to stop watching downloads (preference saved in `storage.local`).

---

## Panel-by-panel

### Backlink Identifier

**What it does.** Probes a token or username across many known hosts using WhatsMyName-style **exists** signals (e-string / status rules). A bare HTTP 200 is never enough for a **confirmed** hit. Results split into:

| Bucket | Meaning |
|--------|---------|
| **Confirmed** | Exists signals matched |
| **Blocked — check manually** | Auth wall, rate-limit, captcha-ish body, or fetch failure — still clickable |
| **Checked / filtered** | Soft misses (missing-page strings, soft-404, unconfirmed, etc.) |

Also lists **Candidates on page** — token-shaped strings scraped from the page for one-click Probe.

**Modes**

- **ID / token** — paste IDs (Pastebin, ControlC, rentry, hastebin, paste.ee, justpaste.it, Telegra.ph, Bitly/is.gd/cutt.ly, Google Docs/Drive, Pinterest pins, Imgur, YouTube, Discord invites, Streamable, archives, etc.), plus current-site and hunt-base path probes (every saved origin + subpath, and the active tab’s directory when you’re not at the site root).
- **Username** — profile-style checks (GitHub, GitLab, Reddit, YouTube @, TikTok, Medium, Scratch, SoundCloud, Bluesky, Linktree, Letterboxd, Pastebin user, Neocities, …). Login-walled networks (Instagram, X, Facebook, LinkedIn, etc.) are skipped for auto-confirm.

**How to use.** Choose mode → paste token → **Search** (or Enter). Watch status for `confirmed / blocked / filtered` counts. Click result URLs to open. **Open all blocked** opens every blocked URL in background tabs.

**Tips.** Prefer right-click **Probe as Backlink ID** / **Probe as Username** on selected text. Expand **Checked / filtered** to see *why* a host was discarded. Blocked ≠ miss — open and verify by hand. Candidates live under this panel but are filled by the Live Assets scan.

### ID Router

**What it does.** Pattern-based “what is this string?” — Discord snowflake, YouTube ID, Pastebin slug, geohash, ISBN, UUID, Reddit id, etc. Shows canonical URLs + **Probe** (full Backlink Identifier) without running probes until you click.

**How to use.** Paste or right-click selection → **Identify string in Hunt Engine (ID router)**. Click **Open** / **Copy** / **Probe** on matched cards.

### Paste / dead-drop

**What it does.** Fetches paste-style URLs or bare IDs (256 KB cap). Warns on password-protected pages. `#tag` chips can be probed as backlink IDs.

**How to use.** Paste URL or ID → **Fetch**. Right-click paste links → **Open paste link in Hunt Engine**. Right-click selection → **Open in Paste panel**.

### Live Assets — artifact chips & hidden content

**Artifact chips** (blue = sure, gray = maybe, green = confirmed hunt hit) appear on Live Assets rows, candidates, and comment workspace. Click a chip to jump to Cipher, DNS, Geohash, Paste panel, ID router, Video lane, or hunt-site auto-probe.

**Hidden content** section merges:
- **DOM scan** — HTML comments, previously hidden (after Reveal), zero-width
- **Source scan** — from **Scan source** (re-fetches HTML, lists comments/CSS-hidden/odd meta; 256 KB cap)

**Media filenames & alt** — `img[alt]`, download filenames, media src basenames.

**Book tip** (static): chapter title + page number — search inside archive preview.

### Video / comments

**What it does.** Loads video title/author via noembed (no API key). **Open comments** for YouTube/Vimeo templates. **Comment workspace** — paste comment text when platforms block scraping; artifact chips classify pasted text.

**How to use.** Paste video URL → **Load**, or click **Video** handoff on a Live Assets media row.

### Cryptic checklist

Zero-spoiler discipline list for DTC/BOT-style hunts (pin origin, view-source, video comments, homophones, concat passwords, one concrete `rel?`). Checkboxes persist locally — progress only.

### Cryptic Guide

Static playbook for BOT / Paradigm-style hunts: the two questions per hop, output-type table, direction branches, mod `rel?` discipline, and tool quick map. Reference only — no hunt spoilers. Scroll inside the panel when expanded.

### Cipher Clipboard — hunt-cli & deep links

Niche ciphers (e.g. HODOR) are **not** built-in decoders — use the **dCode** button (opens the right tool page and auto-fills `#cipher_identifier_ciphertext` or the matching field).

**CLI decode** sends clipboard text to local **hunt-cli** via Firefox native messaging (`python -m hunt_cli install-native`) or HTTP fallback (`python -m hunt_cli serve` on `:8746`). Runs Ciphey when installed; shows results as a cipher card.

**quipqiup**, **dCode**, **CyberChef** open external tools. **dCode** auto-fills the ciphertext textarea via a content script on `dcode.fr` — it waits for dCode’s page scripts, then replaces any saved form state in localStorage so old paste URLs do not stick.

### Image Asset

**What it does.** Holds one captured image URL and offers reverse search, forensics handoff, filename probe, hex / strings / edit+preview, **Split** (concatenated-file extract), and light **Meta** (EXIF / PNG text).

**How to use.** Right-click an image → **Send image URL to Hunt Engine** (or any reverse/forensics/probe image menu — those also capture the URL). Or **drop / choose a local file** in the Image Asset drop zone (same as Audio). Then use:

| Button | Action |
|--------|--------|
| **Open** | Open the image URL |
| **Copy URL** | Copy to clipboard |
| **Lens / Yandex / TinEye** | Open reverse search by URL |
| **ELA** | **Local** Error Level Analysis — recompresses as JPEG and amplifies pixel differences (best on JPEG; CORS/tainted canvas may block remote URLs — drop file if needed) |
| **LSB** | **Local** least-significant-bit planes for R/G/B bits 0–1 |
| **Channels** | **Local** RGB channel split |
| **Forensics** | **Local ELA** in-panel — image is fetched and analyzed automatically (also runs on right-click → ELA analysis) |
| **External sites** | Optional: opens Forensically, Jeffrey’s EXIF, FotoForensics in background tabs (manual upload often still required) |
| **StegStruck** | Sends the image to the local StegStruck pipeline (`http://127.0.0.1:8745`) and opens the live report. Requires StegStruck running (`cd stegstruck && python -m stegstruck serve`). Same idea as right-click → **Scan with StegStruck (local)**. |
| **Probe filename** | Strips the last path segment’s extension and runs Backlink ID probe |
| **Hex / strings** | Fetches the image (≤ ~8 MB), lists printable / trailing strings (Cipher / Probe / Notes handoff), shows head/tail 256-byte hex dumps, an **editable** hex region (full file if ≤ ~2 MB; otherwise last 64 KB only — labeled), and auto-scans for **concatenated** payloads. **Apply / Patch** re-fetches, splices your bytes, shows an `<img>` preview, and **Download patched**. PNG CRC may break if you corrupt chunks — download is still allowed. |
| **Split** | Same fetch/scan as Hex, focused on glued files: second JPEG after `FF D9`, PNG/GIF/ZIP/PDF magics, etc. Shows “Concatenated file detected @ 0x…” with **Download part 1 / 2**, **Preview both** (image types), and **Split all** when more than two segments. |
| **Meta** | Light client-side parse: JPEG EXIF (ImageDescription / UserComment / etc.) and PNG tEXt / iTXt (zTXt noted if compressed). Shown under the same Image Asset card |

**Tips.** Filename tokens (e.g. `corridor-nr00k7px.svg` → `nr00k7px`) are a common hunt hop — use Probe filename early. Reverse search needs a publicly fetchable URL. Use **ELA / LSB / Channels** for quick in-panel forensics; **Forensics+** for heavier external suites. Use **Hex / strings**, **Split**, or **Meta** when you suspect embedded text, a file glued after EOI/IEND, or EXIF clues. Hex edit is for trailing payloads / small binary tweaks, not a full hex editor. Classic theme: JPEG + second JPEG (or ZIP) after the first `FF D9` — **Split** → download part 2.

### Audio Asset

**What it does.** Holds one captured audio/video URL (or a dropped local file) and offers lightweight byte analysis, **local** spectrogram/Morse/SSTV tools, plus optional external tool handoffs.

**How to use.** Right-click `<audio>` / `<video>` (or an `.mp3`/`.wav`/… link) → **Send audio URL to Hunt Engine**. Live Assets lists **Audio / video on page** with an **Audio** handoff. After a download, auto-ingest jumps here when the file is audio.

| Button | Action |
|--------|--------|
| **Open** | Open the audio URL |
| **Copy URL** | Copy to clipboard |
| **Strings / ID3** | Fetches the file (≤ ~16 MB), lists printable strings (trailing payload / embedded text), parses basic **MP3 ID3** (title, artist, comment — comments often hide passwords/clues). Larger files: use **Spectrogram / Morse decode / SSTV** (up to ~32 MB). |
| **Probe filename** | Strips the path segment extension and runs Backlink ID probe |
| **Spectrogram** | **Local** STFT heatmap in-panel — **auto-runs** when audio is captured (Web Audio decode; up to ~90 s) |
| **Morse decode** | **Local** experimental tone-burst Morse decoder — click result to send to Cipher |
| **Spectrogram / Morse decode** | **Local** in-panel tools |
| **SSTV (local)** | Experimental Scottie S1 in-panel; full Robot 36 / VIS via **hunt-cli** (`python -m hunt_cli sstv file.wav`) |
| **Audacity wiki / Spectrum / dCode Morse** | Optional external tools (dCode Morse auto-fills when Morse was decoded in-panel) |

Morse-like text in strings or ID3 shows a **Morse →** chip — click to send to **Cipher → Morse decode** and see the result inline. Drop a local file when the URL is `blob:` / `file:` / expired — the sidebar `<audio>` preview plays it (blob URL + session metadata), and Strings/ID3 still run. Local preview bytes are kept in the sidebar for the session; after an extension reload, re-drop the file to play again.

**Tips.** Hunt audio clues are often spectrogram/Morse — spectrogram **loads automatically** when you capture audio. Use **Morse decode** for tone bursts. External row is optional. ID3 **Comment** frames are a common password stash.

### Last download / Archive

**What it does.** Part of **Auto-ingest** (see Top chrome): watches completed ZIP / JAR / APK downloads (RAR / 7z stubbed as unsupported). Re-fetches the http(s) URL (≤ ~16 MB), reads the ZIP **End of Central Directory** comment, and checks whether entries look encrypted (central-directory general-purpose bit 0). Results land under **Media → Last download / Archive**.

**How to use.** Download a ZIP during a hunt — with Auto-ingest ON the panel fills and scrolls into view. Or use **Analyze archive** (click / drop) when the URL is `blob:` / expired / unreachable. Then:

| Button | Action |
|--------|--------|
| **Copy comment** | Copy the raw archive comment |
| **Cipher** | Send comment to Cipher Clipboard (hex comments decode there — e.g. `746F62696173` → `tobias`) |
| **Notes** | Append `[filename] comment` to Notes |
| **Probe** | Probe comment (or hex-decoded hint) as Backlink ID |

If the comment looks like hex, a **Hex →** chip shows the decoded preview.

**Tips.** Password-protected hunt ZIPs often stash the password (or a hex encoding of it) in the archive comment — check this panel before brute-forcing. Manual drop works offline without re-fetch. RAR / 7z comment parsing is out of scope for now.

### DNS Inspector

**What it does.** DNS-over-HTTPS lookup via Cloudflare for **TXT, A, AAAA, MX, CNAME, NS** (TXT listed first — common cryptic hop). Each record can hand off to Cipher / Probe / Notes.

**How to use.** Enter `example.com` → **Lookup**, or right-click a domain selection → **DNS lookup in Hunt Engine**.

**Tips.** Prefer FQDN without path. Live Assets handoff **DNS** appears when an asset looks domain-like.

### Geohash / Coords

**What it does.** Locally decodes a geohash **or** parses `lat, lon` → shows coordinates (± error for geohash) and links to OpenStreetMap / Google Maps, plus Copy / Cipher / Notes.

**How to use.** Paste `gcf23vys4qp` or `54.65, -8.11` → **Resolve**, or right-click selection → **Resolve geohash / coords in Hunt Engine**.

**Tips.** All math is local — no map API key. Geohash uses the standard base32 alphabet.

### Live Assets

**What it does.** Auto-scans the active page (all frames, with mutation debounce) for hunt-relevant material:

| Section | Contents |
|---------|----------|
| **Response headers** | Main-document response headers (via `webRequest`); flags suspicious / non-standard names (`X-*`, clue-like Set-Cookie, etc.) with Copy / Cipher / Notes |
| **robots.txt paths** | After **Fetch robots.txt**: Allow/Disallow paths (Open / Copy; **Probe** when the last segment looks like a token). Soft-fails if missing |
| **Sitemap** | Up to 50 `<loc>` URLs from robots `Sitemap:` lines and/or `{origin}/sitemap.xml` (Open / Copy / optional Probe on last segment) — discovery list only, not a crawler |
| **Links on page** | Full URLs already in DOM/HTML (Open + copy) |
| **Audio / video on page** | `<audio>` / `<video>` / `.mp3` links (Open + **Audio** handoff) |
| **Previously hidden** | Text found while Reveal is on |
| **HTML comments** | `<!-- … -->` |
| **Base64** | Candidate Base64 blobs (often with decoded preview) |
| **Zero-width / invisible** | ZW chars with code points + counts |
| **Flag-shaped strings** | Patterns like `FLAG{…}`, `CTF{…}`, `picoCTF{…}`, `hunt{…}` |
| **Meta / canonical** | Meta refresh + canonical link |

**Handoff.** Most asset rows offer **Copy**, plus **Cipher**, **Probe**, **Notes**, and **DNS** when a domain is detected. Comments/Base64 may show a **decode chip** (Octal / Decimal / Base64 preview) — click to send decoded text to Cipher.

**How to use.** Open the panel; click **Rescan page** after AJAX/SPA updates. Candidates also feed Backlink Identifier’s candidate list. Use **Fetch robots.txt** for a compact Allow/Disallow + sitemap peek on the current tab origin (and hunt base origin when pinned).

**Tips.** Check comments and meta refresh early. Zero-width often encodes a short clue — send the visible snippet to Notes/Cipher. Caps limit how many items of each type are kept (large pages truncate). Sitemap listing caps at ~50 locs and ~2 MB fetch — enough for trail breadcrumbs, not full site maps.

### Redirect Log

**What it does.** Chronological main-frame redirect chains (HTTP 3xx and client/meta-style hops the extension can observe), newest first. Each chain shows hop index, URL, via/status, and a copy of the chain.

**How to use.** Navigate through shortener / meta-refresh paths with the sidebar open; inspect the log after the bounce settles.

**Tips.** Main frame only — iframe hops are not the focus. Useful to reconstruct “where did this short link dump me?”

### Cipher Clipboard

**What it does.** Local-only decoders run on whatever is in the textarea. Cards mark invalid inputs; successful cards have **Copy**. Guesser chips above the cards suggest likely encodings (Base64, Hex, Morse, A1Z26, Bacon, T9, Caesar, …) — click a chip to jump to that card.

Decoders:

1. Base64  
2. Hex  
3. Octal  
4. Decimal / ASCII  
5. Binary  
6. Binary → Morse (0=· 1=−; space = letter break, `/` = word break; also tries reversed mapping)  
7. Ternary / Base-3 (0–2 digit groups → decimal → ASCII / A–Z)  
8. A1Z26 (numbers ↔ letters)  
9. Bacon’s cipher (A/B, 0/1, or patterned case)  
10. Phone keypad / multi-tap (T9)  
11. ROT13  
12. **ROT-N (manual)** — compact row: slider + N (0–100) + optional **key**. Letters card uses N mod 26; a second **ROT-N ASCII** card rotates printable 32–126 by full N (e.g. ROT32)  
13. Caesar crib (ROT 1–25, English-ish score — best few hits; not a Vigenère brute)  
14. ROT47  
15. URL decode  
16. Reverse  
17. Atbash  
18. Morse  
19. **Vigenère (key)** / **XOR (key)** — appear when the compact **key** field is filled (session memory only; not saved)

**How to use.** Paste, **select encoded text on the page** (auto-fills when it looks like Base64/hex/Morse/ternary/etc.), or right-click selection → **Send to Hunt Engine**. Toggle **Auto-decode selection** in the Cipher panel (default on; uses heuristics so normal prose is ignored). Use the **ROT-N** row (and optional key) under the textarea. Cipher text persists with extension state; the key stays in the sidebar session only. Typing re-runs all decoders.

**Tips.** Invalid cards are expected for mismatched formats — ignore them and read the green/valid ones. **Binary → Morse** maps `0`→`·` and `1`→`−` (also shows reversed `0`→`−`); spaces separate letters, `/` separates words — then Morse-decodes when valid. Morse accepts `.` `-`, bullets, and `/` or multi-space word breaks. Ternary accepts space/comma-separated trit groups (often 5 digits) or continuous 0–2 runs; primary mapping is base-3 → ASCII when values are printable, with A=0 / A=1 letter fallbacks and a raw decimal line. Use **manual ROT-N** for a known shift; Caesar crib still ranks unknown ROT-N. With a known key, use **Vigenère** / **XOR** — full polyalphabetic brute force remains out of scope. Nothing is sent to a remote “cipher API.”

### Notes

**What it does.** Persistent notepad (`storage.local`) for clues. **Analyze** extracts cryptic-hunt style hidden messages from the **selection** (if any) or the full note:

- A1Z26 (line starts) — leading integer on each line → A–Z  
- A1Z26 (all numbers) — integers 1–26 in order → A–Z  
- Spaced numbers — `#`-delimited or noisy integer runs → space-delimited ASCII codes (e.g. `#67#65#80…` or merged `8273` → `82 73`; send to Cipher **Decimal**)  
- Capitals  
- First letters  
- Last letters  
- Acrostic (first char of each non-empty line)  
- Lowercase (when mixed case)  
- Digits  
- Letters inside parentheses  

Each result can go to **Cipher** or **Probe**, or click the value to copy.

**Other controls**

- **Count** — chars / words / lines (selection or full)  
- **Send to Cipher Clipboard** / **Probe as Backlink ID** — uses selection, else first Analyze candidate, else full note  
- **Format** — UPPERCASE, lowercase, Title Case, Trim, Collapse whitespace, Reverse, No spaces (applies to selection or whole note)

**Tips.** Select a paragraph before Analyze to avoid noise from the whole dump. Format → Reverse is handy before Cipher Atbash/Reverse checks.

---

## Right-click menus

### Selection

| Menu item | Effect |
|-----------|--------|
| **Send to Hunt Engine** | Fills Cipher Clipboard and opens sidebar |
| **Probe as Backlink ID** | ID-mode probe |
| **Probe as Username** | Username-mode probe |
| **DNS lookup in Hunt Engine** | Normalizes to a domain and looks up DNS |
| **Resolve geohash / coords in Hunt Engine** | Fills Geohash panel and resolves |
| **Identify string in Hunt Engine (ID router)** | Opens ID Router with selection |
| **Open in Paste panel** | Opens Paste panel with selection |
| **Open paste link in Hunt Engine** | Opens Paste panel with link URL |

### Image

| Menu item | Effect |
|-----------|--------|
| **Send image URL to Hunt Engine** | Captures URL into Image Asset |
| **Reverse image — Google Lens / Yandex / TinEye** | Captures URL + opens reverse search |
| **Open in forensics tools (Forensically+)** | Captures URL, opens three forensics tabs, copies URL into sidebar status flow |
| **Probe image filename as Backlink ID** | Captures URL + probes stripped filename |

### Audio / video / audio links

| Menu item | Effect |
|-----------|--------|
| **Send audio URL to Hunt Engine** | Captures URL into Audio Asset (`audio` context) |
| **Send audio/video URL to Hunt Engine** | Captures URL from `<video>` (`video` context) |
| **Send audio link to Hunt Engine** | Captures `.mp3`/`.wav`/… link URL (`link` context, extension filter) |
| **Probe audio filename as Backlink ID** | Captures URL + probes stripped filename |

---

## Typical hunt workflow

1. Land on the level page → open sidebar → **Rescan** / skim **Live Assets** (comments, Base64, links, meta).
2. **Reveal Hidden Layers** if contrast or `hidden` classes are suspected; note **Previously hidden**.
3. Decode obvious Base64 / Atbash via decode chips or **Cipher Clipboard**.
4. Capture images → reverse search and/or **Probe filename**; use Forensics+ when EXIF/ELA might matter (manual finish in those sites). Capture audio → **Strings / ID3** and deep tools when spectrogram/Morse/SSTV is suspected. After a ZIP download, check **Last download / Archive** for comment / encryption (hex comments → Cipher).
5. **Pin** the contest origin (and useful subpaths) if pastes live on-site; **Search** tokens in Backlink Identifier; open **confirmed** and verify **blocked**.
6. Follow shortener / meta hops with **Redirect Log** open.
7. Domains → **DNS** (especially TXT); geohash-looking strings → **Geohash / Coords**.
8. Keep a running **Notes** pad; **Analyze** for capitals/acrostics before giving up on a prose clue.

---

## Practice demo (optional)

Under `demo/`:

```bash
cd hunt-engine/demo
python server.py
```

- Arena: http://127.0.0.1:8765/  
- **Neon Rook** practice hunt: http://127.0.0.1:8765/practice/

**Mechanic stations** (under `/practice/station-*.html`): paste, page source, video/comments, ID router, HODOR, DNS workflow.

Pin `http://127.0.0.1:8765` as hunt base when probing demo paste tokens. See `demo/README.md` for station list and a spoilered solve path (fiction only — not a live contest).

**Feature caps:** paste fetch and page source scan ≤ 256 KB; paste/tag extraction heuristic only; ID router patterns may false-positive (labeled “maybe” on artifact chips).

---

## What it does **not** do

- Full steganography solvers inside the extension — use **StegStruck** (local companion app) from Image Asset / right-click for the parallel pipeline. In-panel **Hex / strings**, **Split**, **Meta**, **ELA / LSB / Channels** are lightweight peeks. **Audio Asset** does strings + basic MP3 ID3 + Morse chip handoff + **local** spectrogram/Morse/SSTV (experimental; external row remains for hard cases). **Last download / Archive** reads ZIP comments / encryption flags only (not RAR/7z comments, not password recovery).
- Heavy EXIF/ELA analysis — in-panel **ELA** is a quick JPEG-oriented peek; **Forensics+** opens external suites for deeper work.
- Confirming login-walled social posts as “exists” without you opening them.
- Scanning or revealing on Firefox internal / AMO pages.
- Network cipher services — all Cipher Clipboard work is local.
- Full Vigenère / polyalphabetic **brute force** — use **Caesar crib** / **manual ROT-N** for ROT; enter a known key for Vigenère / XOR decrypt (no key search).
- Guaranteeing every shortener/host — soft-404s and SPA shells are filtered or skipped by design.
- Replacing a full WhatsMyName / Sherlock run for arbitrary sites — username coverage is a curated subset.
- Solving CAPTCHAs, bypassing auth, or decrypting Mega/Drive crypto for you.

---

## Persistence & chrome notes

- **Notes**, **group order**, and **group/tool open/closed** state save in extension local storage.
- First load defaults: **Hunt** + **Page** open; **Media** + **Decode** collapsed (your toggles persist). Nested tools keep their own open state (e.g. Cipher open inside Decode when you expand it).
- Legacy flat `sidebarPanelOrder` panel ids are migrated once to group order.
- **Hunt base**, last **cipher** text (not the Key/password field — that is sidebar session memory only), **image asset**, **audio asset**, **archive info**, **probe** results, **response headers**, and **redirect** log are kept in extension session/store and refreshed per tab where relevant.
- Hover **?** on a tool title for help (replaces long lede paragraphs).
- Content script runs at `document_idle` on all frames for matching URLs.
