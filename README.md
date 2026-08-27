# The Hunt Engine

Firefox Manifest V3 sidebar extension for cryptic hunts and light OSINT. Vanilla HTML, CSS, and JavaScript — no build step.

## Load as a temporary add-on

1. Open Firefox and go to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…**
3. Select `hunt-engine/manifest.json` in this folder.
4. Open the sidebar: **View → Sidebar → The Hunt Engine**, or click the toolbar button.

Temporary add-ons unload when Firefox restarts. Load the folder again after a restart.

## What it does

- **Live Assets** — HTML comments, Base64, zero-width, flags, meta, previously-hidden text, and **Links on page** (full URLs already in the DOM).
- **Backlink Identifier** — paste a token (`jGJuVGiK`, `690519146701783042`, …) or right-click → **Probe as Backlink ID**. Probes Pastebin, Pinterest, Imgur, YouTube, shorteners, Drive/Docs, Discord, etc., plus the **current site** and an optional **pinned hunt base**.
- **Reveal Hidden Layers** — forces neon-green text on a black page and unhides `[hidden]` nodes. Toggle off to restore the site.
- **Redirect Log** — chronological main-frame hop chain (HTTP 3xx plus client redirects).
- **Cipher Clipboard** — right-click selected text → **Send to Hunt Engine**, or paste into the sidebar. Decodes Base64, hex, binary, ROT13, URL, reverse, and Atbash locally.

Restricted pages (`about:`, addons.mozilla.org, Firefox UI) do not run content scripts; scan and reveal are unavailable there.

## Local demo arena

A static site under `demo/` exercises every feature (comments, Base64, hidden layers, HTTP + meta redirects, cipher samples, iframe clues).

```bash
cd hunt-engine/demo
python server.py
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/) with the extension loaded.
