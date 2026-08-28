/**
 * The Hunt Engine — content script.
 *
 * Runs in every frame (http/https/file) at document_idle.
 *
 *   1. Walks the DOM for HTML comments (Node.COMMENT_NODE).
 *   2. Scans visible text nodes for padded Base64 payloads.
 *   3. Extra hunt finds: zero-width Unicode, flag-shaped strings, meta refresh / canonical.
 *   4. Injects / removes the "Reveal Hidden Layers" CSS override.
 *   5. Re-scans on DOM mutation (debounced) and on explicit RESCAN messages.
 */

"use strict";

(function huntEngineContent() {
  // Isolated world — still wrap so a second injection is a no-op.
  if (window.__huntEngineLoaded) return;
  window.__huntEngineLoaded = true;

  const MSG = {
    LIVE_ASSETS: "LIVE_ASSETS",
    APPLY_REVEAL: "APPLY_REVEAL",
    GET_REVEAL: "GET_REVEAL",
    RESCAN: "RESCAN",
    PROBE_PAGE_CHECK: "PROBE_PAGE_CHECK",
    CIPHER_INPUT: "CIPHER_INPUT",
    AUTO_PROBE_SELECTION: "AUTO_PROBE_SELECTION",
  };

  const AUTO_DECODE_KEY = "cipherAutoDecode";
  const AUTO_PROBE_HUNT_KEY = "autoProbeHuntSite";
  const AUTO_DECODE_DEBOUNCE_MS = 350;
  const AUTO_PROBE_DEBOUNCE_MS = 400;
  const AUTO_DECODE_MIN = 4;
  const AUTO_PROBE_MIN = 2;
  const AUTO_DECODE_MAX = 2000;
  const AUTO_PROBE_MAX = 64;

  const STYLE_ID = "hunt-engine-reveal";
  const ATTR_WAS_HIDDEN = "data-hunt-was-hidden";
  const ATTR_REASON = "data-hunt-hidden-why";
  const MAX_COMMENTS = 150;
  const MAX_BASE64 = 150;
  const MAX_ZW = 80;
  const MAX_FLAGS = 40;
  const MAX_REVEALED = 80;
  const MAX_BACKLINKS = 120;
  const MAX_MEDIA_URLS = 40;
  const SCAN_DEBOUNCE_MS = 450;
  const SKIP_TEXT_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA"]);
  const SKIP_REVEAL_TAGS = new Set([
    "SCRIPT",
    "STYLE",
    "LINK",
    "META",
    "HEAD",
    "BR",
    "HR",
    "SOURCE",
    "TRACK",
  ]);

  // Padded Base64 only (must end in = or ==) — matches the hunt-finder contract.
  const BASE64_RE = /[A-Za-z0-9+/]{16,}={1,2}/g;
  const FLAG_RE = /\b(?:CTF|FLAG|picoCTF|PICOCTF|hunt|HUNT)\{[^\n\r}]{1,200}\}/g;
  const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\u2060\uFEFF\u180E\u200E\u200F\u2061\u2062\u2063\u2064]/g;

  // Stylesheet alone often loses to page rules like `.x { color:#000 !important }`.
  // Inline setProperty(..., "important") beats author stylesheets — needed for
  // black-on-black hunt text that survived a simple color override.
  const REVEAL_CSS = `
    html, body, html body *:not([${ATTR_WAS_HIDDEN}]) {
      background: #000000 !important;
      background-color: #000000 !important;
      background-image: none !important;
    }
    html, body, html body * {
      color: #00FF00 !important;
      -webkit-text-fill-color: #00FF00 !important;
      caret-color: #00FF00 !important;
      opacity: 1 !important;
      visibility: visible !important;
      filter: none !important;
      mix-blend-mode: normal !important;
      text-shadow: none !important;
    }
    html body *::before,
    html body *::after {
      color: #00FF00 !important;
      -webkit-text-fill-color: #00FF00 !important;
      opacity: 1 !important;
      visibility: visible !important;
    }
    html { font-size: 16px !important; }
    html body, html body * {
      font-size: max(16px, 1rem) !important;
    }
    html body [hidden],
    html body [aria-hidden="true"] {
      display: block !important;
    }
    html body svg,
    html body svg * {
      fill: #00FF00 !important;
      stroke: #00FF00 !important;
    }

    /* Call out text that was invisible before reveal */
    html body [${ATTR_WAS_HIDDEN}] {
      outline: 2px solid #ffcc00 !important;
      outline-offset: 3px !important;
      box-shadow:
        0 0 0 4px rgba(255, 204, 0, 0.35),
        0 0 22px rgba(255, 204, 0, 0.45) !important;
      background: #1a1600 !important;
      background-color: #1a1600 !important;
      border-radius: 2px !important;
      position: relative !important;
      animation: hunt-reveal-pulse 1.4s ease-in-out 2;
    }
    html body [${ATTR_WAS_HIDDEN}]::after {
      content: "was hidden · " attr(${ATTR_REASON}) !important;
      position: absolute !important;
      top: -1.35em !important;
      left: 0 !important;
      z-index: 2147483646 !important;
      font: 700 10px/1.2 ui-monospace, Consolas, monospace !important;
      letter-spacing: 0.02em !important;
      color: #111 !important;
      -webkit-text-fill-color: #111 !important;
      background: #ffcc00 !important;
      background-color: #ffcc00 !important;
      padding: 2px 6px !important;
      border-radius: 3px !important;
      white-space: nowrap !important;
      pointer-events: none !important;
      opacity: 1 !important;
      visibility: visible !important;
      text-transform: none !important;
    }
    @keyframes hunt-reveal-pulse {
      0%, 100% { box-shadow: 0 0 0 4px rgba(255, 204, 0, 0.35), 0 0 18px rgba(255, 204, 0, 0.35); }
      50% { box-shadow: 0 0 0 6px rgba(255, 204, 0, 0.55), 0 0 28px rgba(255, 204, 0, 0.7); }
    }
  `;

  const REVEAL_INLINE_PROPS = [
    ["color", "#00FF00"],
    ["-webkit-text-fill-color", "#00FF00"],
    ["caret-color", "#00FF00"],
    ["opacity", "1"],
    ["visibility", "visible"],
    ["filter", "none"],
    ["mix-blend-mode", "normal"],
    ["background", "#000000"],
    ["background-color", "#000000"],
    ["background-image", "none"],
  ];

  const HIGHLIGHT_INLINE_PROPS = [
    ["outline", "2px solid #ffcc00"],
    ["outline-offset", "3px"],
    ["box-shadow", "0 0 0 4px rgba(255, 204, 0, 0.35), 0 0 22px rgba(255, 204, 0, 0.45)"],
    ["background", "#1a1600"],
    ["background-color", "#1a1600"],
  ];

  let scanTimer = 0;
  let lastPayloadKey = "";
  let revealEnabled = false;
  let revealMutationTimer = 0;
  /** @type {WeakSet<Element>} */
  let revealTouched = new WeakSet();
  /** @type {Element[]} */
  let revealedNodes = [];
  /** @type {MutationObserver | null} */
  let revealObserver = null;

  // -------------------------------------------------------------------------
  // Live asset scanners
  // -------------------------------------------------------------------------

  function collectComments() {
    const found = [];
    const seen = new Set();
    const root = document.documentElement || document;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT);

    let node = walker.nextNode();
    while (node && found.length < MAX_COMMENTS) {
      const value = node.nodeValue == null ? "" : String(node.nodeValue);
      if (value.length === 0) {
        node = walker.nextNode();
        continue;
      }
      const key = value;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({
          text: value,
          preview: preview(value, 240),
        });
      }
      node = walker.nextNode();
    }
    return found;
  }

  function collectTextBlobs() {
    const blobs = [];
    const body = document.body;
    if (!body) return blobs;

    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (SKIP_TEXT_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
        if (parent.closest("script, style, noscript, textarea")) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });

    let node = walker.nextNode();
    while (node) {
      const value = node.nodeValue;
      if (value && value.length >= 8) blobs.push(value);
      node = walker.nextNode();
    }
    return blobs;
  }

  function collectBase64(blobs) {
    const found = [];
    const seen = new Set();

    for (const blob of blobs) {
      BASE64_RE.lastIndex = 0;
      let match;
      while ((match = BASE64_RE.exec(blob)) && found.length < MAX_BASE64) {
        const raw = match[0];
        if (seen.has(raw)) continue;
        if (!isLikelyBase64Payload(raw)) continue;
        seen.add(raw);
        const decoded = tryAtob(raw);
        found.push({
          text: raw,
          preview: preview(raw, 160),
          decodedPreview: decoded ? preview(decoded, 160) : "",
        });
      }
      if (found.length >= MAX_BASE64) break;
    }
    return found;
  }

  function collectFlags(blobs) {
    const found = [];
    const seen = new Set();
    for (const blob of blobs) {
      FLAG_RE.lastIndex = 0;
      let match;
      while ((match = FLAG_RE.exec(blob)) && found.length < MAX_FLAGS) {
        const raw = match[0];
        if (seen.has(raw)) continue;
        seen.add(raw);
        found.push({ text: raw, preview: preview(raw, 200) });
      }
      if (found.length >= MAX_FLAGS) break;
    }
    return found;
  }

  function collectZeroWidth(blobs) {
    const found = [];
    const seen = new Set();

    for (const blob of blobs) {
      ZERO_WIDTH_RE.lastIndex = 0;
      if (!ZERO_WIDTH_RE.test(blob)) continue;

      const chars = [];
      ZERO_WIDTH_RE.lastIndex = 0;
      let m;
      while ((m = ZERO_WIDTH_RE.exec(blob))) {
        const cp = m[0].codePointAt(0);
        const hex = "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
        if (!chars.includes(hex)) chars.push(hex);
      }

      const snippet = preview(visibleSnippet(blob), 120);
      const key = chars.join(",") + "|" + snippet;
      if (seen.has(key)) continue;
      seen.add(key);

      found.push({
        text: snippet,
        preview: snippet,
        codes: chars,
        count: (blob.match(new RegExp(ZERO_WIDTH_RE.source, "g")) || []).length,
      });
      if (found.length >= MAX_ZW) break;
    }
    return found;
  }

  function collectMeta() {
    const meta = [];

    document.querySelectorAll("meta[http-equiv]").forEach((el) => {
      const httpEquiv = (el.getAttribute("http-equiv") || "").trim();
      if (!/^refresh$/i.test(httpEquiv)) return;
      const content = el.getAttribute("content") || "";
      meta.push({
        kind: "refresh",
        text: content,
        preview: "meta refresh: " + preview(content, 180),
      });
    });

    document.querySelectorAll("link[rel]").forEach((el) => {
      const rel = (el.getAttribute("rel") || "").trim();
      if (!/^canonical$/i.test(rel)) return;
      const href = el.getAttribute("href") || "";
      if (!href) return;
      meta.push({
        kind: "canonical",
        text: href,
        preview: "canonical: " + preview(href, 180),
      });
    });

    return meta;
  }

  // -------------------------------------------------------------------------
  // Base64 validation — padded, decodes, mostly printable
  // -------------------------------------------------------------------------

  function tryAtob(str) {
    try {
      const bin = atob(str);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch (_err) {
      return "";
    }
  }

  function isLikelyBase64Payload(str) {
    if (!/(=|==)$/.test(str)) return false;
    let decoded = "";
    try {
      decoded = atob(str);
    } catch (_err) {
      return false;
    }
    if (decoded.length < 4) return false;

    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const c = decoded.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126) || c >= 160) {
        printable++;
      }
    }
    return printable / decoded.length >= 0.85;
  }

  function preview(text, max) {
    const flat = String(text).replace(/\s+/g, " ").trim();
    if (flat.length <= max) return flat;
    return flat.slice(0, max) + "…";
  }

  function visibleSnippet(text) {
    return String(text).replace(ZERO_WIDTH_RE, "·");
  }

  // -------------------------------------------------------------------------
  // Backlink identifier (local equivalent of backlinks.rex.wf service list)
  // -------------------------------------------------------------------------

  const BACKLINK_SERVICES = [
    { id: "imgur", label: "Imgur", test: /(?:^|\.)imgur\.com$/i },
    { id: "youtube", label: "YouTube", test: /(?:^|\.)(?:youtube\.com|youtu\.be|youtube-nocookie\.com)$/i },
    { id: "tinyurl", label: "TinyURL", test: /(?:^|\.)tinyurl\.com$/i },
    { id: "googl", label: "Goo.gl", test: /(?:^|\.)goo\.gl$/i },
    { id: "bitly", label: "Bit.ly", test: /(?:^|\.)bit\.ly$/i },
    { id: "pastebin", label: "Pastebin", test: /(?:^|\.)pastebin\.com$/i },
    { id: "mediafire", label: "MediaFire", test: /(?:^|\.)mediafire\.com$/i },
    { id: "mega", label: "Mega", test: /(?:^|\.)mega\.(?:nz|co\.nz)$/i },
    { id: "gyazo", label: "Gyazo", test: /(?:^|\.)gyazo\.com$/i },
    { id: "dailymotion", label: "Dailymotion", test: /(?:^|\.)dailymotion\.com$/i },
    { id: "vimeo", label: "Vimeo", test: /(?:^|\.)vimeo\.com$/i },
    { id: "onion", label: "Onion", test: /\.onion$/i },
    { id: "facebook", label: "Facebook", test: /(?:^|\.)(?:facebook\.com|fb\.com|fb\.me|fb\.watch)$/i },
    { id: "reddit", label: "Reddit", test: /(?:^|\.)(?:reddit\.com|redd\.it)$/i },
    { id: "lightshot", label: "Lightshot", test: /(?:^|\.)(?:prnt\.sc|prntscr\.com)$/i },
    { id: "dropbox", label: "Dropbox", test: /(?:^|\.)(?:dropbox\.com|db\.tt)$/i },
    { id: "discord", label: "Discord", test: /(?:^|\.)(?:discord\.com|discord\.gg|discordapp\.com|discord\.media)$/i },
    { id: "imdb", label: "IMDb", test: /(?:^|\.)imdb\.com$/i },
    { id: "pinterest", label: "Pinterest", test: /(?:^|\.)(?:pinterest\.com|pin\.it)$/i },
    { id: "whatsapp", label: "WhatsApp", test: /(?:^|\.)(?:wa\.me|whatsapp\.com|api\.whatsapp\.com)$/i },
    { id: "gdrive", label: "Google Drive", test: /(?:^|\.)drive\.google\.com$/i },
    { id: "gsheets", label: "Google Sheets", test: /(?:^|\.)docs\.google\.com$/i, path: /\/spreadsheets\//i },
    { id: "gslides", label: "Google Slides", test: /(?:^|\.)docs\.google\.com$/i, path: /\/presentation\//i },
    { id: "gforms", label: "Google Forms", test: /(?:^|\.)docs\.google\.com$/i, path: /\/forms\//i },
    { id: "gdocs", label: "Google Docs", test: /(?:^|\.)docs\.google\.com$/i, path: /\/document\//i },
    { id: "gmeet", label: "Google Meet", test: /(?:^|\.)meet\.google\.com$/i },
    { id: "vocaroo", label: "Vocaroo", test: /(?:^|\.)(?:vocaroo\.com|voca\.ro)$/i },
    { id: "clyp", label: "Clyp", test: /(?:^|\.)clyp\.it$/i },
    { id: "instagram", label: "Instagram", test: /(?:^|\.)(?:instagram\.com|instagr\.am)$/i },
    { id: "notion", label: "Notion", test: /(?:^|\.)(?:notion\.so|notion\.site)$/i },
    { id: "imgflip", label: "Imgflip", test: /(?:^|\.)imgflip\.com$/i },
  ];

  const URL_PICK_RE = /https?:\/\/[^\s<>"'`)\]]+/gi;
  const WWW_PICK_RE =
    /(?:^|[\s"'<>(])((?:www\.)[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>"'`)\]]*)?)/gi;
  const ISBN_RE =
    /\bISBN(?:-1[03])?:?\s*([0-9][0-9\-\s]{8,}[\dXx])\b/gi;
  const ONION_BARE_RE = /\b[a-z2-7]{16,56}\.onion(?:\/[^\s<>"'`)\]]*)?/gi;

  const AUDIO_EXT_RE = /\.(mp3|wav|ogg|m4a|flac|aac|webm)(?:[?#].*)?$/i;

  function isMediaUrl(raw) {
    const s = String(raw || "").trim();
    if (!s || s.startsWith("#") || s.startsWith("javascript:") || s.startsWith("data:text/")) {
      return false;
    }
    if (/^blob:/i.test(s) || /^data:audio\//i.test(s)) return true;
    let abs = s;
    try {
      abs = new URL(s, location.href).href;
    } catch (_err) {
      return AUDIO_EXT_RE.test(s);
    }
    if (AUDIO_EXT_RE.test(abs)) return true;
    if (/^data:audio\//i.test(abs)) return true;
    try {
      const u = new URL(abs);
      const path = u.pathname || "";
      if (AUDIO_EXT_RE.test(path)) return true;
    } catch (_err) {
      /* ignore */
    }
    return false;
  }

  function mediaKindFromUrl(url, tag) {
    const t = String(tag || "").toLowerCase();
    if (t === "video") return "video";
    if (t === "audio") return "audio";
    if (/\.webm$/i.test(url) && /video/i.test(t)) return "video";
    return "audio";
  }

  function collectMediaUrls() {
    const found = [];
    const seen = new Set();

    function push(raw, source, tag) {
      if (found.length >= MAX_MEDIA_URLS) return;
      let abs = String(raw || "").trim();
      if (!abs) return;
      try {
        abs = new URL(abs, location.href).href;
      } catch (_err) {
        if (!/^blob:/i.test(abs) && !/^data:audio\//i.test(abs)) return;
      }
      if (!isMediaUrl(abs)) return;
      const key = abs;
      if (seen.has(key)) return;
      seen.add(key);
      const kind = mediaKindFromUrl(abs, tag);
      const name = (() => {
        try {
          const u = new URL(abs);
          const base = (u.pathname || "").split("/").pop() || "";
          return base || kind;
        } catch (_err) {
          return kind;
        }
      })();
      found.push({
        url: abs,
        kind,
        label: kind === "video" ? "Video" : "Audio",
        preview: (kind === "video" ? "Video" : "Audio") + " · " + (name || abs).slice(0, 120),
        source,
      });
    }

    try {
      document
        .querySelectorAll("audio[src], audio source[src], video[src], video source[src], track[src]")
        .forEach((el) => {
          const src = el.getAttribute("src") || "";
          const tag = el.tagName || "";
          push(src, "dom", tag);
        });
    } catch (_err) {
      /* ignore */
    }

    try {
      document.querySelectorAll("a[href]").forEach((el) => {
        const href = el.getAttribute("href") || "";
        if (AUDIO_EXT_RE.test(href)) push(href, "link", "a");
      });
    } catch (_err) {
      /* ignore */
    }

    found.sort((a, b) => a.label.localeCompare(b.label) || a.url.localeCompare(b.url));
    return found;
  }

  const MAX_MEDIA_ALT = 40;

  function collectMediaAlt() {
    const found = [];
    const seen = new Set();
    function push(text, source, tag) {
      const t = String(text || "").trim();
      if (!t || t.length < 2 || seen.has(t) || found.length >= MAX_MEDIA_ALT) return;
      seen.add(t);
      found.push({
        text: t,
        preview: (tag ? tag + " · " : "") + t.slice(0, 120),
        source,
        tag,
      });
    }
    try {
      document.querySelectorAll("img[alt]").forEach((el) => {
        push(el.getAttribute("alt"), "img alt", "img");
      });
      document.querySelectorAll("img[title], video[title], audio[title]").forEach((el) => {
        push(el.getAttribute("title"), "media title", el.tagName.toLowerCase());
      });
      document.querySelectorAll("a[download]").forEach((el) => {
        push(el.getAttribute("download") || "", "download attr", "a");
      });
      document.querySelectorAll("img[src], video[src], audio[src]").forEach((el) => {
        const src = el.getAttribute("src") || "";
        try {
          const base = decodeURIComponent(new URL(src, location.href).pathname.split("/").pop() || "");
          if (base && base.length >= 3) push(base, "filename", el.tagName.toLowerCase());
        } catch (_err) {
          /* ignore */
        }
      });
    } catch (_err) {
      /* ignore */
    }
    return found;
  }

  function classifyBacklink(rawUrl) {
    let url = String(rawUrl || "").trim();
    if (!url) return null;
    url = url.replace(/[.,;:!?)\]]+$/g, "");
    if (!/^https?:\/\//i.test(url) && !/\.onion/i.test(url)) {
      if (/^www\./i.test(url)) url = "http://" + url;
      else return null;
    }
    if (/\.onion(?:\/|$)/i.test(url)) {
      if (!/^https?:\/\//i.test(url)) url = "http://" + url;
      return { service: "onion", label: "Onion", url };
    }

    let host = "";
    let path = "";
    try {
      const u = new URL(url);
      host = u.hostname.replace(/^www\./i, "");
      path = u.pathname || "";
    } catch (_err) {
      return null;
    }

    for (const svc of BACKLINK_SERVICES) {
      if (!svc.test.test(host)) continue;
      if (svc.path && !svc.path.test(path)) continue;
      return { service: svc.id, label: svc.label, url };
    }
    return null;
  }

  function collectBacklinks(blobs) {
    const found = [];
    const seen = new Set();

    function consider(raw, source) {
      if (found.length >= MAX_BACKLINKS) return;

      if (source === "isbn") {
        const key = "isbn:" + raw;
        if (seen.has(key)) return;
        seen.add(key);
        found.push({
          service: "isbn",
          label: "ISBN",
          text: raw,
          url: raw,
          preview: "ISBN " + raw,
          source,
        });
        return;
      }

      const hit = classifyBacklink(raw);
      if (!hit) return;
      const key = hit.service + "|" + hit.url;
      if (seen.has(key)) return;
      seen.add(key);
      found.push({
        service: hit.service,
        label: hit.label,
        text: hit.url,
        url: hit.url,
        preview: hit.label + " · " + preview(hit.url, 140),
        source,
      });
    }

    try {
      document.querySelectorAll("a[href], img[src], iframe[src], source[src], embed[src], audio[src], video[src]").forEach((el) => {
        const href = el.getAttribute("href") || el.getAttribute("src") || "";
        if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;
        let abs = href;
        try {
          abs = new URL(href, location.href).href;
        } catch (_err) {
          /* keep raw */
        }
        consider(abs, "dom");
      });
    } catch (_err) {
      /* ignore */
    }

    const corpora = [];
    for (const b of blobs || []) corpora.push(b);
    try {
      const html = document.documentElement ? document.documentElement.innerHTML : "";
      if (html) corpora.push(html.slice(0, 500000));
    } catch (_err) {
      /* ignore */
    }

    for (const blob of corpora) {
      if (found.length >= MAX_BACKLINKS) break;
      let m;
      URL_PICK_RE.lastIndex = 0;
      while ((m = URL_PICK_RE.exec(blob)) && found.length < MAX_BACKLINKS) {
        consider(m[0], "text");
      }
      WWW_PICK_RE.lastIndex = 0;
      while ((m = WWW_PICK_RE.exec(blob)) && found.length < MAX_BACKLINKS) {
        consider(m[1] || m[0], "text");
      }
      ONION_BARE_RE.lastIndex = 0;
      while ((m = ONION_BARE_RE.exec(blob)) && found.length < MAX_BACKLINKS) {
        const onion = m[0];
        consider(/^https?:\/\//i.test(onion) ? onion : "http://" + onion, "onion");
      }
      ISBN_RE.lastIndex = 0;
      while ((m = ISBN_RE.exec(blob)) && found.length < MAX_BACKLINKS) {
        const isbn = (m[1] || "").replace(/\s+/g, "").trim();
        const digits = isbn.replace(/-/g, "");
        if (digits.length === 10 || digits.length === 13) consider(isbn, "isbn");
      }
    }

    found.sort((a, b) => a.label.localeCompare(b.label) || a.url.localeCompare(b.url));
    return found;
  }

  const CANDIDATE_RE = /\b[A-Za-z0-9_-]{6,20}\b/g;
  const CANDIDATE_STOP = new Set([
    "https", "http", "typeof", "function", "return", "object", "string",
    "number", "boolean", "undefined", "document", "window", "script",
    "content", "display", "hidden", "visible", "opacity", "webkit",
    "mozilla", "firefox", "chrome", "example", "password", "username",
  ]);

  /** Prefer full Google Drive / Docs ids from the address bar (too long for CANDIDATE_RE). */
  function collectUrlPathCandidates() {
    const found = [];
    const seen = new Set();
    function push(id, hint) {
      if (!id || seen.has(id) || !/^[\w-]{25,}$/.test(id)) return;
      seen.add(id);
      found.push({ id, text: id, hint, preview: id });
    }
    try {
      const href = String(location.href || "");
      let m = href.match(
        /drive\.google\.com\/drive\/(?:u\/\d+\/)?folders\/([A-Za-z0-9_-]{25,})/i
      );
      if (m) push(m[1], "Drive folder");
      m = href.match(/drive\.google\.com\/file\/d\/([A-Za-z0-9_-]{25,})/i);
      if (m) push(m[1], "Drive file");
      m = href.match(
        /docs\.google\.com\/(?:document|spreadsheets|presentation|forms)\/(?:u\/\d+\/)?d\/([A-Za-z0-9_-]{25,})/i
      );
      if (m) {
        const kind = /spreadsheets/i.test(href)
          ? "Sheets"
          : /presentation/i.test(href)
            ? "Slides"
            : /forms/i.test(href)
              ? "Forms"
              : "Docs";
        push(m[1], kind + " id");
      }
      m = href.match(/drive\.google\.com\/(?:open|uc)\?[^#]*[?&]id=([A-Za-z0-9_-]{25,})/i);
      if (m) push(m[1], "Drive id");
    } catch (_err) {
      /* ignore */
    }
    return found;
  }

  function collectCandidates(blobs) {
    const found = collectUrlPathCandidates();
    const seen = new Set(found.map((c) => c.id));
    const counts = new Map();

    for (const blob of blobs || []) {
      CANDIDATE_RE.lastIndex = 0;
      let m;
      while ((m = CANDIDATE_RE.exec(blob))) {
        const tok = m[0];
        if (CANDIDATE_STOP.has(tok.toLowerCase())) continue;
        // Prefer mixed / numeric / pastebin-like tokens over plain English words.
        const hasDigit = /\d/.test(tok);
        const mixed = /[A-Z]/.test(tok) && /[a-z]/.test(tok);
        if (!hasDigit && !mixed && tok.length < 8) continue;
        if (/^[a-z]+$/i.test(tok) && !hasDigit && tok.length < 10) continue;
        counts.set(tok, (counts.get(tok) || 0) + 1);
      }
    }

    const ranked = Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 40);

    for (const [tok, n] of ranked) {
      if (seen.has(tok)) continue;
      seen.add(tok);
      found.push({
        id: tok,
        text: tok,
        hint: n > 1 ? "seen ×" + n : "token",
        preview: tok,
      });
    }
    return found;
  }

  // -------------------------------------------------------------------------
  // Report to background
  // -------------------------------------------------------------------------

  function scanAndReport() {
    try {
      const comments = collectComments();
      const blobs = collectTextBlobs();
      const backlinks = collectBacklinks(blobs);
      const mediaUrls = collectMediaUrls();
      const mediaAlt = collectMediaAlt();
      const candidates = collectCandidates(blobs);
      const payload = {
        type: MSG.LIVE_ASSETS,
        frameUrl: location.href,
        pageUrl: location.href,
        comments,
        base64: collectBase64(blobs),
        zeroWidth: collectZeroWidth(blobs),
        flags: collectFlags(blobs),
        meta: collectMeta(),
        revealedHidden: revealEnabled ? collectRevealedHidden() : [],
        backlinks,
        mediaUrls,
        mediaAlt,
        candidates,
      };

      const key = JSON.stringify({
        c: payload.comments.length,
        b: payload.base64.length,
        z: payload.zeroWidth.length,
        f: payload.flags.length,
        m: payload.meta.length,
        r: payload.revealedHidden.length,
        k: payload.backlinks.length,
        v: payload.mediaUrls.length,
        a: payload.mediaAlt.length,
        n: payload.candidates.length,
        u: payload.frameUrl,
        sample: (
          (payload.candidates[0] && payload.candidates[0].text) ||
          (payload.backlinks[0] && payload.backlinks[0].url) ||
          (payload.comments[0] && payload.comments[0].text) ||
          ""
        ).slice(0, 80),
      });
      if (key === lastPayloadKey) return;
      lastPayloadKey = key;

      browser.runtime.sendMessage(payload).catch(() => {});
    } catch (_err) {
      // Never throw into the page.
    }
  }

  function scheduleScan() {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(() => {
      scanTimer = 0;
      scanAndReport();
    }, SCAN_DEBOUNCE_MS);
  }

  // -------------------------------------------------------------------------
  // Reveal Hidden Layers + highlight previously invisible text
  // -------------------------------------------------------------------------

  function parseCssColor(input) {
    if (!input || input === "transparent") return { r: 0, g: 0, b: 0, a: 0 };
    const str = String(input).trim().toLowerCase();
    if (str === "transparent") return { r: 0, g: 0, b: 0, a: 0 };

    let m = str.match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)(?:\s*,\s*([\d.]+))?\s*\)$/);
    if (m) {
      return {
        r: Number(m[1]),
        g: Number(m[2]),
        b: Number(m[3]),
        a: m[4] === undefined ? 1 : Number(m[4]),
      };
    }

    // rgb(r g b / a) modern syntax — approximate via canvas when available
    try {
      const canvas = parseCssColor._c || (parseCssColor._c = document.createElement("canvas"));
      canvas.width = canvas.height = 1;
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = "#000";
        ctx.fillStyle = str;
        const filled = String(ctx.fillStyle);
        m = filled.match(/^#([0-9a-f]{6})$/i);
        if (m) {
          const hex = m[1];
          return {
            r: parseInt(hex.slice(0, 2), 16),
            g: parseInt(hex.slice(2, 4), 16),
            b: parseInt(hex.slice(4, 6), 16),
            a: 1,
          };
        }
      }
    } catch (_err) {
      /* ignore */
    }
    return null;
  }

  function relativeLuminance(c) {
    const lin = (v) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
  }

  function contrastRatio(a, b) {
    const L1 = relativeLuminance(a);
    const L2 = relativeLuminance(b);
    const hi = Math.max(L1, L2);
    const lo = Math.min(L1, L2);
    return (hi + 0.05) / (lo + 0.05);
  }

  function effectiveBackground(el) {
    let node = el;
    while (node && node.nodeType === Node.ELEMENT_NODE) {
      const cs = getComputedStyle(node);
      const bg = parseCssColor(cs.backgroundColor);
      if (bg && bg.a > 0.08) return bg;
      node = node.parentElement;
    }
    // CTF pages often paint black via a wrapper while html/body stay "transparent".
    // Guess dark canvas when most of the viewport sits on a dark opaque layer.
    if (pageLooksDark()) return { r: 0, g: 0, b: 0, a: 1 };
    return { r: 255, g: 255, b: 255, a: 1 };
  }

  function pageLooksDark() {
    if (pageLooksDark._cached != null) return pageLooksDark._cached;
    let darkArea = 0;
    const nodes = [];
    if (document.documentElement) nodes.push(document.documentElement);
    if (document.body) nodes.push(document.body);
    try {
      const kids = document.body ? document.body.children : [];
      for (let i = 0; i < kids.length && i < 16; i++) nodes.push(kids[i]);
    } catch (_err) {
      /* ignore */
    }

    for (let i = 0; i < nodes.length; i++) {
      const el = nodes[i];
      let cs;
      try {
        cs = getComputedStyle(el);
      } catch (_err) {
        continue;
      }
      const bg = parseCssColor(cs.backgroundColor);
      if (!bg || bg.a < 0.45) continue;
      if (relativeLuminance(bg) >= 0.28) continue;
      const rect = el.getBoundingClientRect();
      darkArea += Math.max(0, rect.width) * Math.max(0, rect.height);
    }

    const viewport = Math.max(1, window.innerWidth * window.innerHeight);
    pageLooksDark._cached = darkArea >= viewport * 0.3;
    return pageLooksDark._cached;
  }

  function ownText(el) {
    let out = "";
    for (let i = 0; i < el.childNodes.length; i++) {
      const n = el.childNodes[i];
      if (n.nodeType === Node.TEXT_NODE) out += n.nodeValue || "";
    }
    return out.replace(/\s+/g, " ").trim();
  }

  function hiddenNameHint(el) {
    try {
      if (el.classList && el.classList.length) {
        for (let i = 0; i < el.classList.length; i++) {
          const c = el.classList.item(i) || "";
          if (/unhidden|not-hidden|is-visible|nohide/i.test(c)) continue;
          if (
            /hidden|invisible|spoiler|conceal|visually-hidden|sr-only/i.test(c)
          ) {
            return "class ." + c;
          }
        }
      }
    } catch (_err) {
      /* ignore */
    }
    const id = el.id || "";
    if (id && /hidden|invisible|spoiler|conceal/i.test(id) && !/unhidden/i.test(id)) {
      return "id #" + id;
    }
    return "";
  }

  /** Direct text, or shallow textContent for class-tagged hunt nodes. */
  function relevantText(el) {
    const direct = ownText(el);
    if (direct) return direct;
    if (!hiddenNameHint(el) && !el.hasAttribute("hidden")) return "";
    if (el.children && el.children.length > 3) return "";
    const all = (el.textContent || "").replace(/\s+/g, " ").trim();
    if (!all || all.length > 280) return "";
    return all;
  }

  function nearBlack(c) {
    return c && c.a > 0.5 && relativeLuminance(c) < 0.08;
  }

  function nearWhite(c) {
    return c && c.a > 0.5 && relativeLuminance(c) > 0.9;
  }

  function colorsMatch(a, b, tol) {
    if (!a || !b) return false;
    const t = tol == null ? 10 : tol;
    return (
      Math.abs(a.r - b.r) <= t &&
      Math.abs(a.g - b.g) <= t &&
      Math.abs(a.b - b.b) <= t &&
      a.a > 0.5 &&
      b.a > 0.5
    );
  }

  /** Backdrop that actually sits behind the glyphs — not distant page chrome. */
  function firstOpaqueBackground(el) {
    let node = el;
    while (node && node.nodeType === Node.ELEMENT_NODE) {
      const bg = parseCssColor(getComputedStyle(node).backgroundColor);
      if (bg && bg.a > 0.45) return bg;
      node = node.parentElement;
    }
    if (pageLooksDark()) return { r: 0, g: 0, b: 0, a: 1 };
    return { r: 255, g: 255, b: 255, a: 1 };
  }

  function whyInvisible(el) {
    if (!(el instanceof Element)) return "";
    if (SKIP_REVEAL_TAGS.has(el.tagName)) return "";
    if (el.id === STYLE_ID) return "";

    const nameHint = hiddenNameHint(el);
    const text = relevantText(el);
    if (!text) return "";

    if (el.hasAttribute("hidden")) return "hidden attr";

    let cs;
    try {
      cs = getComputedStyle(el);
    } catch (_err) {
      return nameHint;
    }
    if (!cs) return nameHint;

    if (cs.display === "none") return "display:none";
    if (cs.visibility === "hidden" || cs.visibility === "collapse") return "visibility";
    if (el.getAttribute("aria-hidden") === "true") return "aria-hidden";

    const opacity = Number(cs.opacity);
    if (!Number.isNaN(opacity) && opacity <= 0.05) return "opacity:0";

    const fontSize = parseFloat(cs.fontSize);
    if (!Number.isNaN(fontSize) && fontSize > 0 && fontSize <= 1.5) return "tiny text";

    // .sp-hidden etc. — check before contrast so we never miss tagged clues.
    if (nameHint) return nameHint;

    const fillRaw = (cs.webkitTextFillColor || "").toLowerCase();
    if (
      fillRaw === "transparent" ||
      fillRaw.includes("0, 0, 0, 0") ||
      fillRaw.includes("0,0,0,0")
    ) {
      return "transparent fill";
    }

    const color = parseCssColor(cs.color);
    const fill = parseCssColor(cs.webkitTextFillColor || "");
    const ink = fill && fill.a > 0.08 ? fill : color;
    if (color && color.a <= 0.08) return "transparent color";
    if (!ink || ink.a <= 0.08) return "";

    // Compare only to the first opaque backdrop (fixes white-on-dark buttons
    // being flagged because body was light).
    const bg = firstOpaqueBackground(el);
    if (colorsMatch(ink, bg, 12)) return "same as bg";
    if (contrastRatio(ink, bg) < 1.45) return "low contrast";

    if (nearBlack(ink) && pageLooksDark() && contrastRatio(ink, bg) < 2.2) {
      return "black on dark";
    }
    if (nearWhite(ink) && !pageLooksDark() && contrastRatio(ink, bg) < 1.8) {
      return "white on light";
    }

    const clip = (cs.clip || "") + " " + (cs.clipPath || "");
    if (/rect\(\s*0/i.test(clip) || clip.includes("inset(50%)") || clip.includes("inset(100%)")) {
      return "clipped";
    }

    return "";
  }

  function markWasHidden(el, reason) {
    el.setAttribute(ATTR_WAS_HIDDEN, "1");
    el.setAttribute(ATTR_REASON, reason);
    for (const [prop, value] of HIGHLIGHT_INLINE_PROPS) {
      try {
        el.style.setProperty(prop, value, "important");
      } catch (_err) {
        /* ignore */
      }
    }
    if (!revealedNodes.includes(el)) revealedNodes.push(el);
  }

  function clearWasHiddenMarks() {
    const marked = document.querySelectorAll("[" + ATTR_WAS_HIDDEN + "]");
    for (let i = 0; i < marked.length; i++) {
      const el = marked[i];
      el.removeAttribute(ATTR_WAS_HIDDEN);
      el.removeAttribute(ATTR_REASON);
      for (const [prop] of HIGHLIGHT_INLINE_PROPS) {
        try {
          el.style.removeProperty(prop);
        } catch (_err) {
          /* ignore */
        }
      }
    }
    revealedNodes = [];
  }

  function findInvisibleBeforeReveal(root) {
    pageLooksDark._cached = null;
    const hits = [];
    const seen = new Set();
    const candidates = [];

    if (root && root.nodeType === Node.ELEMENT_NODE) candidates.push(root);
    const scope = root && root.querySelectorAll ? root : document.documentElement;
    if (scope && scope.querySelectorAll) {
      const nodes = scope.querySelectorAll("*");
      for (let i = 0; i < nodes.length; i++) candidates.push(nodes[i]);
    }

    function pushHit(el, reason, text) {
      if (seen.has(el) || hits.length >= MAX_REVEALED) return;
      seen.add(el);
      hits.push({
        el,
        reason,
        text: text || relevantText(el) || ownText(el),
      });
    }

    for (let i = 0; i < candidates.length && hits.length < MAX_REVEALED; i++) {
      const el = candidates[i];
      const reason = whyInvisible(el);
      if (!reason) continue;
      pushHit(el, reason);
    }

    // Explicit pass for class*="hidden" so .sp-hidden never slips through.
    if (scope && scope.querySelectorAll) {
      let tagged = [];
      try {
        tagged = scope.querySelectorAll(
          '[class*="hidden"], [class*="Hidden"], [class*="invisible"], [class*="spoiler"]'
        );
      } catch (_err) {
        tagged = [];
      }
      for (let i = 0; i < tagged.length && hits.length < MAX_REVEALED; i++) {
        const el = tagged[i];
        if (seen.has(el)) continue;
        if (el === document.body || el === document.documentElement) continue;
        const hint = hiddenNameHint(el);
        if (!hint) continue;
        const text = relevantText(el);
        if (!text) continue;
        pushHit(el, hint, text);
      }
    }

    return hits;
  }

  function paintElement(el, opts) {
    if (!(el instanceof Element)) return;
    if (el.id === STYLE_ID) return;
    if (SKIP_REVEAL_TAGS.has(el.tagName)) return;

    const wasHidden = opts && opts.wasHidden;
    const props = wasHidden
      ? REVEAL_INLINE_PROPS.filter(([prop]) => prop !== "background" && prop !== "background-color")
      : REVEAL_INLINE_PROPS;

    for (const [prop, value] of props) {
      try {
        el.style.setProperty(prop, value, "important");
      } catch (_err) {
        // Some props (e.g. -webkit-*) may be rejected in odd hosts.
      }
    }
    if (el.hasAttribute("hidden")) el.removeAttribute("hidden");
    if (el.getAttribute("aria-hidden") === "true") el.setAttribute("aria-hidden", "false");
    revealTouched.add(el);
  }

  function paintTree(root) {
    if (!root) return;
    // Detect BEFORE forcing styles, otherwise everything looks "visible".
    const hits = findInvisibleBeforeReveal(root.nodeType === Node.ELEMENT_NODE ? root : document);
    const hitSet = new Map();
    for (const hit of hits) hitSet.set(hit.el, hit.reason);

    if (root.nodeType === Node.ELEMENT_NODE) {
      paintElement(root, { wasHidden: hitSet.has(root) });
    }
    const nodes = root.querySelectorAll ? root.querySelectorAll("*") : [];
    for (let i = 0; i < nodes.length; i++) {
      paintElement(nodes[i], { wasHidden: hitSet.has(nodes[i]) });
    }

    for (const hit of hits) {
      markWasHidden(hit.el, hit.reason);
    }

    return hits;
  }

  function collectRevealedHidden() {
    const found = [];
    for (let i = 0; i < revealedNodes.length && found.length < MAX_REVEALED; i++) {
      const el = revealedNodes[i];
      if (!el.isConnected) continue;
      const text = ownText(el) || (el.textContent || "").replace(/\s+/g, " ").trim();
      if (!text) continue;
      found.push({
        text,
        preview: preview(text, 180),
        reason: el.getAttribute(ATTR_REASON) || "hidden",
      });
    }
    return found;
  }

  function clearRevealInline() {
    const all = document.querySelectorAll("*");
    for (let i = 0; i < all.length; i++) {
      const el = all[i];
      if (!revealTouched.has(el)) continue;
      for (const [prop] of REVEAL_INLINE_PROPS) {
        try {
          el.style.removeProperty(prop);
        } catch (_err) {
          /* ignore */
        }
      }
    }
    revealTouched = new WeakSet();
    clearWasHiddenMarks();
  }

  function stopRevealObserver() {
    if (revealObserver) {
      revealObserver.disconnect();
      revealObserver = null;
    }
    if (revealMutationTimer) {
      clearTimeout(revealMutationTimer);
      revealMutationTimer = 0;
    }
  }

  function startRevealObserver() {
    stopRevealObserver();
    revealObserver = new MutationObserver((mutations) => {
      if (!revealEnabled) return;
      if (revealMutationTimer) clearTimeout(revealMutationTimer);
      revealMutationTimer = setTimeout(() => {
        revealMutationTimer = 0;
        for (const m of mutations) {
          if (m.type === "childList") {
            m.addedNodes.forEach((n) => {
              if (n.nodeType === Node.ELEMENT_NODE || (n.querySelectorAll && n.childNodes)) {
                paintTree(n);
              }
            });
          } else if (m.type === "attributes" && m.target instanceof Element) {
            if (m.attributeName === ATTR_WAS_HIDDEN || m.attributeName === ATTR_REASON) return;
            const reason = whyInvisible(m.target);
            paintElement(m.target, { wasHidden: Boolean(reason) });
            if (reason) markWasHidden(m.target, reason);
          }
        }
        lastPayloadKey = "";
        scanAndReport();
      }, 80);
    });
    const root = document.documentElement || document.body;
    if (root) {
      revealObserver.observe(root, {
        subtree: true,
        childList: true,
        attributes: true,
        // Omit "style" — we write inline styles ourselves and would feedback-loop.
        attributeFilter: ["class", "hidden", "aria-hidden"],
      });
    }
  }

  function applyReveal(enabled) {
    revealEnabled = Boolean(enabled);
    pageLooksDark._cached = null;
    const existing = document.getElementById(STYLE_ID);

    if (!revealEnabled) {
      stopRevealObserver();
      clearRevealInline();
      if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
      lastPayloadKey = "";
      scanAndReport();
      return;
    }

    // Always strip prior reveal styling first so detection sees the page's real CSS
    // (.sp-hidden black-on-black, etc.). Leaving the stylesheet on caused misses and
    // also false "same as bg" hits on already-forced green/black nodes.
    stopRevealObserver();
    clearRevealInline();
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);

    const hits = findInvisibleBeforeReveal(document.documentElement);

    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = REVEAL_CSS;
    (document.head || document.documentElement).appendChild(style);

    const hitSet = new Map();
    for (const hit of hits) hitSet.set(hit.el, hit.reason);

    paintElement(document.documentElement, {
      wasHidden: hitSet.has(document.documentElement),
    });
    const nodes = document.documentElement
      ? document.documentElement.querySelectorAll("*")
      : [];
    for (let i = 0; i < nodes.length; i++) {
      paintElement(nodes[i], { wasHidden: hitSet.has(nodes[i]) });
    }
    for (const hit of hits) {
      markWasHidden(hit.el, hit.reason);
    }

    startRevealObserver();
    lastPayloadKey = "";
    scanAndReport();
  }

  function syncRevealFromBackground() {
    browser.runtime
      .sendMessage({ type: MSG.GET_REVEAL })
      .then((res) => {
        if (res && res.enabled) applyReveal(true);
      })
      .catch(() => {});
  }

  // -------------------------------------------------------------------------
  // Messages from the event page
  // -------------------------------------------------------------------------

  function probePageCheck(message) {
    const id = String((message && message.id) || "");
    const host = String((message && message.host) || "");
    const href = String(location.href || "");
    const title = String(document.title || "");
    const text = String((document.body && document.body.innerText) || "").slice(0, 8000);
    const html = String((document.documentElement && document.documentElement.innerHTML) || "").slice(
      0,
      120000
    );

    if (host === "pinterest") {
      const missingRe =
        /page not found|pin not found|something went wrong|hmm,? we can.?t find|couldn.?t find that page|no pin found/i;
      const missing = missingRe.test(title) || missingRe.test(text.slice(0, 2500));
      const pinImg = Boolean(
        document.querySelector(
          '[data-test-id="pin-closeup-image"], [data-test-id="CloseupImage"], [data-test-id="pinrep-image"], img[src*="pinimg.com/originals"], img[src*="pinimg.com/736x"], img[src*="i.pinimg.com"]'
        )
      );
      const pinMeta =
        /og:type["'\s]+content=["']pinterestapp:pin|property=["']og:image["']/i.test(html) ||
        html.indexOf("pinimg.com/originals") !== -1 ||
        html.indexOf('"grid_title"') !== -1;
      const idInPage = !id || href.indexOf(id) !== -1 || html.indexOf(id) !== -1;
      const exists = !missing && idInPage && (pinImg || pinMeta);
      return {
        host,
        href,
        title,
        status: 200,
        exists,
        missing: missing || (!exists && /login|sign up to see/i.test(text.slice(0, 400))),
        blocked: false,
      };
    }

    // Generic fallback for future tab hosts
    const soft =
      /page not found|not found|doesn.?t exist|content isn.?t available|video unavailable/i.test(
        title + " " + text.slice(0, 1500)
      );
    return {
      host,
      href,
      title,
      status: 200,
      exists: !soft && (!id || href.indexOf(id) !== -1),
      missing: soft,
      blocked: false,
    };
  }

  browser.runtime.onMessage.addListener((message) => {
    if (!message || !message.type) return;
    if (message.type === MSG.APPLY_REVEAL) {
      applyReveal(Boolean(message.enabled));
    } else if (message.type === MSG.RESCAN) {
      lastPayloadKey = "";
      scanAndReport();
    } else if (message.type === MSG.PROBE_PAGE_CHECK) {
      return Promise.resolve(probePageCheck(message));
    }
  });

  // -------------------------------------------------------------------------
  // Auto-decode selection → Cipher Clipboard (heuristic-gated)
  // Auto-probe selection → hunt-site backlink fast path (background)
  // -------------------------------------------------------------------------

  let autoDecodeEnabled = true;
  let autoProbeHuntEnabled = true;
  let autoDecodeTimer = 0;
  /** @type {Map<string, number>} */
  const autoProbeTimers = new Map();
  let lastAutoDecodeSent = "";
  const AUTO_PROBE_TOKEN_GAP_MS = 120;

  function looksEncoded(raw) {
    const t = String(raw || "").trim();
    if (t.length < AUTO_DECODE_MIN || t.length > AUTO_DECODE_MAX) return false;

    // Morse: dots/dashes/slashes (and common bullet variants)
    const morseBody = t.replace(/\s+/g, " ").trim();
    if (
      /^[.\-_•·/\s|]+$/.test(morseBody) &&
      /[.\-_•·]/.test(morseBody) &&
      morseBody.replace(/[\s|/]/g, "").length >= 4
    ) {
      return true;
    }

    // Binary groups (8-bit runs or compact bitstream)
    const binCompact = t.replace(/[\s,_|]+/g, "");
    if (/^[01]+$/.test(binCompact) && binCompact.length >= 8 && binCompact.length % 8 === 0) {
      return true;
    }
    if (/(?:^|[\s,|_])[01]{8}(?:[\s,|_]+[01]{8})+/.test(t)) return true;

    // Short / unaligned binary → Morse (e.g. 0101 → ·−·−)
    if (/^[01]+$/.test(binCompact) && binCompact.length >= 2 && binCompact.length < 8) {
      return true;
    }
    if (
      /^[01]+$/.test(binCompact) &&
      binCompact.length >= 8 &&
      binCompact.length % 8 !== 0
    ) {
      return true;
    }
    if (
      /^(?:[01]{1,12}[\s/]+)+[01]{1,12}$/.test(t.trim()) ||
      /^[01]{1,12}(?:[\s/]+[01]{1,12})+$/.test(t.trim())
    ) {
      return true;
    }

    // Hex dump / hex string
    const hexCompact = t.replace(/0x/gi, "").replace(/[\s:_,\-]+/g, "");
    if (
      /^[0-9a-fA-F]+$/.test(hexCompact) &&
      hexCompact.length >= 6 &&
      hexCompact.length % 2 === 0 &&
      (/[a-fA-F]/.test(hexCompact) || hexCompact.length >= 8)
    ) {
      return true;
    }

    // Ternary / base-3 groups (digits 0–2; often 5-trit ASCII)
    const ternTokens = t.trim().split(/[\s,;|/\\]+/).filter(Boolean);
    if (
      ternTokens.length >= 2 &&
      ternTokens.every((p) => /^[0-2]{2,12}$/.test(p)) &&
      (/2/.test(ternTokens.join("")) ||
        ternTokens.every((p) => p.length >= 3 && p.length <= 6))
    ) {
      return true;
    }
    const ternCompact = t.replace(/[\s,;|/\\]+/g, "");
    if (
      /^[0-2]+$/.test(ternCompact) &&
      /2/.test(ternCompact) &&
      ternCompact.length >= 10 &&
      (ternCompact.length % 5 === 0 ||
        ternCompact.length % 4 === 0 ||
        ternCompact.length % 3 === 0)
    ) {
      return true;
    }

    // Tokenized numeric codes (octal / decimal / A1Z26)
    const numTokens = t.trim().split(/[\s,;|/]+/).filter(Boolean);
    if (numTokens.length >= 3 && numTokens.every((p) => /^\d{1,3}$/.test(p))) {
      const vals = numTokens.map((p) => Number(p));
      const allOctish = numTokens.every((p) => /^[0-7]{1,3}$/.test(p) && Number(p) <= 255);
      const allAscii = vals.every((n) => n >= 0 && n <= 255);
      const allA1 = vals.every((n) => n >= 1 && n <= 26);
      if (allOctish || allAscii || allA1) return true;
    }

    // Bacon cipher (A/B groups, length multiple of 5)
    const bacon = t.replace(/[\s|/]+/g, "");
    if (/^[ABab]+$/.test(bacon) && bacon.length >= 10 && bacon.length % 5 === 0) {
      const a = (bacon.match(/[Aa]/g) || []).length;
      const b = (bacon.match(/[Bb]/g) || []).length;
      if (a > 0 && b > 0) return true;
    }

    // URL-encoded payload
    const pct = t.match(/%[0-9A-Fa-f]{2}/g);
    if (pct && pct.length >= 2 && pct.join("").length >= t.replace(/\s+/g, "").length * 0.35) {
      return true;
    }

    // Base64-ish (mixed alphabet / padding / +/) — reject plain words
    const b64 = t.replace(/\s+/g, "");
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(b64) && b64.length >= 8) {
      const hasDigit = /\d/.test(b64);
      const hasUpper = /[A-Z]/.test(b64);
      const hasLower = /[a-z]/.test(b64);
      const hasPlus = /[+/]/.test(b64);
      const padded = /=+$/.test(b64);
      if (padded || hasPlus) return true;
      if (hasUpper && hasLower && hasDigit && b64.length >= 12) return true;
      if (hasUpper && hasLower && hasDigit && b64.length >= 8 && b64.length % 4 === 0) {
        return true;
      }
    }

    return false;
  }

  function readSelectionText() {
    try {
      const sel = window.getSelection();
      if (!sel) return "";
      return String(sel.toString() || "").trim();
    } catch (_err) {
      return "";
    }
  }

  function normalizeSelectionForProbe(raw) {
    let s = String(raw || "").trim();
    if (!s) return "";
    s = s.replace(/^[\s"'<(]+|[\s"'?)!.,;:>]+$/g, "");
    return s;
  }

  function looksHuntProbeable(raw) {
    const t = normalizeSelectionForProbe(raw);
    if (t.length < AUTO_PROBE_MIN || t.length > AUTO_PROBE_MAX) return false;
    if (/\s/.test(t)) return false;
    return /^[A-Za-z0-9_-]+$/.test(t);
  }

  function sendHuntProbeSelection(raw) {
    if (!autoProbeHuntEnabled) return;
    const text = normalizeSelectionForProbe(raw);
    if (!text || !looksHuntProbeable(text)) return;

    browser.runtime
      .sendMessage({
        type: MSG.AUTO_PROBE_SELECTION,
        text,
        pageUrl: location.href,
      })
      .catch(() => {});
  }

  function scheduleAutoProbeForToken(raw) {
    const text = normalizeSelectionForProbe(raw);
    if (!text || !looksHuntProbeable(text)) return;

    const key = text.toLowerCase();
    const existing = autoProbeTimers.get(key);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(() => {
      autoProbeTimers.delete(key);
      sendHuntProbeSelection(text);
    }, AUTO_PROBE_TOKEN_GAP_MS);
    autoProbeTimers.set(key, timer);
  }

  function maybeSendSelection() {
    if (!autoDecodeEnabled) return;
    const text = readSelectionText();
    if (!text || text.length < AUTO_DECODE_MIN || text.length > AUTO_DECODE_MAX) return;
    if (text === lastAutoDecodeSent) return;
    if (!looksEncoded(text)) return;

    lastAutoDecodeSent = text;
    browser.runtime
      .sendMessage({ type: MSG.CIPHER_INPUT, text, auto: true })
      .catch(() => {});
  }

  function scheduleAutoDecode() {
    if (autoDecodeTimer) clearTimeout(autoDecodeTimer);
    autoDecodeTimer = setTimeout(() => {
      autoDecodeTimer = 0;
      maybeSendSelection();
    }, AUTO_DECODE_DEBOUNCE_MS);
  }

  function onSelectionGesture(ev) {
    // Ignore modifier-only noise on keyup except keys that move the caret/selection.
    if (ev && ev.type === "keyup") {
      const k = ev.key || "";
      if (
        !ev.shiftKey &&
        k !== "ArrowLeft" &&
        k !== "ArrowRight" &&
        k !== "ArrowUp" &&
        k !== "ArrowDown" &&
        k !== "Home" &&
        k !== "End" &&
        k !== "PageUp" &&
        k !== "PageDown" &&
        k !== "A" &&
        k !== "a"
      ) {
        // Still allow Ctrl/Cmd+A and Shift+arrows (shiftKey true above).
        if (!(ev.ctrlKey || ev.metaKey) || (k !== "A" && k !== "a")) return;
      }
    }
    const captured = readSelectionText();
    scheduleAutoDecode();
    if (captured) scheduleAutoProbeForToken(captured);
  }

  async function loadAutoSelectionSettings() {
    try {
      const bag = await browser.storage.local.get([
        AUTO_DECODE_KEY,
        AUTO_PROBE_HUNT_KEY,
      ]);
      if (typeof bag[AUTO_DECODE_KEY] === "boolean") {
        autoDecodeEnabled = bag[AUTO_DECODE_KEY];
      } else {
        autoDecodeEnabled = true;
      }
      if (typeof bag[AUTO_PROBE_HUNT_KEY] === "boolean") {
        autoProbeHuntEnabled = bag[AUTO_PROBE_HUNT_KEY];
      } else {
        autoProbeHuntEnabled = true;
      }
    } catch (_err) {
      autoDecodeEnabled = true;
      autoProbeHuntEnabled = true;
    }
  }

  try {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area !== "local") return;
      if (changes[AUTO_DECODE_KEY]) {
        const next = changes[AUTO_DECODE_KEY].newValue;
        autoDecodeEnabled = typeof next === "boolean" ? next : true;
        if (!autoDecodeEnabled) lastAutoDecodeSent = "";
      }
      if (changes[AUTO_PROBE_HUNT_KEY]) {
        const next = changes[AUTO_PROBE_HUNT_KEY].newValue;
        autoProbeHuntEnabled = typeof next === "boolean" ? next : true;
        if (!autoProbeHuntEnabled) {
          for (const t of autoProbeTimers.values()) clearTimeout(t);
          autoProbeTimers.clear();
        }
      }
    });
  } catch (_err) {
    /* ignore */
  }

  document.addEventListener("mouseup", onSelectionGesture, true);
  document.addEventListener("keyup", onSelectionGesture, true);

  // -------------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------------

  syncRevealFromBackground();
  loadAutoSelectionSettings();
  scanAndReport();

  const observer = new MutationObserver(() => scheduleScan());
  const root = document.documentElement || document.body;
  if (root) {
    observer.observe(root, {
      subtree: true,
      childList: true,
      characterData: true,
    });
  }
})();
