/**
 * The Hunt Engine — background event page (Firefox MV3).
 *
 * Responsibilities:
 *   - Context menu: "Send to Hunt Engine"
 *   - Passive redirect-chain logging (webRequest + webNavigation)
 *   - Message hub between content scripts and the sidebar
 *   - session storage so state survives event-page sleep
 *
 * Firefox uses background.scripts (event page). Chrome would use the
 * service_worker key in the same manifest; this file is written to work as both.
 */

"use strict";

// Chrome service_worker path: load shared ZIP helper when not already present
// (Firefox loads it via background.scripts before this file).
if (typeof importScripts === "function" && typeof ZIP_ARCHIVE === "undefined") {
  try {
    importScripts("zip-archive.js");
  } catch (_err) {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// Message / storage contracts (keep in sync with sidebar.js + content.js)
// ---------------------------------------------------------------------------

const MSG = {
  LIVE_ASSETS: "LIVE_ASSETS",
  TOGGLE_REVEAL: "TOGGLE_REVEAL",
  APPLY_REVEAL: "APPLY_REVEAL",
  GET_REVEAL: "GET_REVEAL",
  RESCAN: "RESCAN",
  GET_STATE: "GET_STATE",
  STATE: "STATE",
  CIPHER_INPUT: "CIPHER_INPUT",
  PROBE_BACKLINK: "PROBE_BACKLINK",
  PROBE_PROGRESS: "PROBE_PROGRESS",
  PROBE_RESULT: "PROBE_RESULT",
  PROBE_PAGE_CHECK: "PROBE_PAGE_CHECK",
  PIN_HUNT_BASE: "PIN_HUNT_BASE",
  CLEAR_HUNT_BASE: "CLEAR_HUNT_BASE",
  FETCH_SITE_DISCOVERY: "FETCH_SITE_DISCOVERY",
  IMAGE_ASSET: "IMAGE_ASSET",
  IMAGE_FORENSICS: "IMAGE_FORENSICS",
  IMAGE_HEX: "IMAGE_HEX",
  IMAGE_HEX_PATCH: "IMAGE_HEX_PATCH",
  IMAGE_EXTRACT_PART: "IMAGE_EXTRACT_PART",
  IMAGE_META: "IMAGE_META",
  STEGSTRUCK_SCAN: "STEGSTRUCK_SCAN",
  AUDIO_ASSET: "AUDIO_ASSET",
  AUDIO_ANALYZE: "AUDIO_ANALYZE",
  AUDIO_CAPTURE: "AUDIO_CAPTURE",
  OPEN_URL: "OPEN_URL",
  DNS_LOOKUP: "DNS_LOOKUP",
  DNS_RESULT: "DNS_RESULT",
  DNS_INPUT: "DNS_INPUT",
  GEOHASH_INPUT: "GEOHASH_INPUT",
  ARCHIVE_INFO: "ARCHIVE_INFO",
  ANALYZE_ARCHIVE: "ANALYZE_ARCHIVE",
  CLEAR_PENDING_INGEST: "CLEAR_PENDING_INGEST",
};

const STORE = {
  ASSETS: "assetsByTab",
  REVEAL: "revealByTab",
  REDIRECTS: "redirectLog",
  HEADERS: "responseHeadersByTab",
  CIPHER: "cipherInput",
  PROBE: "backlinkProbe",
  HUNT_BASE: "huntBase",
  IMAGE: "imageAsset", // { url, pageUrl, capturedAt }
  AUDIO: "audioAsset",
  ARCHIVE: "archiveInfo", // last ZIP/archive inspect result
};

/** Re-fetch cap for audio download / URL analysis (~8 MB). */
const AUDIO_MAX_BYTES = 8 * 1024 * 1024;

/** Re-fetch cap for download / URL archive inspection (~16 MB). */
const ARCHIVE_MAX_BYTES = 16 * 1024 * 1024;
/** Re-fetch cap for text download → Cipher (~512 KB). */
const TEXT_INGEST_MAX_BYTES = 512 * 1024;
/** storage.local — default ON when unset. */
const AUTO_INGEST_KEY = "autoIngestDownloads";

const MENU_CIPHER = "send-to-hunt-engine";
const MENU_PROBE = "probe-backlink-id";
const MENU_PROBE_USER = "probe-username";
const MENU_DNS = "dns-lookup-hunt";
const MENU_GEOHASH = "geohash-resolve-hunt";
const MENU_IMG_SEND = "image-send-hunt";
const MENU_IMG_LENS = "image-reverse-lens";
const MENU_IMG_YANDEX = "image-reverse-yandex";
const MENU_IMG_TINEYE = "image-reverse-tineye";
const MENU_IMG_FORENSICS = "image-forensics-tools";
const MENU_IMG_PROBE = "image-probe-token";
const MENU_IMG_STEGSTRUCK = "image-stegstruck";
const MENU_AUDIO_SEND = "audio-send-hunt";

/** Local StegStruck pipeline (must be running separately). */
const STEGSTRUCK_BASE = "http://127.0.0.1:8745";
const STEGSTRUCK_MAX_BYTES = 16 * 1024 * 1024;
const MENU_AUDIO_PROBE = "audio-probe-token";
const MENU_LINK_AUDIO = "link-audio-hunt";
const MAX_CHAINS = 40;
const INTERNAL_URL = /^(about:|moz-extension:|chrome:|resource:|devtools:)/i;

/** In-flight redirect chains keyed by tabId. Fast path; also mirrored to session. */
const activeChains = new Map();

/** Last main-frame URL that finished loading, used to stitch post-load client redirects. */
const lastLanded = new Map();

// ---------------------------------------------------------------------------
// session storage helpers (event pages must not rely on RAM alone)
// ---------------------------------------------------------------------------

async function storeGet(key, fallback) {
  try {
    const bag = await browser.storage.session.get(key);
    return bag[key] !== undefined ? bag[key] : fallback;
  } catch (_err) {
    return fallback;
  }
}

async function storeSet(key, value) {
  await browser.storage.session.set({ [key]: value });
}

async function patchMap(key, mutator, fallback) {
  const current = await storeGet(key, fallback);
  const next = mutator(current);
  await storeSet(key, next);
  return next;
}

// ---------------------------------------------------------------------------
// Sidebar broadcast — fails quietly when the panel is closed
// ---------------------------------------------------------------------------

async function notifySidebar(message) {
  try {
    await browser.runtime.sendMessage(message);
    return true;
  } catch (_err) {
    // No receiving end (sidebar closed). State is still in session storage.
    return false;
  }
}

function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Sidebar may still be booting after sidebarAction.open — retry a few times.
 * Session storage remains the source of truth for cold start via GET_STATE.
 */
async function notifySidebarReliable(message, attempts) {
  const n = typeof attempts === "number" ? attempts : 4;
  let ok = false;
  for (let i = 0; i < n; i++) {
    if (i > 0) await sleepMs(120 * i);
    ok = (await notifySidebar(message)) || ok;
    if (ok && i >= 1) break;
  }
  return ok;
}

async function buildState(tabId) {
  const [
    assetsByTab,
    revealByTab,
    redirectLog,
    headersByTab,
    cipherInput,
    probe,
    huntBase,
    imageAsset,
    archiveInfo,
    audioAsset,
  ] = await Promise.all([
    storeGet(STORE.ASSETS, {}),
    storeGet(STORE.REVEAL, {}),
    storeGet(STORE.REDIRECTS, []),
    storeGet(STORE.HEADERS, {}),
    storeGet(STORE.CIPHER, ""),
    storeGet(STORE.PROBE, null),
    storeGetLocal(STORE.HUNT_BASE, null),
    storeGet(STORE.IMAGE, null),
    storeGet(STORE.ARCHIVE, null),
    storeGet(STORE.AUDIO, null),
  ]);

  let tab = null;
  try {
    tab = tabId ? await browser.tabs.get(tabId) : null;
  } catch (_err) {
    tab = null;
  }

  return {
    type: MSG.STATE,
    tabId: tabId || null,
    pageUrl: tab ? tab.url : "",
    pageTitle: tab ? tab.title : "",
    revealEnabled: Boolean(revealByTab[tabId]),
    assets: flattenAssets(assetsByTab[tabId]),
    redirectLog,
    responseHeaders: tabId != null ? headersByTab[tabId] || null : null,
    cipherInput,
    probe,
    huntBase: normalizeHuntBase(huntBase),
    imageAsset,
    archiveInfo,
    audioAsset,
  };
}

async function storeGetLocal(key, fallback) {
  try {
    const bag = await browser.storage.local.get(key);
    return bag[key] !== undefined ? bag[key] : fallback;
  } catch (_err) {
    return fallback;
  }
}

async function storeSetLocal(key, value) {
  await browser.storage.local.set({ [key]: value });
}

async function pushState(tabId) {
  const state = await buildState(tabId);
  await notifySidebar(state);
  return state;
}

function flattenAssets(tabAssets) {
  const empty = {
    comments: [],
    base64: [],
    zeroWidth: [],
    flags: [],
    meta: [],
    revealedHidden: [],
    backlinks: [],
    mediaUrls: [],
    candidates: [],
    pageUrl: "",
    updatedAt: 0,
  };
  if (!tabAssets || !tabAssets.frames) return empty;

  const comments = [];
  const base64 = [];
  const zeroWidth = [];
  const flags = [];
  const meta = [];
  const revealedHidden = [];
  const backlinks = [];
  const mediaUrls = [];
  const candidates = [];

  for (const [frameKey, payload] of Object.entries(tabAssets.frames)) {
    const frame = payload.frameUrl || frameKey;
    for (const item of payload.comments || []) {
      comments.push({ ...item, frame });
    }
    for (const item of payload.base64 || []) {
      base64.push({ ...item, frame });
    }
    for (const item of payload.zeroWidth || []) {
      zeroWidth.push({ ...item, frame });
    }
    for (const item of payload.flags || []) {
      flags.push({ ...item, frame });
    }
    for (const item of payload.meta || []) {
      meta.push({ ...item, frame });
    }
    for (const item of payload.revealedHidden || []) {
      revealedHidden.push({ ...item, frame });
    }
    for (const item of payload.backlinks || []) {
      backlinks.push({ ...item, frame });
    }
    for (const item of payload.mediaUrls || []) {
      mediaUrls.push({ ...item, frame });
    }
    for (const item of payload.candidates || []) {
      candidates.push({ ...item, frame });
    }
  }

  return {
    comments,
    base64,
    zeroWidth,
    flags,
    meta,
    revealedHidden,
    backlinks,
    mediaUrls,
    candidates,
    pageUrl: tabAssets.pageUrl || "",
    updatedAt: tabAssets.updatedAt || 0,
  };
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

function ensureMenus() {
  const create = () => {
    browser.menus.create({
      id: MENU_CIPHER,
      title: "Send to Hunt Engine",
      contexts: ["selection"],
    });
    browser.menus.create({
      id: MENU_PROBE,
      title: "Probe as Backlink ID",
      contexts: ["selection"],
    });
    browser.menus.create({
      id: MENU_PROBE_USER,
      title: "Probe as Username",
      contexts: ["selection"],
    });
    browser.menus.create({
      id: MENU_DNS,
      title: "DNS lookup in Hunt Engine",
      contexts: ["selection"],
    });
    browser.menus.create({
      id: MENU_GEOHASH,
      title: "Resolve geohash / coords in Hunt Engine",
      contexts: ["selection"],
    });
    browser.menus.create({
      id: MENU_IMG_SEND,
      title: "Send image URL to Hunt Engine",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_IMG_LENS,
      title: "Reverse image — Google Lens",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_IMG_YANDEX,
      title: "Reverse image — Yandex",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_IMG_TINEYE,
      title: "Reverse image — TinEye",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_IMG_FORENSICS,
      title: "Open in forensics tools (Forensically+)",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_IMG_STEGSTRUCK,
      title: "Scan with StegStruck (local)",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_IMG_PROBE,
      title: "Probe image filename as Backlink ID",
      contexts: ["image"],
    });
    browser.menus.create({
      id: MENU_AUDIO_SEND,
      title: "Send audio URL to Hunt Engine",
      contexts: ["audio"],
    });
    browser.menus.create({
      id: MENU_AUDIO_PROBE,
      title: "Probe audio filename as Backlink ID",
      contexts: ["audio"],
    });
    browser.menus.create({
      id: MENU_AUDIO_SEND + "-video",
      title: "Send audio/video URL to Hunt Engine",
      contexts: ["video"],
    });
    browser.menus.create({
      id: MENU_LINK_AUDIO,
      title: "Send audio link to Hunt Engine",
      contexts: ["link"],
      targetUrlPatterns: [
        "*://*/*.mp3",
        "*://*/*.MP3",
        "*://*/*.wav",
        "*://*/*.WAV",
        "*://*/*.ogg",
        "*://*/*.OGG",
        "*://*/*.m4a",
        "*://*/*.M4A",
        "*://*/*.flac",
        "*://*/*.FLAC",
        "*://*/*.aac",
        "*://*/*.AAC",
        "*://*/*.webm",
        "*://*/*.WEBM",
      ],
    });
  };

  const removing = browser.menus.removeAll();
  if (removing && typeof removing.then === "function") {
    removing.then(create).catch(create);
  } else {
    create();
  }
}

browser.runtime.onInstalled.addListener(ensureMenus);
ensureMenus();

function reverseSearchUrls(imageUrl) {
  const q = encodeURIComponent(imageUrl);
  return {
    lens: "https://lens.google.com/uploadbyurl?url=" + q,
    yandex: "https://yandex.com/images/search?rpt=imageview&url=" + q,
    tineye: "https://tineye.com/search?url=" + q,
  };
}

/** Best-effort forensics suite: Forensically (drag-drop) + URL EXIF + FotoForensics. */
function forensicsToolUrls(imageUrl) {
  const q = encodeURIComponent(imageUrl);
  return [
    "https://29a.ch/photo-forensics/#forensic",
    "https://exif.regex.info/exif.cgi?imgurl=" + q,
    "https://fotoforensics.com/",
  ];
}

function openForensicsTabs(imageUrl) {
  for (const url of forensicsToolUrls(imageUrl)) {
    browser.tabs.create({ url, active: false }).catch(() => {});
  }
}

function tokenFromImageUrl(imageUrl) {
  try {
    const u = new URL(imageUrl);
    const parts = u.pathname.split("/").filter(Boolean);
    let last = parts[parts.length - 1] || "";
    last = last.split("?")[0].split("#")[0];
    // strip common image extensions
    last = last.replace(/\.(jpe?g|png|gif|webp|bmp|svg|avif|ico)$/i, "");
    return normalizeProbeId(last, "id");
  } catch (_err) {
    return "";
  }
}

function tokenFromMediaUrl(mediaUrl) {
  try {
    const u = new URL(mediaUrl);
    const parts = u.pathname.split("/").filter(Boolean);
    let last = parts[parts.length - 1] || "";
    last = last.split("?")[0].split("#")[0];
    last = last.replace(/\.(mp3|wav|ogg|m4a|flac|aac|webm|opus)$/i, "");
    return normalizeProbeId(last, "id");
  } catch (_err) {
    return "";
  }
}

const AUDIO_EXT_RE = /\.(mp3|wav|ogg|m4a|flac|aac|webm)(?:[?#].*|$)/i;
const AUDIO_MIME_RE =
  /^audio\/(mpeg|mp3|wav|x-wav|ogg|vorbis|mp4|m4a|flac|aac|webm|x-m4a|opus)\b/i;

function isAudioDownloadCandidate(filename, mime, url) {
  const name = String(filename || "").toLowerCase();
  const m = String(mime || "").toLowerCase();
  const u = String(url || "");
  if (/^data:audio\//i.test(u)) return true;
  if (AUDIO_EXT_RE.test(name)) return true;
  if (AUDIO_MIME_RE.test(m)) return true;
  if (/^video\/webm\b/.test(m) && AUDIO_EXT_RE.test(name)) return true;
  try {
    if (/^https?:\/\//i.test(u)) {
      const path = new URL(u).pathname || "";
      if (AUDIO_EXT_RE.test(path)) return true;
    }
  } catch (_err) {
    /* ignore */
  }
  return false;
}

function isAudioLinkUrl(url) {
  const s = String(url || "").trim();
  if (!s) return false;
  if (/^blob:/i.test(s) || /^data:audio\//i.test(s)) return true;
  try {
    const u = new URL(s);
    return AUDIO_EXT_RE.test(u.pathname || "");
  } catch (_err) {
    return AUDIO_EXT_RE.test(s);
  }
}

async function openSidebarSafe() {
  try {
    if (browser.sidebarAction && browser.sidebarAction.open) {
      await browser.sidebarAction.open();
    }
  } catch (_err) {
    /* ignore */
  }
}

/**
 * @param {string} imageUrl
 * @param {string} [pageUrl]
 * @param {{ focus?: boolean, analyzeHex?: boolean, ingestToast?: string|null, needsDrop?: boolean, filename?: string, pendingIngest?: boolean }} [opts]
 */
async function captureImageAsset(imageUrl, pageUrl, opts) {
  const o = opts || {};
  const payload = {
    url: imageUrl || "",
    pageUrl: pageUrl || "",
    capturedAt: Date.now(),
  };
  if (o.filename) payload.filename = o.filename;
  if (o.needsDrop) payload.needsDrop = true;
  // One-shot flags for sidebar cold-start (GET_STATE) when notify races boot.
  if (o.pendingIngest || o.ingestToast || o.analyzeHex) {
    payload.pendingIngest = {
      toast: o.ingestToast || null,
      focus: o.focus !== false,
      analyzeHex: Boolean(o.analyzeHex),
      at: Date.now(),
    };
  }
  await storeSet(STORE.IMAGE, payload);
  await notifySidebarReliable({
    type: MSG.IMAGE_ASSET,
    imageAsset: payload,
    focus: o.focus !== false,
    analyzeHex: Boolean(o.analyzeHex),
    ingestToast: o.ingestToast || null,
  });
  return payload;
}

/**
 * @param {string} audioUrl
 * @param {string} [pageUrl]
 * @param {{ focus?: boolean, analyze?: boolean, ingestToast?: string|null, needsDrop?: boolean, filename?: string, pendingIngest?: boolean }} [opts]
 */
async function captureAudioAsset(audioUrl, pageUrl, opts) {
  const o = opts || {};
  const payload = {
    url: audioUrl || "",
    pageUrl: pageUrl || "",
    capturedAt: Date.now(),
  };
  if (o.filename) payload.filename = o.filename;
  if (o.needsDrop) payload.needsDrop = true;
  if (o.pendingIngest || o.ingestToast || o.analyze) {
    payload.pendingIngest = {
      toast: o.ingestToast || null,
      focus: o.focus !== false,
      analyze: Boolean(o.analyze),
      at: Date.now(),
    };
  }
  await storeSet(STORE.AUDIO, payload);
  await notifySidebarReliable({
    type: MSG.AUDIO_ASSET,
    audioAsset: payload,
    focus: o.focus !== false,
    analyze: Boolean(o.analyze),
    ingestToast: o.ingestToast || null,
  });
  return payload;
}

browser.menus.onClicked.addListener(async (info, tab) => {
  const pageUrl = tab && tab.url ? tab.url : "";
  const imageUrl = (info.srcUrl || "").trim();
  const mediaUrl = (info.srcUrl || info.linkUrl || "").trim();

  // Audio / video element menus
  if (
    info.menuItemId === MENU_AUDIO_SEND ||
    info.menuItemId === MENU_AUDIO_SEND + "-video" ||
    info.menuItemId === MENU_AUDIO_PROBE
  ) {
    if (!mediaUrl) return;
    await openSidebarSafe();
    if (info.menuItemId === MENU_AUDIO_PROBE) {
      await captureAudioAsset(mediaUrl, pageUrl, { analyze: /^https?:\/\//i.test(mediaUrl) });
      const id = tokenFromMediaUrl(mediaUrl);
      if (!id) return;
      runBacklinkProbe(id, pageUrl, "id").catch(() => {});
      return;
    }
    await captureAudioAsset(mediaUrl, pageUrl, {
      analyze: /^https?:\/\//i.test(mediaUrl),
    });
    if (tab && tab.id != null) await pushState(tab.id);
    return;
  }

  if (info.menuItemId === MENU_LINK_AUDIO) {
    const linkUrl = (info.linkUrl || "").trim();
    if (!isAudioLinkUrl(linkUrl)) return;
    await openSidebarSafe();
    await captureAudioAsset(linkUrl, pageUrl, {
      analyze: /^https?:\/\//i.test(linkUrl),
    });
    if (tab && tab.id != null) await pushState(tab.id);
    return;
  }

  // Image menus — do not require selection text
  if (
    info.menuItemId === MENU_IMG_SEND ||
    info.menuItemId === MENU_IMG_LENS ||
    info.menuItemId === MENU_IMG_YANDEX ||
    info.menuItemId === MENU_IMG_TINEYE ||
    info.menuItemId === MENU_IMG_FORENSICS ||
    info.menuItemId === MENU_IMG_STEGSTRUCK ||
    info.menuItemId === MENU_IMG_PROBE
  ) {
    if (!imageUrl) return;
    await openSidebarSafe();

    if (info.menuItemId === MENU_IMG_SEND) {
      await captureImageAsset(imageUrl, pageUrl);
      if (tab && tab.id != null) await pushState(tab.id);
      return;
    }

    if (info.menuItemId === MENU_IMG_LENS) {
      await captureImageAsset(imageUrl, pageUrl);
      browser.tabs.create({ url: reverseSearchUrls(imageUrl).lens, active: false });
      return;
    }
    if (info.menuItemId === MENU_IMG_YANDEX) {
      await captureImageAsset(imageUrl, pageUrl);
      browser.tabs.create({ url: reverseSearchUrls(imageUrl).yandex, active: false });
      return;
    }
    if (info.menuItemId === MENU_IMG_TINEYE) {
      await captureImageAsset(imageUrl, pageUrl);
      browser.tabs.create({ url: reverseSearchUrls(imageUrl).tineye, active: false });
      return;
    }
    if (info.menuItemId === MENU_IMG_FORENSICS) {
      const asset = await captureImageAsset(imageUrl, pageUrl);
      openForensicsTabs(imageUrl);
      await notifySidebar({
        type: MSG.IMAGE_FORENSICS,
        imageAsset: asset,
        copyUrl: imageUrl,
        toolCount: 3,
      });
      return;
    }
    if (info.menuItemId === MENU_IMG_STEGSTRUCK) {
      await captureImageAsset(imageUrl, pageUrl);
      const result = await sendImageToStegStruck(imageUrl, { tier: "quick" });
      await notifySidebar({
        type: MSG.IMAGE_FORENSICS,
        imageAsset: { url: imageUrl },
        stegstruck: result,
      });
      return;
    }
    if (info.menuItemId === MENU_IMG_PROBE) {
      await captureImageAsset(imageUrl, pageUrl);
      const id = tokenFromImageUrl(imageUrl);
      if (!id) return;
      runBacklinkProbe(id, pageUrl, "id").catch(() => {});
      return;
    }
  }

  const text = (info.selectionText || "").trim();
  if (!text) return;

  await openSidebarSafe();

  if (info.menuItemId === MENU_CIPHER) {
    await storeSet(STORE.CIPHER, text);
    await notifySidebar({ type: MSG.CIPHER_INPUT, text });
    if (tab && tab.id != null) await pushState(tab.id);
    return;
  }

  if (info.menuItemId === MENU_PROBE) {
    const id = normalizeProbeId(text, "id");
    if (!id) return;
    runBacklinkProbe(id, pageUrl, "id").catch(() => {});
    return;
  }

  if (info.menuItemId === MENU_PROBE_USER) {
    const id = normalizeProbeId(text, "username");
    if (!id) return;
    runBacklinkProbe(id, pageUrl, "username").catch(() => {});
    return;
  }

  if (info.menuItemId === MENU_DNS) {
    const domain = normalizeDomain(text);
    if (!domain) return;
    await notifySidebar({ type: MSG.DNS_INPUT, domain });
    runDnsLookup(domain).catch(() => {});
    return;
  }

  if (info.menuItemId === MENU_GEOHASH) {
    await notifySidebar({ type: MSG.GEOHASH_INPUT, text });
  }
});

function normalizeDomain(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  s = s.replace(/^https?:\/\//i, "");
  s = s.split("/")[0].split("?")[0].split("#")[0].trim();
  s = s.replace(/:\d+$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return "";
  return s.toLowerCase();
}

async function runDnsLookup(domain) {
  const name = normalizeDomain(domain);
  if (!name) {
    await notifySidebar({
      type: MSG.DNS_RESULT,
      ok: false,
      domain: domain || "",
      error: "Need a domain like example.com",
    });
    return;
  }

  const types = ["TXT", "A", "AAAA", "MX", "CNAME", "NS"];
  const records = {};
  const errors = [];

  await Promise.all(
    types.map(async (type) => {
      try {
        const url =
          "https://cloudflare-dns.com/dns-query?name=" +
          encodeURIComponent(name) +
          "&type=" +
          encodeURIComponent(type);
        const res = await fetch(url, {
          method: "GET",
          headers: { Accept: "application/dns-json" },
          cache: "no-store",
        });
        if (!res.ok) {
          errors.push(type + " HTTP " + res.status);
          records[type] = [];
          return;
        }
        const data = await res.json();
        const answers = Array.isArray(data.Answer) ? data.Answer : [];
        records[type] = answers
          .map((a) => {
            let dataStr = a.data != null ? String(a.data) : "";
            // TXT often arrives quoted
            dataStr = dataStr.replace(/^"|"$/g, "").replace(/\\"|"/g, "");
            return { data: dataStr, ttl: a.TTL };
          })
          .filter((a) => a.data);
      } catch (err) {
        errors.push(type + " failed");
        records[type] = [];
      }
    })
  );

  const total = types.reduce((n, t) => n + (records[t] || []).length, 0);
  await notifySidebar({
    type: MSG.DNS_RESULT,
    ok: true,
    domain: name,
    records,
    total,
    error: errors.length ? errors.join("; ") : "",
  });
}

/** Soft cap note — hard limit enforced in analyzeImageHex (8 MB). */
const IMAGE_HEX_MAX_BYTES = 8 * 1024 * 1024;
/** Full-file hex edit when ≤ this size; otherwise last EDIT_TAIL_BYTES only. */
const IMAGE_HEX_EDIT_FULL_MAX = 2 * 1024 * 1024;
const IMAGE_HEX_EDIT_TAIL_BYTES = 64 * 1024;

function bytesToHexDump(bytes, offsetBase) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, Math.min(i + 16, bytes.length));
    const off = (offsetBase + i).toString(16).padStart(8, "0");
    let hex = "";
    let asc = "";
    for (let j = 0; j < 16; j++) {
      if (j < slice.length) {
        const b = slice[j];
        hex += b.toString(16).padStart(2, "0") + (j === 7 ? "  " : " ");
        asc += b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
      } else {
        hex += j === 7 ? "   " : "   ";
        asc += " ";
      }
    }
    lines.push(off + "  " + hex.trimEnd().padEnd(49, " ") + "  |" + asc + "|");
  }
  return lines.join("\n");
}

/** Spaced compact hex for editable textarea (16 bytes per line). */
function bytesToEditableHex(bytes) {
  const parts = [];
  for (let i = 0; i < bytes.length; i++) {
    if (i > 0 && i % 16 === 0) parts.push("\n");
    else if (i > 0) parts.push(" ");
    parts.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return parts.join("");
}

function parseEditableHex(hexStr) {
  const cleaned = String(hexStr || "")
    .replace(/0x/gi, "")
    .replace(/[^0-9a-f]/gi, "");
  if (!cleaned.length) {
    return { ok: false, error: "Empty hex — need at least one byte" };
  }
  if (cleaned.length % 2 !== 0) {
    return { ok: false, error: "Odd hex length (need even number of nybbles)" };
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    out[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
  }
  return { ok: true, bytes: out };
}

function uint8ToBase64(bytes) {
  const chunk = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, Math.min(i + chunk, bytes.length))
    );
  }
  return btoa(binary);
}

async function fetchImageBytes(imageUrl) {
  const res = await fetch(imageUrl, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    redirect: "follow",
  });
  if (!res.ok) {
    return { ok: false, error: "HTTP " + res.status + " fetching image" };
  }
  const cl = Number(res.headers.get("content-length") || 0);
  if (cl > IMAGE_HEX_MAX_BYTES) {
    return {
      ok: false,
      error:
        "Image too large (" +
        Math.round(cl / 1024 / 1024) +
        " MB) for in-extension hex peek",
    };
  }
  const buf = await res.arrayBuffer();
  if (buf.byteLength > IMAGE_HEX_MAX_BYTES) {
    return { ok: false, error: "Image too large for in-extension hex peek" };
  }
  return {
    ok: true,
    bytes: new Uint8Array(buf),
    contentType: res.headers.get("content-type") || "",
  };
}

/**
 * Upload image bytes to local StegStruck and open the live report tab.
 * Requires `python -m stegstruck serve` on 127.0.0.1:8745.
 */
async function sendImageToStegStruck(imageUrl, opts) {
  const o = opts || {};
  const tier = o.tier || "quick";
  try {
    const health = await fetch(STEGSTRUCK_BASE + "/api/health", {
      method: "GET",
      cache: "no-store",
    });
    if (!health.ok) {
      return {
        ok: false,
        error: "StegStruck not responding. Start it: cd stegstruck && python -m stegstruck serve",
      };
    }
  } catch (_err) {
    return {
      ok: false,
      error: "StegStruck is offline. Run: python -m stegstruck serve (port 8745)",
    };
  }

  let bytes;
  let contentType = "application/octet-stream";
  try {
    const res = await fetch(imageUrl, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
    });
    if (!res.ok) {
      return { ok: false, error: "Could not fetch image (HTTP " + res.status + ")" };
    }
    const cl = Number(res.headers.get("content-length") || 0);
    if (cl > STEGSTRUCK_MAX_BYTES) {
      return { ok: false, error: "Image too large for StegStruck upload (>16 MB)" };
    }
    const buf = await res.arrayBuffer();
    if (buf.byteLength > STEGSTRUCK_MAX_BYTES) {
      return { ok: false, error: "Image too large for StegStruck upload (>16 MB)" };
    }
    if (!buf.byteLength) {
      return { ok: false, error: "Empty image — drop the file in StegStruck instead" };
    }
    bytes = buf;
    contentType = res.headers.get("content-type") || contentType;
  } catch (_err) {
    return {
      ok: false,
      error: "Could not fetch image (blob/expired URL?). Open StegStruck and drop the file.",
    };
  }

  let filename = "image.bin";
  try {
    const u = new URL(imageUrl);
    const base = (u.pathname.split("/").pop() || "").split("?")[0];
    if (base) filename = base.slice(0, 120);
  } catch (_err) {
    /* keep default */
  }
  if (!/\.[A-Za-z0-9]{2,5}$/.test(filename)) {
    if (/png/i.test(contentType)) filename += ".png";
    else if (/gif/i.test(contentType)) filename += ".gif";
    else if (/webp/i.test(contentType)) filename += ".webp";
    else filename += ".jpg";
  }

  const form = new FormData();
  form.append("file", new Blob([bytes], { type: contentType }), filename);
  form.append("tier", tier);
  form.append("passphrase", o.passphrase || "");
  form.append("llm", o.llm ? "1" : "0");

  let job;
  try {
    const created = await fetch(STEGSTRUCK_BASE + "/api/jobs", {
      method: "POST",
      body: form,
    });
    if (!created.ok) {
      const text = await created.text();
      return { ok: false, error: "StegStruck upload failed: " + (text || created.status) };
    }
    job = await created.json();
  } catch (_err) {
    return { ok: false, error: "StegStruck upload failed — is the server still up?" };
  }

  const ui = STEGSTRUCK_BASE + "/?job=" + encodeURIComponent(job.id);
  browser.tabs.create({ url: ui, active: true });
  return { ok: true, jobId: job.id, ui: ui, filename: job.filename || filename };
}

function extractPrintableStrings(bytes, minLen) {
  const min = minLen || 4;
  const out = [];
  let buf = "";
  let start = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) {
      if (!buf) start = i;
      buf += String.fromCharCode(b);
    } else {
      if (buf.length >= min) {
        out.push({ text: buf, offset: start, len: buf.length });
      }
      buf = "";
    }
  }
  if (buf.length >= min) {
    out.push({ text: buf, offset: start, len: buf.length });
  }
  return out;
}

/** Magic signatures used for concatenated / polyglot file detection. */
const FILE_MAGIC_DEFS = [
  {
    type: "jpeg",
    label: "JPEG",
    seq: [0xff, 0xd8, 0xff],
    ext: ".jpg",
    mime: "image/jpeg",
    previewable: true,
  },
  {
    type: "png",
    label: "PNG",
    seq: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    ext: ".png",
    mime: "image/png",
    previewable: true,
  },
  {
    type: "gif",
    label: "GIF",
    seq: [0x47, 0x49, 0x46, 0x38], // GIF8
    ext: ".gif",
    mime: "image/gif",
    previewable: true,
  },
  {
    type: "zip",
    label: "ZIP",
    seq: [0x50, 0x4b, 0x03, 0x04],
    ext: ".zip",
    mime: "application/zip",
    previewable: false,
  },
  {
    type: "pdf",
    label: "PDF",
    seq: [0x25, 0x50, 0x44, 0x46], // %PDF
    ext: ".pdf",
    mime: "application/pdf",
    previewable: false,
  },
];

function findByteSequence(bytes, seq, from) {
  const start = Math.max(0, from | 0);
  const last = bytes.length - seq.length;
  outer: for (let i = start; i <= last; i++) {
    for (let j = 0; j < seq.length; j++) {
      if (bytes[i + j] !== seq[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function findAllByteSequences(bytes, seq, from) {
  const hits = [];
  let pos = Math.max(0, from | 0);
  while (pos <= bytes.length - seq.length) {
    const at = findByteSequence(bytes, seq, pos);
    if (at < 0) break;
    hits.push(at);
    pos = at + 1;
  }
  return hits;
}

/** First JPEG EOI (FF D9) at or after `from`. */
function findJpegEoi(bytes, from) {
  return findByteSequence(bytes, [0xff, 0xd9], from | 0);
}

/**
 * PNG IEND chunk end offset (byte after CRC), or -1.
 * Looks for type bytes "IEND"; chunk end = typeStart + 4 (type) + 4 (CRC).
 */
function findPngIendEnd(bytes) {
  const typeAt = findByteSequence(
    bytes,
    [0x49, 0x45, 0x4e, 0x44], // IEND
    0
  );
  if (typeAt < 0) return -1;
  const end = typeAt + 8;
  return end <= bytes.length ? end : -1;
}

/**
 * Scan for concatenated / glued file payloads (JPEG-after-JPEG, PNG+ZIP, …).
 * Returns split segments + end-of-container markers.
 */
function detectConcatenatedSplits(bytes) {
  const size = bytes.length;
  const markers = {
    jpegEoi: null,
    jpegEoiEnd: null,
    pngIend: null,
    pngIendEnd: null,
  };

  const jpegSoiHits = findAllByteSequences(bytes, [0xff, 0xd8, 0xff], 0);
  if (jpegSoiHits.length) {
    const eoi = findJpegEoi(bytes, jpegSoiHits[0] + 3);
    if (eoi >= 0) {
      markers.jpegEoi = eoi;
      markers.jpegEoiEnd = eoi + 2;
    }
  }

  const pngIendEnd = findPngIendEnd(bytes);
  if (pngIendEnd >= 0) {
    markers.pngIend = pngIendEnd - 8;
    markers.pngIendEnd = pngIendEnd;
  }

  /** @type {{ offset: number, type: string, label: string, ext: string, mime: string, previewable: boolean }[]} */
  const starts = [];
  const seenOff = new Set();

  function addStart(offset, def) {
    if (offset < 0 || offset >= size || seenOff.has(offset)) return;
    seenOff.add(offset);
    starts.push({
      offset,
      type: def.type,
      label: def.label,
      ext: def.ext,
      mime: def.mime,
      previewable: !!def.previewable,
    });
  }

  for (const def of FILE_MAGIC_DEFS) {
    if (def.type === "jpeg") {
      // Prefer SOI @ first hit, then any SOI after first EOI (glued JPEG theme).
      // Avoid mid-stream FF D8 FF false splits before EOI when EOI is known.
      for (let i = 0; i < jpegSoiHits.length; i++) {
        const off = jpegSoiHits[i];
        if (i === 0) {
          addStart(off, def);
          continue;
        }
        if (markers.jpegEoiEnd != null) {
          if (off >= markers.jpegEoiEnd) addStart(off, def);
        } else if (off > 0) {
          addStart(off, def);
        }
      }
      continue;
    }
    const hits = findAllByteSequences(bytes, def.seq, 0);
    for (const off of hits) addStart(off, def);
  }

  starts.sort((a, b) => a.offset - b.offset);

  // If nothing matched at 0 but trailing data exists after container end, note raw head.
  let logicalEnd = null;
  if (markers.jpegEoiEnd != null) logicalEnd = markers.jpegEoiEnd;
  if (markers.pngIendEnd != null) {
    logicalEnd =
      logicalEnd == null
        ? markers.pngIendEnd
        : Math.min(logicalEnd, markers.pngIendEnd);
  }

  // Build segments between magic starts (and EOF).
  /** @type {{ offset: number, type: string, label: string, ext: string, mime: string, previewable: boolean, size: number, index: number }[]} */
  const splits = [];
  if (starts.length) {
    for (let i = 0; i < starts.length; i++) {
      const cur = starts[i];
      const nextOff = i + 1 < starts.length ? starts[i + 1].offset : size;
      const segSize = nextOff - cur.offset;
      if (segSize <= 0) continue;
      splits.push({
        offset: cur.offset,
        type: cur.type,
        label: cur.label,
        ext: cur.ext,
        mime: cur.mime,
        previewable: cur.previewable,
        size: segSize,
        index: splits.length,
      });
    }
  }

  // Trailing unknown bytes after logical end with no magic: expose as raw part.
  if (
    logicalEnd != null &&
    logicalEnd < size &&
    !seenOff.has(logicalEnd) &&
    !starts.some((s) => s.offset === logicalEnd)
  ) {
    const hasMagicAtOrAfter = starts.some((s) => s.offset >= logicalEnd);
    if (!hasMagicAtOrAfter) {
      // Only add raw trailing if we already have a first segment covering [0, logicalEnd)
      // or file starts with a known type that ended.
      const firstCovers =
        splits.length && splits[0].offset === 0 && splits[0].size >= logicalEnd;
      if (firstCovers && splits.length === 1) {
        splits[0].size = logicalEnd - splits[0].offset;
        splits.push({
          offset: logicalEnd,
          type: "raw",
          label: "trailing bytes",
          ext: ".bin",
          mime: "application/octet-stream",
          previewable: false,
          size: size - logicalEnd,
          index: 1,
        });
      } else if (!splits.length && logicalEnd > 0) {
        splits.push({
          offset: 0,
          type: "raw",
          label: "part 1",
          ext: ".bin",
          mime: "application/octet-stream",
          previewable: false,
          size: logicalEnd,
          index: 0,
        });
        splits.push({
          offset: logicalEnd,
          type: "raw",
          label: "trailing bytes",
          ext: ".bin",
          mime: "application/octet-stream",
          previewable: false,
          size: size - logicalEnd,
          index: 1,
        });
      }
    }
  }

  const concatenated = splits.length >= 2;
  return {
    splits,
    markers,
    concatenated,
    logicalEnd,
  };
}

/**
 * Extract a byte range from a fetched image (≤ IMAGE_HEX_MAX_BYTES).
 */
async function extractImagePart(imageUrl, offset, length, mimeHint) {
  const off = Number(offset);
  const len = Number(length);
  if (!Number.isFinite(off) || off < 0 || !Number.isFinite(len) || len <= 0) {
    return { ok: false, error: "Invalid offset/length" };
  }
  const fetched = await fetchImageBytes(imageUrl);
  if (!fetched.ok) return fetched;
  const bytes = fetched.bytes;
  if (off >= bytes.length) {
    return { ok: false, error: "Offset past end of file" };
  }
  const end = Math.min(bytes.length, off + len);
  const slice = bytes.subarray(off, end);
  return {
    ok: true,
    url: imageUrl,
    offset: off,
    size: slice.length,
    contentType: mimeHint || "application/octet-stream",
    base64: uint8ToBase64(slice),
  };
}

async function analyzeImageHex(imageUrl) {
  const fetched = await fetchImageBytes(imageUrl);
  if (!fetched.ok) return fetched;
  const bytes = fetched.bytes;
  const size = bytes.length;
  const headLen = Math.min(256, size);
  const tailLen = Math.min(256, size);
  const tailStart = size <= 256 ? 0 : size - tailLen;
  const headBytes = bytes.subarray(0, headLen);
  const tailBytes = bytes.subarray(tailStart);

  // Prefer last 64KB for trailing stego payloads; also scan earlier for longer strings
  const stringScanFrom = Math.max(0, size - 65536);
  let strings = extractPrintableStrings(bytes.subarray(stringScanFrom), 4).map((s) => ({
    text: s.text,
    offset: stringScanFrom + s.offset,
    len: s.len,
  }));
  if (stringScanFrom > 0) {
    const earlier = extractPrintableStrings(bytes.subarray(0, stringScanFrom), 8);
    strings = strings.concat(
      earlier.map((s) => ({ text: s.text, offset: s.offset, len: s.len }))
    );
  }
  strings.sort((a, b) => b.len - a.len || b.offset - a.offset);
  const seen = new Set();
  strings = strings
    .filter((s) => {
      const key = s.text.slice(0, 200);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 40);

  let editScope;
  let editOffset;
  let editBytes;
  if (size <= IMAGE_HEX_EDIT_FULL_MAX) {
    editScope = "full";
    editOffset = 0;
    editBytes = bytes;
  } else {
    editScope = "tail";
    editOffset = Math.max(0, size - IMAGE_HEX_EDIT_TAIL_BYTES);
    editBytes = bytes.subarray(editOffset);
  }

  const splitInfo = detectConcatenatedSplits(bytes);

  return {
    ok: true,
    url: imageUrl,
    size,
    truncated: false,
    contentType: fetched.contentType || "",
    headHex: bytesToHexDump(headBytes, 0),
    tailHex: bytesToHexDump(tailBytes, tailStart),
    strings,
    metaFields: extractImageMetaFields(bytes),
    editScope,
    editOffset,
    editSize: editBytes.length,
    editHex: bytesToEditableHex(editBytes),
    splits: splitInfo.splits,
    concatenated: splitInfo.concatenated,
    markers: splitInfo.markers,
    logicalEnd: splitInfo.logicalEnd,
  };
}

/**
 * Re-fetch image, replace bytes from editOffset through EOF with parsed hex, return patched file.
 */
async function patchImageHex(imageUrl, editOffset, editHex) {
  const parsed = parseEditableHex(editHex);
  if (!parsed.ok) return parsed;

  const fetched = await fetchImageBytes(imageUrl);
  if (!fetched.ok) return fetched;
  const bytes = fetched.bytes;
  const size = bytes.length;
  const off = Number(editOffset);
  if (!Number.isFinite(off) || off < 0 || off > size) {
    return { ok: false, error: "Invalid edit offset" };
  }

  const newEdit = parsed.bytes;
  const patched = new Uint8Array(off + newEdit.length);
  patched.set(bytes.subarray(0, off), 0);
  patched.set(newEdit, off);

  return {
    ok: true,
    url: imageUrl,
    size: patched.length,
    originalSize: size,
    editOffset: off,
    editSize: newEdit.length,
    contentType: fetched.contentType || "application/octet-stream",
    base64: uint8ToBase64(patched),
  };
}

function readAscii(bytes, start, len) {
  let s = "";
  const end = Math.min(bytes.length, start + len);
  for (let i = start; i < end; i++) {
    const b = bytes[i];
    if (b === 0) break;
    if (b >= 32 && b <= 126) s += String.fromCharCode(b);
    else if (b === 9 || b === 10 || b === 13) s += String.fromCharCode(b);
  }
  return s;
}

function readUtf8(bytes, start, len) {
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(start, start + len));
  } catch (_err) {
    return readAscii(bytes, start, len);
  }
}

function extractPngTextChunks(bytes) {
  const fields = [];
  if (bytes.length < 8) return fields;
  // PNG signature
  if (!(bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47)) {
    return fields;
  }
  let offset = 8;
  while (offset + 12 <= bytes.length) {
    const len =
      (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
    const type = String.fromCharCode(
      bytes[offset + 4],
      bytes[offset + 5],
      bytes[offset + 6],
      bytes[offset + 7]
    );
    const dataStart = offset + 8;
    if (dataStart + len + 4 > bytes.length) break;
    if (type === "tEXt" && len > 1) {
      let nul = -1;
      for (let i = 0; i < len; i++) {
        if (bytes[dataStart + i] === 0) {
          nul = i;
          break;
        }
      }
      if (nul > 0) {
        const key = readAscii(bytes, dataStart, nul);
        const value = readUtf8(bytes, dataStart + nul + 1, len - nul - 1).replace(/\0+$/, "");
        if (key && value) fields.push({ key, value, source: "PNG tEXt" });
      }
    } else if (type === "iTXt" && len > 5) {
      let p = dataStart;
      const end = dataStart + len;
      let key = "";
      while (p < end && bytes[p] !== 0) {
        key += String.fromCharCode(bytes[p]);
        p++;
      }
      p++; // null
      const compressionFlag = p < end ? bytes[p] : 1;
      p += 2; // flag + method
      // skip language tag
      while (p < end && bytes[p] !== 0) p++;
      p++;
      // skip translated keyword
      while (p < end && bytes[p] !== 0) p++;
      p++;
      if (compressionFlag === 0 && p < end) {
        const value = readUtf8(bytes, p, end - p).replace(/\0+$/, "").trim();
        if (key && value) fields.push({ key, value, source: "PNG iTXt" });
      }
    } else if (type === "zTXt" && len > 2) {
      let nul = -1;
      for (let i = 0; i < len; i++) {
        if (bytes[dataStart + i] === 0) {
          nul = i;
          break;
        }
      }
      if (nul > 0 && dataStart + nul + 2 < dataStart + len) {
        const key = readAscii(bytes, dataStart, nul);
        // compression method at nul+1; deflated data follows — skip inflate for lightness
        // unless DecompressionStream exists
        const compStart = dataStart + nul + 2;
        const compLen = len - nul - 2;
        if (key && typeof DecompressionStream !== "undefined" && compLen > 0) {
          // sync inflate not available; store placeholder note only if we can decode later
          fields.push({
            key,
            value: "(compressed zTXt — open Forensics+ / external tool)",
            source: "PNG zTXt",
          });
        } else if (key) {
          fields.push({
            key,
            value: "(compressed zTXt)",
            source: "PNG zTXt",
          });
        }
      }
    } else if (type === "IEND") {
      break;
    }
    offset = dataStart + len + 4; // data + CRC
  }
  return fields;
}

function extractJpegExifText(bytes) {
  const fields = [];
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return fields;

  let offset = 2;
  while (offset + 4 < bytes.length) {
    if (bytes[offset] !== 0xff) break;
    const marker = bytes[offset + 1];
    const segLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
    if (segLen < 2 || offset + 2 + segLen > bytes.length) break;
    const segStart = offset + 4;
    const segEnd = offset + 2 + segLen;

    // APP1 EXIF
    if (marker === 0xe1 && segLen > 8) {
      const head = readAscii(bytes, segStart, 6);
      if (head.startsWith("Exif")) {
        const tiffStart = segStart + 6;
        const parsed = parseExifIfdTexts(bytes, tiffStart, segEnd);
        for (const f of parsed) fields.push(f);
      }
    }
    // COM comment
    if (marker === 0xfe && segLen > 2) {
      const value = readUtf8(bytes, segStart, segLen - 2).replace(/\0+$/, "").trim();
      if (value) fields.push({ key: "Comment", value, source: "JPEG COM" });
    }

    if (marker === 0xda) break; // SOS — image data
    offset = segEnd;
  }
  return fields;
}

function parseExifIfdTexts(bytes, tiffStart, limit) {
  const fields = [];
  if (tiffStart + 8 > limit) return fields;
  const le = bytes[tiffStart] === 0x49 && bytes[tiffStart + 1] === 0x49;
  const be = bytes[tiffStart] === 0x4d && bytes[tiffStart + 1] === 0x4d;
  if (!le && !be) return fields;

  const u16 = (o) =>
    le ? bytes[o] | (bytes[o + 1] << 8) : (bytes[o] << 8) | bytes[o + 1];
  const u32 = (o) =>
    le
      ? bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)
      : (bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3];

  const ifd0 = tiffStart + u32(tiffStart + 4);
  if (ifd0 < tiffStart || ifd0 + 2 > limit) return fields;
  const count = u16(ifd0);
  const WANTED = {
    0x010e: "ImageDescription",
    0x9286: "UserComment",
    0x010f: "Make",
    0x0110: "Model",
    0x013b: "Artist",
    0x8298: "Copyright",
  };

  for (let i = 0; i < count; i++) {
    const entry = ifd0 + 2 + i * 12;
    if (entry + 12 > limit) break;
    const tag = u16(entry);
    const type = u16(entry + 2);
    const num = u32(entry + 4);
    const name = WANTED[tag];
    if (!name) continue;
    // type 2 = ASCII, 7 = undefined (UserComment)
    let valueOffset = entry + 8;
    let byteLen = num;
    if (type === 2) byteLen = num;
    else if (type === 7) byteLen = num;
    else continue;
    if (byteLen > 4) {
      valueOffset = tiffStart + u32(entry + 8);
    }
    if (valueOffset < tiffStart || valueOffset + byteLen > limit) continue;
    let value = "";
    if (tag === 0x9286 && byteLen > 8) {
      // UserComment: 8-byte charset code + data
      value = readUtf8(bytes, valueOffset + 8, byteLen - 8).replace(/\0+$/, "").trim();
    } else {
      value = readUtf8(bytes, valueOffset, byteLen).replace(/\0+$/, "").trim();
    }
    if (value) fields.push({ key: name, value, source: "JPEG EXIF" });
  }
  return fields;
}

function extractImageMetaFields(bytes) {
  const out = [];
  const seen = new Set();
  const addAll = (list) => {
    for (const f of list) {
      const key = (f.key || "") + "|" + (f.value || "").slice(0, 80);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  };
  addAll(extractPngTextChunks(bytes));
  addAll(extractJpegExifText(bytes));
  return out.slice(0, 40);
}

async function analyzeImageMeta(imageUrl) {
  const res = await fetch(imageUrl, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    redirect: "follow",
  });
  if (!res.ok) {
    return { ok: false, error: "HTTP " + res.status + " fetching image" };
  }
  const cl = Number(res.headers.get("content-length") || 0);
  if (cl > 8 * 1024 * 1024) {
    return { ok: false, error: "Image too large for in-extension meta peek" };
  }
  const buf = await res.arrayBuffer();
  if (buf.byteLength > 8 * 1024 * 1024) {
    return { ok: false, error: "Image too large for in-extension meta peek" };
  }
  const bytes = new Uint8Array(buf);
  return {
    ok: true,
    url: imageUrl,
    size: bytes.length,
    contentType: res.headers.get("content-type") || "",
    fields: extractImageMetaFields(bytes),
  };
}

function readId3SynchsafeInt(bytes, offset) {
  return (
    ((bytes[offset] & 0x7f) << 21) |
    ((bytes[offset + 1] & 0x7f) << 14) |
    ((bytes[offset + 2] & 0x7f) << 7) |
    (bytes[offset + 3] & 0x7f)
  );
}

function decodeId3Text(data, encoding) {
  if (!data || !data.length) return "";
  try {
    const enc = encoding == null ? 0 : encoding;
    if (enc === 3) return new TextDecoder("utf-8").decode(data).replace(/\0+$/, "");
    if (enc === 1 || enc === 2) {
      let start = 0;
      if (enc === 1 && data.length >= 2 && data[0] === 0xff && data[1] === 0xfe) start = 2;
      let out = "";
      for (let i = start; i + 1 < data.length; i += 2) {
        const c = data[i] | (data[i + 1] << 8);
        if (c === 0) break;
        out += String.fromCharCode(c);
      }
      return out.trim();
    }
    let out = "";
    for (let i = 0; i < data.length; i++) {
      if (data[i] === 0) break;
      out += String.fromCharCode(data[i]);
    }
    return out.trim();
  } catch (_err) {
    return "";
  }
}

function parseId3v2(bytes) {
  const fields = [];
  if (bytes.length < 10) return fields;
  if (bytes[0] !== 0x49 || bytes[1] !== 0x44 || bytes[2] !== 0x33) return fields;

  const versionMajor = bytes[3];
  const tagSize = readId3SynchsafeInt(bytes, 6);
  let pos = 10;
  const end = Math.min(bytes.length, 10 + tagSize);
  const labels = {
    TIT2: "Title",
    TPE1: "Artist",
    TALB: "Album",
    TYER: "Year",
    TCON: "Genre",
    COMM: "Comment",
    USLT: "Lyrics",
    TXXX: "User text",
    TPE2: "Album artist",
  };

  while (pos + 10 <= end) {
    const id = String.fromCharCode(bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]);
    if (!/^[A-Z0-9]{4}$/.test(id)) break;

    let frameSize;
    if (versionMajor === 4) {
      frameSize = readId3SynchsafeInt(bytes, pos + 4);
      pos += 10;
    } else {
      frameSize =
        (bytes[pos + 4] << 24) |
        (bytes[pos + 5] << 16) |
        (bytes[pos + 6] << 8) |
        bytes[pos + 7];
      pos += 10;
    }
    if (frameSize <= 0 || pos + frameSize > end) break;

    const data = bytes.subarray(pos, pos + frameSize);
    pos += frameSize;

    if (!/^(TIT2|TPE1|TALB|TYER|TCON|COMM|USLT|TXXX|TPE2)$/.test(id)) continue;

    let text = "";
    if (id === "COMM") {
      const enc = data[0];
      let i = 4;
      while (i < data.length && data[i] !== 0) i++;
      i++;
      text = decodeId3Text(data.subarray(i), enc);
    } else if (id === "TXXX") {
      const enc = data[0];
      let i = 1;
      while (i < data.length && data[i] !== 0) i++;
      i++;
      text = decodeId3Text(data.subarray(i), enc);
    } else {
      text = decodeId3Text(data.subarray(1), data[0]);
    }
    if (text) {
      fields.push({ id, label: labels[id] || id, text, source: "MP3 ID3" });
    }
  }
  return fields.slice(0, 20);
}

function findMorseLikeInStrings(strings) {
  const hits = [];
  const seen = new Set();
  const re =
    /[.\-•·_–—−]+(?:[ \t]+[.\-•·_–—−]+)*(?:\s{2,}|\s*\/\s*|\s*\|\s*|[.\-•·_–—−]+(?:[ \t]+[.\-•·_–—−]+)*)*/g;

  for (const s of strings || []) {
    const text = String((s && s.text) || s || "");
    if (!text) continue;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      const raw = m[0].trim();
      if (raw.length < 4) continue;
      const compact = raw.replace(/[\s/|]+/g, "");
      const morseChars = (compact.match(/[.\-•·_–—−]/g) || []).length;
      if (morseChars < 4 || morseChars / Math.max(compact.length, 1) < 0.75) continue;
      if (seen.has(raw)) continue;
      seen.add(raw);
      hits.push({ text: raw, source: s.offset != null ? "@0x" + s.offset.toString(16) : "string" });
      if (hits.length >= 12) return hits;
    }
  }
  return hits;
}

async function fetchAudioBytes(audioUrl) {
  const res = await fetch(audioUrl, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    redirect: "follow",
  });
  if (!res.ok) {
    return { ok: false, error: "HTTP " + res.status + " fetching audio" };
  }
  const cl = Number(res.headers.get("content-length") || 0);
  if (cl > AUDIO_MAX_BYTES) {
    return {
      ok: false,
      error:
        "Audio too large (" +
        Math.round(cl / 1024 / 1024) +
        " MB) for in-extension peek",
    };
  }
  const buf = await res.arrayBuffer();
  if (buf.byteLength > AUDIO_MAX_BYTES) {
    return { ok: false, error: "Audio too large for in-extension peek" };
  }
  return {
    ok: true,
    bytes: new Uint8Array(buf),
    contentType: res.headers.get("content-type") || "",
  };
}

function analyzeAudioBuffer(bytes, meta) {
  const size = bytes.length;
  const stringScanFrom = Math.max(0, size - Math.min(size, 512 * 1024));
  let strings = extractPrintableStrings(bytes.subarray(stringScanFrom), 4).map((s) => ({
    ...s,
    offset: s.offset + stringScanFrom,
  }));
  if (stringScanFrom > 0) {
    const earlier = extractPrintableStrings(bytes.subarray(0, stringScanFrom), 8);
    strings = earlier.concat(strings);
  }
  strings = strings.slice(0, 60);
  const id3 = parseId3v2(bytes);
  const morseLike = findMorseLikeInStrings(strings);
  if (id3.length) {
    for (const f of id3) {
      if (f.text && looksLikeMorseText(f.text)) {
        morseLike.push({ text: f.text, source: "ID3 " + (f.label || f.id) });
      }
    }
  }
  return {
    ok: true,
    url: (meta && meta.url) || "",
    filename: (meta && meta.filename) || "",
    size,
    contentType: (meta && meta.contentType) || "",
    strings,
    id3,
    morseLike,
    headHex: bytesToHexDump(bytes.subarray(0, Math.min(256, size)), 0),
    tailHex: bytesToHexDump(bytes.subarray(Math.max(0, size - 256)), Math.max(0, size - 256)),
  };
}

function looksLikeMorseText(text) {
  const t = String(text || "").trim();
  if (t.length < 4) return false;
  if (!/[.\-•·_–—−]/.test(t)) return false;
  const compact = t.replace(/[\s/|]+/g, "");
  const morseChars = (compact.match(/[.\-•·_–—−•·_–—]/g) || []).length;
  return morseChars >= 4 && morseChars / Math.max(compact.length, 1) >= 0.75;
}

async function analyzeAudioFromUrl(audioUrl) {
  const fetched = await fetchAudioBytes(audioUrl);
  if (!fetched.ok) return fetched;
  return analyzeAudioBuffer(fetched.bytes, {
    url: audioUrl,
    contentType: fetched.contentType,
  });
}

async function analyzeAudioFromArrayBuffer(buffer, filename) {
  const bytes = new Uint8Array(buffer);
  if (bytes.byteLength > AUDIO_MAX_BYTES) {
    return {
      ok: false,
      error: "Audio too large (>" + Math.round(AUDIO_MAX_BYTES / (1024 * 1024)) + " MB)",
    };
  }
  return analyzeAudioBuffer(bytes, { filename: filename || "audio" });
}

const HEADER_CLUE_RE = /hint|clue|next|flag|secret|token|key|puzzle|cipher|hunt|ctf/i;
const COMMON_HEADER_RE =
  /^(content-|cache-|strict-|access-|referrer|server|date|etag|vary|age|expires|pragma|connection|keep-alive|transfer-|accept-|location|set-cookie|www-authenticate|retry-after|link|alt-svc|nel|report-to|permissions-policy|cross-origin|last-modified|x-content-type|x-frame|x-xss|x-powered|x-request|x-amz|cf-|nel$)/i;

function classifyResponseHeader(name, value) {
  const n = String(name || "");
  const v = String(value || "");
  if (/^x-/i.test(n)) return true;
  if (HEADER_CLUE_RE.test(n)) return true;
  if (/^set-cookie$/i.test(n) && HEADER_CLUE_RE.test(v)) return true;
  if (!COMMON_HEADER_RE.test(n) && HEADER_CLUE_RE.test(v)) return true;
  if (!COMMON_HEADER_RE.test(n) && /^[a-z0-9_-]{2,40}$/i.test(n) && !/^(server|date|etag|vary|age|expires|pragma|connection|location|link)$/i.test(n)) {
    if (HEADER_CLUE_RE.test(n) || /^x-/i.test(n)) return true;
  }
  return false;
}

async function storeResponseHeaders(tabId, url, responseHeaders, statusCode) {
  if (tabId < 0 || isInternalUrl(url)) return;
  const headers = (responseHeaders || [])
    .map((h) => {
      const name = h.name || "";
      const value = h.value || "";
      return {
        name,
        value,
        suspicious: classifyResponseHeader(name, value),
      };
    })
    .filter((h) => h.name);
  // Prefer clue-ish first, then alpha
  headers.sort((a, b) => Number(b.suspicious) - Number(a.suspicious) || a.name.localeCompare(b.name));
  const payload = {
    url,
    statusCode: statusCode == null ? null : statusCode,
    capturedAt: Date.now(),
    headers: headers.slice(0, 80),
  };
  await patchMap(
    STORE.HEADERS,
    (map) => {
      const next = Object.assign({}, map || {});
      next[tabId] = payload;
      return next;
    },
    {}
  );
  await notifySidebar({
    type: MSG.STATE,
    responseHeaders: payload,
    tabId,
  });
}

// Toolbar button toggles the Firefox sidebar (no popup).
if (browser.action && browser.action.onClicked) {
  browser.action.onClicked.addListener(async () => {
    try {
      if (browser.sidebarAction && browser.sidebarAction.toggle) {
        await browser.sidebarAction.toggle();
      }
    } catch (_err) {
      // Ignore — some Firefox builds only expose open/close.
    }
  });
}

// ---------------------------------------------------------------------------
// Redirect chain tracker
//
// HTTP hops  → webRequest.onBeforeRedirect (status + from/to URL)
// Client hops → webNavigation.onCommitted  (meta refresh / JS)
// Seal        → webNavigation.onCompleted  when 2+ distinct URLs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

function isInternalUrl(url) {
  return !url || INTERNAL_URL.test(url);
}

function hopEqual(a, b) {
  return a && b && a.url === b.url;
}

function getChain(tabId) {
  if (!activeChains.has(tabId)) {
    activeChains.set(tabId, {
      tabId,
      hops: [],
      startedAt: Date.now(),
      seed: lastLanded.get(tabId) || "",
    });
  }
  return activeChains.get(tabId);
}

function appendHop(tabId, url, via, statusCode) {
  if (isInternalUrl(url)) return;
  const chain = getChain(tabId);
  const hop = {
    url,
    via: via || "nav",
    statusCode: statusCode == null ? null : statusCode,
    ts: Date.now(),
  };
  const last = chain.hops[chain.hops.length - 1];
  if (hopEqual(last, hop)) return;
  chain.hops.push(hop);
}

function uniqueUrlCount(chain) {
  return new Set(chain.hops.map((h) => h.url)).size;
}

function resetChain(tabId, firstUrl) {
  const chain = {
    tabId,
    hops: [],
    startedAt: Date.now(),
    seed: lastLanded.get(tabId) || "",
  };
  activeChains.set(tabId, chain);
  if (firstUrl) appendHop(tabId, firstUrl, "start", null);
}

function isContinuation(tabId, url) {
  const chain = activeChains.get(tabId);
  if (!chain || !chain.hops.length) return false;
  return chain.hops.some((h) => h.url === url);
}

async function sealChain(tabId, finalUrl) {
  const chain = activeChains.get(tabId);
  if (!chain) return;

  if (finalUrl) appendHop(tabId, finalUrl, "final", null);

  if (uniqueUrlCount(chain) < 2) {
    activeChains.delete(tabId);
    return;
  }

  const record = {
    id: `${Date.now()}-${tabId}-${Math.random().toString(16).slice(2, 8)}`,
    tabId,
    hops: chain.hops.slice(),
    finalUrl: finalUrl || chain.hops[chain.hops.length - 1].url,
    completedAt: Date.now(),
  };

  activeChains.delete(tabId);

  const log = await storeGet(STORE.REDIRECTS, []);
  log.unshift(record);
  await storeSet(STORE.REDIRECTS, log.slice(0, MAX_CHAINS));
  await pushState(tabId);
}

browser.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (details.type && details.type !== "main_frame") return;
    appendHop(details.tabId, details.url, `http-${details.statusCode || "3xx"}`, details.statusCode);
    if (details.redirectUrl) {
      appendHop(details.tabId, details.redirectUrl, "redirect-target", null);
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (details.type !== "main_frame") return;
    storeResponseHeaders(
      details.tabId,
      details.url,
      details.responseHeaders,
      details.statusCode
    ).catch(() => {});
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders"]
);

browser.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;

  // Redirect bursts fire extra onBeforeNavigate events for the next hop.
  // Only reset when this URL is not already part of the in-flight chain.
  if (!isContinuation(details.tabId, details.url)) {
    resetChain(details.tabId, details.url);
  }
});

browser.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;

  const qualifiers = details.transitionQualifiers || [];
  const type = details.transitionType || "";

  // Back/forward is not a tracking bounce.
  if (qualifiers.includes("forward_back")) {
    activeChains.delete(details.tabId);
    return;
  }

  // Same-URL reload is noise.
  if (type === "reload") {
    const chain = activeChains.get(details.tabId);
    if (!chain || uniqueUrlCount(chain) < 2) {
      activeChains.delete(details.tabId);
      return;
    }
  }

  let via = type || "committed";
  if (qualifiers.includes("client_redirect")) via = "client-redirect";
  else if (qualifiers.includes("server_redirect")) via = "server-redirect";

  // Meta-refresh / JS redirects often complete page A first, then navigate to B.
  // Re-attach A as the origin hop when the browser marks this commit as a redirect.
  if (via === "client-redirect" || via === "server-redirect") {
    const chain = getChain(details.tabId);
    const seed = chain.seed || lastLanded.get(details.tabId);
    if (seed && seed !== details.url && !chain.hops.some((h) => h.url === seed)) {
      chain.hops.unshift({
        url: seed,
        via: "origin",
        statusCode: null,
        ts: chain.startedAt || Date.now(),
      });
    }
  }

  appendHop(details.tabId, details.url, via, null);

  // Main-document committed: drop stale Live Assets so the new scan replaces them.
  storeGet(STORE.ASSETS, {}).then((assets) => {
    if (assets[details.tabId]) {
      delete assets[details.tabId];
      return storeSet(STORE.ASSETS, assets);
    }
  }).catch(() => {});
});

browser.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;
  lastLanded.set(details.tabId, details.url);
  sealChain(details.tabId, details.url);
});

browser.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0) return;
  // Keep a partial chain if it already bounced; otherwise drop it.
  const chain = activeChains.get(details.tabId);
  if (chain && uniqueUrlCount(chain) >= 2) {
    sealChain(details.tabId, details.url);
  } else {
    activeChains.delete(details.tabId);
  }
});

// ---------------------------------------------------------------------------
// Tab lifecycle
// ---------------------------------------------------------------------------

browser.tabs.onRemoved.addListener(async (tabId) => {
  activeChains.delete(tabId);
  lastLanded.delete(tabId);
  await patchMap(STORE.ASSETS, (map) => {
    delete map[tabId];
    return map;
  }, {});
  await patchMap(STORE.REVEAL, (map) => {
    delete map[tabId];
    return map;
  }, {});
});

browser.tabs.onActivated.addListener(async (info) => {
  await pushState(info.tabId);
});

browser.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === "complete" || changeInfo.url) {
    await pushState(tabId);
  }
});

// ---------------------------------------------------------------------------
// Backlink ID / username probe
// ---------------------------------------------------------------------------

/**
 * WhatsMyName-style confirmation (WebBreacher/WhatsMyName wmn-data.json):
 *   eCode / eString  — positive "exists" signals (required for confirmed hits)
 *   mCode / mString  — "missing" signals
 *   checkUrl         — optional API/check URI (display url stays human-readable)
 *   idShape          — skip probe unless id matches (e.g. IMDb tt########)
 *   requireIdInUrl   — final URL must still contain the id (default true for wmn)
 *   ambiguousAsBlocked — unconfirmed 200 → blocked (manual) instead of silent filter
 *   check: "wmn" | "raw" | "status" | "skip" | "hint" | "tab"
 * Ambiguous 200 responses are NEVER confirmed — bare HTTP 200 is not enough.
 */

/** Google Drive / Docs / Sheets file & folder ids (typically 25–44 URL-safe chars). */
const GOOGLE_FILE_ID_RE = /^[\w-]{25,}$/;
const BACKLINK_TEMPLATES = [
  {
    label: "Pastebin",
    url: "https://pastebin.com/{id}",
    check: "wmn",
    priority: 0,
    eCode: 200,
    eString: 'id="paste_code"',
    mString: ["pastebin.com/error", "Not Found (#404)", "This page has been removed"],
  },
  { label: "Pastebin raw", url: "https://pastebin.com/raw/{id}", check: "raw", priority: 0 },
  {
    label: "Bit.ly",
    url: "https://bit.ly/{id}",
    check: "status",
    priority: 1,
    requireIdInUrl: true,
  },
  {
    label: "TinyURL",
    url: "https://tinyurl.com/{id}",
    check: "status",
    priority: 1,
    requireIdInUrl: true,
  },
  {
    label: "Goo.gl",
    url: "https://goo.gl/{id}",
    check: "status",
    priority: 1,
    requireIdInUrl: true,
  },
  {
    label: "Google Docs",
    url: "https://docs.google.com/document/d/{id}/edit",
    check: "wmn",
    priority: 2,
    idShape: GOOGLE_FILE_ID_RE,
    eCode: 200,
    eString: ["docs-dm", "google-docs", "Document"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Sorry, the file you have requested does not exist", "not found"],
    requireIdInUrl: true,
  },
  {
    label: "Google Sheets",
    url: "https://docs.google.com/spreadsheets/d/{id}/edit",
    check: "wmn",
    priority: 2,
    idShape: GOOGLE_FILE_ID_RE,
    eCode: 200,
    eString: ["spreadsheets", "docs-dm"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Google Slides",
    url: "https://docs.google.com/presentation/d/{id}/edit",
    check: "wmn",
    priority: 2,
    idShape: GOOGLE_FILE_ID_RE,
    eCode: 200,
    eString: ["presentation", "docs-dm"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Google Forms",
    url: "https://docs.google.com/forms/d/{id}/viewform",
    check: "wmn",
    priority: 2,
    idShape: GOOGLE_FILE_ID_RE,
    eCode: 200,
    eString: ["freebirdFormviewerView", "docs-dm", "viewform"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  // Folder: human URL + embeddedfolderview check (anonymous shared-folder HTML).
  // Public folders confirm via flip-*/favicon_shared; private/auth → blocked; 404 → miss.
  // Never bury Drive-shaped ids in filtered when the response is merely ambiguous.
  {
    label: "Google Drive folder",
    url: "https://drive.google.com/drive/folders/{id}",
    checkUrl: "https://drive.google.com/embeddedfolderview?id={id}",
    check: "wmn",
    priority: 2,
    idShape: GOOGLE_FILE_ID_RE,
    eCode: 200,
    eString: ["favicon_shared", "flip-embedded", "flip-contents", "folderlandingpage"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Error 404", "Sorry, the file you have requested does not exist"],
    requireIdInUrl: true,
    ambiguousAsBlocked: true,
  },
  {
    label: "Google Drive file",
    url: "https://drive.google.com/file/d/{id}/view",
    check: "wmn",
    priority: 2,
    idShape: GOOGLE_FILE_ID_RE,
    eCode: 200,
    // Live viewer markup uses _DRIVE_VIEWER / docs-dm (not legacy "drive-viewer").
    eString: ["_DRIVE_VIEWER", "docs-dm", 'og:site_name" content="Google Docs"'],
    eStringMode: "any",
    mCode: 404,
    mString: ["Sorry, the file you have requested does not exist", "Error 404"],
    requireIdInUrl: true,
    ambiguousAsBlocked: true,
  },
  {
    label: "Imgur",
    url: "https://imgur.com/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ['property="og:image"', "i.imgur.com"],
    eStringMode: "all",
    mString: ["Imgur: The magic of the Internet"],
    requireIdInUrl: true,
  },
  {
    label: "Imgur album",
    url: "https://imgur.com/a/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ['property="og:image"', "/a/"],
    eStringMode: "all",
    requireIdInUrl: true,
  },
  {
    label: "YouTube",
    url: "https://youtu.be/{id}",
    check: "wmn",
    priority: 3,
    idShape: /^[\w-]{11}$/,
    eCode: 200,
    eString: ['"playabilityStatus":{"status":"OK"', "og:video:url"],
    eStringMode: "any",
    mString: ["Video unavailable", '"status":"ERROR"', '"status":"LOGIN_REQUIRED"'],
    requireIdInUrl: true,
  },
  {
    label: "YouTube watch",
    url: "https://www.youtube.com/watch?v={id}",
    check: "wmn",
    priority: 3,
    idShape: /^[\w-]{11}$/,
    eCode: 200,
    eString: ['"playabilityStatus":{"status":"OK"', "og:video:url"],
    eStringMode: "any",
    mString: ["Video unavailable", '"status":"ERROR"', '"status":"LOGIN_REQUIRED"'],
    requireIdInUrl: true,
  },
  {
    label: "Lightshot",
    url: "https://prnt.sc/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["screenshot-image", "no-footer__image"],
    eStringMode: "any",
    mString: ["image-404", "does not exist", "Page not found"],
    requireIdInUrl: true,
  },
  {
    label: "Gyazo",
    url: "https://gyazo.com/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ['property="og:image"', "i.gyazo.com"],
    eStringMode: "all",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Vocaroo",
    url: "https://voca.ro/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["media-url", "og:audio", "vocaroo-player"],
    eStringMode: "any",
    mString: ["Vocaroo | Online voice recorder"],
    requireIdInUrl: true,
  },
  {
    label: "Clyp",
    url: "https://clyp.it/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["audio/mp3", "clyp.it"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "MediaFire",
    url: "https://www.mediafire.com/file/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["aria-label=\"Download", "Download file"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Invalid or Deleted File", "File Restricted"],
    requireIdInUrl: true,
  },
  // Mega always returns a generic SPA shell — cannot confirm without JS crypto.
  { label: "Mega", url: "https://mega.nz/file/{id}", check: "skip", priority: 4 },
  {
    label: "Dropbox",
    url: "https://www.dropbox.com/s/{id}",
    check: "wmn",
    priority: 4,
    // Share codes are short; exclude Google Drive-length ids (≈33 chars).
    idShape: /^[a-z0-9]{10,22}$/i,
    eCode: 200,
    eString: ["shared-link", "is_dir", '"filename"'],
    eStringMode: "any",
    mString: ["Dropbox - Error", "error_page"],
    requireIdInUrl: true,
  },
  // Discord: WMN uses invite API (e_string "channel", m_string Unknown Invite).
  {
    label: "Discord invite",
    url: "https://discord.gg/{id}",
    checkUrl: "https://discord.com/api/v9/invites/{id}?with_counts=true&with_expiration=true",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: '"channel":',
    mCode: 404,
    mString: ["Unknown Invite", "Unknown Code", "invite invalid"],
    requireIdInUrl: false,
  },
  {
    label: "Discord invite (com)",
    url: "https://discord.com/invite/{id}",
    checkUrl: "https://discord.com/api/v9/invites/{id}?with_counts=true&with_expiration=true",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: '"channel":',
    mCode: 404,
    mString: ["Unknown Invite", "Unknown Code"],
    requireIdInUrl: false,
  },
  {
    label: "Reddit",
    url: "https://redd.it/{id}",
    check: "wmn",
    priority: 4,
    // Base36 post ids are typically short; long pure-decimal tokens are not redd.it.
    idShape: /^[a-z0-9]{5,10}$/i,
    eCode: 200,
    eString: ["shreddit-post", '"name":"t3_'],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  /**
   * Pinterest pin pages are JS shells — bare fetch cannot tell real vs fake.
   * check:"tab" opens one inactive tab, lets content.js inspect the hydrated DOM,
   * then closes it. Not used for every host (too noisy).
   */
  {
    label: "Pinterest pin",
    url: "https://www.pinterest.com/pin/{id}/",
    check: "tab",
    priority: 2,
    idShape: /^\d{10,20}$/,
    tabHost: "pinterest",
    tabSettleMs: 2800,
    requireIdInUrl: true,
  },
  {
    label: "Pinterest",
    url: "https://pin.it/{id}",
    check: "status",
    priority: 4,
    // pin.it codes are short alphanumerics, not long decimal pin ids
    idShape: /^[A-Za-z0-9]{4,12}$/,
    requireIdInUrl: true,
  },
  // Login / SPA shells — cannot reliably confirm; excluded from confirmed hits.
  { label: "Instagram", url: "https://www.instagram.com/p/{id}/", check: "skip", priority: 5 },
  { label: "Facebook", url: "https://www.facebook.com/{id}", check: "skip", priority: 5 },
  { label: "WhatsApp", url: "https://wa.me/{id}", check: "skip", priority: 5 },
  {
    label: "Vimeo",
    url: "https://vimeo.com/{id}",
    check: "wmn",
    priority: 5,
    idShape: /^\d{6,12}$/,
    eCode: 200,
    eString: ['property="og:video"', "player.vimeo.com"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Dailymotion",
    url: "https://www.dailymotion.com/video/{id}",
    check: "wmn",
    priority: 5,
    // DailyMotion video keys are typically like x7xxzz, not long decimals
    idShape: /^[a-zA-Z][a-zA-Z0-9]{4,12}$/,
    eCode: 200,
    eString: ['property="og:video"', 'property="og:video:url"'],
    eStringMode: "any",
    mCode: 404,
    mString: ["Page not found", "video is not available"],
    requireIdInUrl: true,
  },
  {
    label: "IMDb",
    url: "https://www.imdb.com/title/{id}/",
    check: "wmn",
    priority: 5,
    idShape: /^tt\d{7,8}$/i,
    eCode: 200,
    eString: ['"@type":"Movie"', '"@type":"TVSeries"', "ipc-page-content-container"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  { label: "Notion", url: "https://www.notion.so/{id}", check: "skip", priority: 5 },
  {
    label: "Imgflip",
    url: "https://imgflip.com/i/{id}",
    check: "wmn",
    priority: 5,
    eCode: 200,
    eString: ["imgflip.com/s_img", "meme-image"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  { label: "Google Meet", url: "https://meet.google.com/{id}", check: "skip", priority: 5 },
  // --- Hunt-native paste / media IDs (BOT-style cryptic hunts) ---
  {
    label: "ControlC",
    url: "https://controlc.com/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["paste_code", "paste-content", "controlc.com"],
    eStringMode: "any",
    mString: ["Paste not found", "404", "does not exist"],
    requireIdInUrl: true,
  },
  {
    label: "rentry",
    url: "https://rentry.co/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["rentry", "markdown", "entry-text"],
    eStringMode: "any",
    mCode: 404,
    mString: ["404", "Not Found", "does not exist"],
    requireIdInUrl: true,
  },
  {
    label: "rentry raw",
    url: "https://rentry.co/raw/{id}",
    check: "raw",
    priority: 1,
  },
  {
    label: "Scratch project",
    url: "https://scratch.mit.edu/projects/{id}/",
    check: "wmn",
    priority: 2,
    idShape: /^\d{6,12}$/,
    eCode: 200,
    eString: ["scratch", "project-title", '"title":'],
    eStringMode: "any",
    mCode: 404,
    mString: ["Scratch - Imagine, Program, Share"],
    requireIdInUrl: true,
  },
  {
    label: "Genius annotation",
    url: "https://genius.com/annotations/{id}",
    check: "wmn",
    priority: 2,
    idShape: /^\d{5,12}$/,
    eCode: 200,
    eString: ["annotation", "lyrics", "genius.com"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Spotify track",
    url: "https://open.spotify.com/track/{id}",
    check: "wmn",
    priority: 3,
    idShape: /^[A-Za-z0-9]{22}$/,
    eCode: 200,
    eString: ['"@type":"MusicRecording"', "track"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Spotify playlist",
    url: "https://open.spotify.com/playlist/{id}",
    check: "wmn",
    priority: 3,
    idShape: /^[A-Za-z0-9]{22}$/,
    eCode: 200,
    eString: ["playlist", '"@type":"MusicPlaylist"'],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Letterboxd film",
    url: "https://letterboxd.com/film/{id}/",
    check: "wmn",
    priority: 3,
    // Film slugs are short hyphenated words — not Google Drive-length ids.
    idShape: /^(?=.{2,40}$)[a-z0-9]+(?:-[a-z0-9]+)*$/i,
    eCode: 200,
    eString: ["film-title", "letterboxd.com/film", "film-poster"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Discord message snowflake",
    url: "https://discord.com/channels/@me/{id}",
    check: "hint",
    priority: 4,
    idShape: /^\d{17,20}$/,
  },
  {
    label: "IG highlight /s/",
    url: "https://www.instagram.com/s/{id}/",
    check: "hint",
    priority: 4,
    // Highlight /s/ tokens are shorter base64-ish — not 25–44 char Drive ids.
    idShape: /^[A-Za-z0-9_-]{8,24}$/,
  },
  {
    label: "file.garden",
    url: "https://file.garden/{id}",
    check: "status",
    priority: 3,
    requireIdInUrl: true,
  },
  {
    label: "catbox",
    url: "https://files.catbox.moe/{id}",
    check: "status",
    priority: 3,
    idShape: /^[a-z0-9]+\.[a-z0-9]+$/i,
    requireIdInUrl: true,
  },
  // --- Extra paste / short / media hosts (cryptic + OSINT) ---
  {
    label: "hastebin",
    url: "https://hastebin.com/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["hastebin", "button-save", "code-line"],
    eStringMode: "any",
    mCode: 404,
    mString: ["not found", "Document not found"],
    requireIdInUrl: true,
  },
  {
    label: "hastebin raw",
    url: "https://hastebin.com/raw/{id}",
    check: "raw",
    priority: 1,
  },
  {
    label: "paste.ee",
    url: "https://paste.ee/p/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["paste.ee", "paste-content", "hljs"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Paste not found", "404"],
    requireIdInUrl: true,
  },
  {
    label: "dpaste",
    url: "https://dpaste.com/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["dpaste", "paste_wrapper", "hljs"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "justpaste.it",
    url: "https://justpaste.it/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["justpaste", "articleContent", "jp-article"],
    eStringMode: "any",
    mString: ["Page not found", "does not exist", "404"],
    requireIdInUrl: true,
  },
  {
    label: "Mozilla Paste",
    url: "https://paste.mozilla.org/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["pastebin-theme", "CodeMirror", "paste.mozilla"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Telegra.ph",
    url: "https://telegra.ph/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["tl_article", "tl_article_content", "og:site_name"],
    eStringMode: "any",
    mCode: 404,
    mString: ["404", "Page not found"],
    requireIdInUrl: true,
  },
  {
    label: "GitHub Gist",
    url: "https://gist.github.com/{id}",
    check: "wmn",
    priority: 2,
    // Gist ids are hex; exclude short paste tokens and Drive-length ids when pure decimal.
    idShape: /^[a-f0-9]{7,40}$/i,
    eCode: 200,
    eString: ["gist-content", "js-gist-file-update-container", "octotree"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Not Found", "gist not found"],
    requireIdInUrl: true,
  },
  {
    label: "rentry.org",
    url: "https://rentry.org/{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["rentry", "markdown", "entry-text"],
    eStringMode: "any",
    mCode: 404,
    mString: ["404", "Not Found", "does not exist"],
    requireIdInUrl: true,
  },
  {
    label: "write.as",
    url: "https://write.as/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["write.as", "post-title", "article"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "is.gd",
    url: "https://is.gd/{id}",
    check: "status",
    priority: 1,
    requireIdInUrl: true,
  },
  {
    label: "v.gd",
    url: "https://v.gd/{id}",
    check: "status",
    priority: 1,
    requireIdInUrl: true,
  },
  {
    label: "cutt.ly",
    url: "https://cutt.ly/{id}",
    check: "status",
    priority: 1,
    requireIdInUrl: true,
  },
  {
    label: "rb.gy",
    url: "https://rb.gy/{id}",
    check: "status",
    priority: 2,
    requireIdInUrl: true,
  },
  {
    label: "ibb.co",
    url: "https://ibb.co/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["image-viewer", "og:image", "ibb.co"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Page not found", "Image not found"],
    requireIdInUrl: true,
  },
  {
    label: "postimg",
    url: "https://postimg.cc/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["postimg", "og:image", "main-image"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "litterbox",
    url: "https://litter.catbox.moe/{id}",
    check: "status",
    priority: 3,
    idShape: /^[a-z0-9]+\.[a-z0-9]+$/i,
    requireIdInUrl: true,
  },
  {
    label: "Streamable",
    url: "https://streamable.com/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["streamable", "og:video", "video-container"],
    eStringMode: "any",
    mCode: 404,
    mString: ["not found", "Page not found"],
    requireIdInUrl: true,
  },
  {
    label: "Pixeldrain",
    url: "https://pixeldrain.com/u/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["pixeldrain", "file_name", "download"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "gofile",
    url: "https://gofile.io/d/{id}",
    check: "status",
    priority: 4,
    requireIdInUrl: true,
  },
  {
    label: "archive.ph",
    url: "https://archive.ph/{id}",
    check: "status",
    priority: 4,
    requireIdInUrl: true,
  },
  {
    label: "archive.is",
    url: "https://archive.is/{id}",
    check: "status",
    priority: 4,
    requireIdInUrl: true,
  },
  {
    label: "Trello card",
    url: "https://trello.com/c/{id}",
    check: "wmn",
    priority: 4,
    idShape: /^[a-zA-Z0-9]{8,12}$/,
    eCode: 200,
    eString: ["trello", "card-detail", "js-card-name"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "JSFiddle",
    url: "https://jsfiddle.net/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["jsfiddle", "editorCont", "actionCont"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
];

const USERNAME_TEMPLATES = [
  {
    label: "GitHub",
    url: "https://github.com/{id}",
    checkUrl: "https://api.github.com/users/{id}",
    check: "wmn",
    priority: 0,
    eCode: 200,
    // Prefer "login" over bare "id" — error/docs JSON often contains "id"-like keys.
    eString: '"login":',
    mCode: 404,
    mString: ['"message":"Not Found"', '"message": "Not Found"', "Not Found"],
    requireIdInUrl: false,
  },
  {
    label: "GitLab",
    url: "https://gitlab.com/{id}",
    checkUrl: "https://gitlab.com/api/v4/users?username={id}",
    check: "wmn",
    priority: 0,
    eCode: 200,
    eString: '"id":',
    mString: "[]",
    requireIdInUrl: false,
  },
  {
    label: "Reddit user",
    url: "https://www.reddit.com/user/{id}",
    checkUrl: "https://www.reddit.com/user/{id}/about.json",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: '"id":',
    mCode: 404,
    mString: ['"error":404', "Not Found"],
    requireIdInUrl: false,
  },
  // Instagram / Facebook / X / LinkedIn: login walls & soft-200s — skip auto-confirm.
  { label: "Instagram", url: "https://www.instagram.com/{id}/", check: "skip", priority: 1 },
  { label: "X / Twitter", url: "https://x.com/{id}", check: "skip", priority: 1 },
  {
    label: "YouTube @",
    url: "https://www.youtube.com/@{id}",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: "canonicalBaseUrl",
    mCode: 404,
    mString: ["<title>404 Not Found</title>", "This page isn't available"],
    requireIdInUrl: true,
  },
  {
    label: "TikTok",
    url: "https://www.tiktok.com/@{id}",
    checkUrl: "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: '"author_url":',
    mCode: 400,
    mString: ['"code":400', "Something went wrong"],
    requireIdInUrl: false,
  },
  { label: "Facebook", url: "https://www.facebook.com/{id}", check: "skip", priority: 2 },
  { label: "LinkedIn", url: "https://www.linkedin.com/in/{id}", check: "skip", priority: 2 },
  {
    label: "Medium",
    url: "https://medium.com/@{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["Medium member since", "Followers"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Out of nothing, something", "PAGE_NOT_FOUND"],
    requireIdInUrl: true,
  },
  {
    label: "Dev.to",
    url: "https://dev.to/{id}",
    checkUrl: "https://dev.to/api/users/by_username?url={id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: '"id":',
    mCode: 404,
    mString: '"status":404',
    requireIdInUrl: false,
  },
  {
    label: "HackerOne",
    url: "https://hackerone.com/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["profile-header", "HackerOne"],
    eStringMode: "all",
    mString: ["Page not found", "NOT_FOUND"],
    requireIdInUrl: true,
  },
  {
    label: "Keybase",
    url: "https://keybase.io/{id}",
    checkUrl: "https://keybase.io/_/api/1.0/user/lookup.json?usernames={id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: '"id":',
    mString: '"them":[null]',
    requireIdInUrl: false,
  },
  {
    label: "About.me",
    url: "https://about.me/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: "| about.me",
    mCode: 404,
    mString: "<title>about.me</title>",
    requireIdInUrl: true,
  },
  {
    label: "Twitch",
    url: "https://www.twitch.tv/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["isLiveBroadcast", "twitch.tv/", "og:video"],
    eStringMode: "any",
    mString: ["Sorry. Unless you've got a time machine", "page does not exist"],
    requireIdInUrl: true,
  },
  {
    label: "Pinterest",
    url: "https://www.pinterest.com/{id}/",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: " - Profile | Pinterest",
    mString: ['id="home-main-title', "page not found"],
    requireIdInUrl: true,
  },
  {
    label: "Telegram",
    url: "https://t.me/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: "tgme_page_title",
    mString: "noindex, nofollow",
    requireIdInUrl: true,
  },
  {
    label: "Steam",
    url: "https://steamcommunity.com/id/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: "g_rgProfileData =",
    mString: "Steam Community :: Error",
    requireIdInUrl: true,
  },
  // --- Extra profile hosts (username mode) ---
  {
    label: "Scratch user",
    url: "https://scratch.mit.edu/users/{id}/",
    check: "wmn",
    priority: 1,
    eCode: 200,
    eString: ["scratch", "profile-details", "user-name"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Scratch - Imagine, Program, Share", "not found"],
    requireIdInUrl: true,
  },
  {
    label: "SoundCloud",
    url: "https://soundcloud.com/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["soundcloud", "profileHeader", "og:type"],
    eStringMode: "any",
    mCode: 404,
    mString: ["We can’t find that user", "Page not found"],
    requireIdInUrl: true,
  },
  {
    label: "Bandcamp",
    url: "https://bandcamp.com/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["bandcamp", "fan-bio", "collection-items"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Codeberg",
    url: "https://codeberg.org/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["codeberg", "profile", "user-profile"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Bitbucket",
    url: "https://bitbucket.org/{id}/",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["bitbucket", "profile", "user-card"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Hacker News",
    url: "https://news.ycombinator.com/user?id={id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["created:", "karma:", "user?id="],
    eStringMode: "any",
    mString: ["No such user", "Unknown."],
    requireIdInUrl: true,
  },
  {
    label: "Bluesky",
    url: "https://bsky.app/profile/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["bsky.app", "ProfileView", "og:title"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Not found", "Unable to load"],
    requireIdInUrl: true,
  },
  {
    label: "Flickr",
    url: "https://www.flickr.com/people/{id}/",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["flickr", "person-profile", "og:profile"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Tumblr",
    url: "https://www.tumblr.com/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["tumblr", "blog-title", "og:type"],
    eStringMode: "any",
    mCode: 404,
    mString: ["There's nothing here", "not found"],
    requireIdInUrl: true,
  },
  {
    label: "DeviantArt",
    url: "https://www.deviantart.com/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["deviantart", "user-profile", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Roblox",
    url: "https://www.roblox.com/users/profile?username={id}",
    check: "status",
    priority: 3,
    requireIdInUrl: false,
  },
  {
    label: "Lichess",
    url: "https://lichess.org/@/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["lichess", "user-show", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Chess.com",
    url: "https://www.chess.com/member/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["chess.com", "profile-header", "user-username"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Page not found", "User not found"],
    requireIdInUrl: true,
  },
  {
    label: "Replit",
    url: "https://replit.com/@{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["replit", "profile", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "CodePen",
    url: "https://codepen.io/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["codepen", "profile-header", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "npm",
    url: "https://www.npmjs.com/~{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["npm", "profile", "~"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Docker Hub",
    url: "https://hub.docker.com/u/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["docker", "orgname", "profile"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Neocities",
    url: "https://neocities.org/site/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["neocities", "site-info", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Linktree",
    url: "https://linktr.ee/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["linktr.ee", "ProfileCard", "og:title"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Page not found", "doesn't exist"],
    requireIdInUrl: true,
  },
  {
    label: "Letterboxd user",
    url: "https://letterboxd.com/{id}/",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["letterboxd", "profile-header", "person-summary"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Last.fm",
    url: "https://www.last.fm/user/{id}",
    check: "wmn",
    priority: 3,
    eCode: 200,
    eString: ["last.fm", "header-new-title", "user-dashboard"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Behance",
    url: "https://www.behance.net/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["behance", "Profile", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Dribbble",
    url: "https://dribbble.com/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["dribbble", "profile-header", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "TryHackMe",
    url: "https://tryhackme.com/p/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["tryhackme", "profile", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Hack The Box",
    url: "https://app.hackthebox.com/users/{id}",
    check: "hint",
    priority: 4,
  },
  {
    label: "Vimeo user",
    url: "https://vimeo.com/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["vimeo", "profile", "og:type"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Spotify user",
    url: "https://open.spotify.com/user/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["spotify", "profile", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Pastebin user",
    url: "https://pastebin.com/u/{id}",
    check: "wmn",
    priority: 2,
    eCode: 200,
    eString: ["pastebin", "user-view", "profile"],
    eStringMode: "any",
    mString: ["Not Found (#404)", "This page has been removed"],
    requireIdInUrl: true,
  },
  {
    label: "Wikipedia user",
    url: "https://en.wikipedia.org/wiki/User:{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["mw-userpage", "User:", "og:title"],
    eStringMode: "any",
    mCode: 404,
    mString: ["Wikipedia does not have a", "no user by this name"],
    requireIdInUrl: true,
  },
  {
    label: "Kaggle",
    url: "https://www.kaggle.com/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["kaggle", "profile__name", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  {
    label: "Hugging Face",
    url: "https://huggingface.co/{id}",
    check: "wmn",
    priority: 4,
    eCode: 200,
    eString: ["huggingface", "profile", "og:title"],
    eStringMode: "any",
    mCode: 404,
    requireIdInUrl: true,
  },
  { label: "Carrd", url: "https://{id}.carrd.co", check: "status", priority: 4 },
];

const HUNT_BASE_PATHS = [
  "/{id}",
  "/raw/{id}",
  "/p/{id}",
  "/a/{id}",
  "/file/{id}",
  "/paste/{id}",
];

/** Common profile-style paths probed on origin / hunt base in username mode (/{id} is first via HUNT_BASE_PATHS). */
const HUNT_BASE_USERNAME_EXTRA_PATHS = ["/user/{id}", "/u/{id}", "/profile/{id}"];

/** Extra templates under a non-root page directory (static /practice/*.html etc.). */
const HUNT_BASE_DIR_EXTRA_PATHS = ["/{id}.html"];

/** Path templates for this-site / hunt-base probes (ID vs username mode). */
function huntBasePathsForProbe(mode, isDir) {
  const rootPaths =
    mode === "username"
      ? ["/{id}"]
          .concat(HUNT_BASE_USERNAME_EXTRA_PATHS)
          .concat(HUNT_BASE_PATHS.filter((p) => p !== "/{id}"))
      : HUNT_BASE_PATHS;
  return isDir ? rootPaths.concat(HUNT_BASE_DIR_EXTRA_PATHS) : rootPaths;
}

/**
 * Normalize pinned hunt base: always keep origin root ("") plus any path variants.
 * Legacy pins without `paths` migrate from `url` pathname when present.
 */
function normalizeHuntBase(raw) {
  if (!raw || !raw.origin) return null;
  let origin = String(raw.origin || "").replace(/\/+$/, "");
  let host = raw.host || "";
  try {
    const u = new URL(origin);
    origin = u.origin;
    host = host || u.host;
  } catch (_err) {
    return null;
  }

  const pathSet = new Set([""]);
  if (Array.isArray(raw.paths)) {
    for (const p of raw.paths) {
      if (p == null) continue;
      let s = String(p).trim();
      if (!s || s === "/") {
        pathSet.add("");
        continue;
      }
      if (!s.startsWith("/")) s = "/" + s;
      s = s.replace(/\/+$/, "");
      pathSet.add(s || "");
    }
  } else if (raw.url) {
    try {
      const u = new URL(raw.url);
      if (u.origin === origin) {
        let p = u.pathname.replace(/\/+$/, "") || "";
        if (p === "/") p = "";
        if (p) pathSet.add(p);
      }
    } catch (_err) {
      /* ignore */
    }
  }

  const paths = Array.from(pathSet);
  paths.sort((a, b) => a.length - b.length || a.localeCompare(b));
  return {
    origin,
    host,
    url: raw.url || origin,
    paths,
    pinnedAt: raw.pinnedAt || Date.now(),
  };
}

/** Prefixes to probe: origin root + each saved subpath (deduped). */
function huntBasePrefixes(huntBase) {
  const hb = normalizeHuntBase(huntBase);
  if (!hb) return [];
  return hb.paths.map((path) => ({
    prefix: hb.origin + (path || ""),
    pathLabel: path || "",
  }));
}

/**
 * Directory path of a page URL for path-aware ID probes.
 * Strips trailing slash and document filenames (e.g. index.html, *.html).
 * Returns "" for site root, or e.g. "/practice".
 */
function directoryPathFromUrl(pageUrl) {
  if (!pageUrl || INTERNAL_URL.test(pageUrl)) return "";
  try {
    const u = new URL(pageUrl);
    let path = u.pathname || "/";
    if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
    if (!path || path === "/") return "";
    const segments = path.split("/").filter(Boolean);
    if (!segments.length) return "";
    const last = segments[segments.length - 1];
    if (/\.(html?|php|aspx?|jsp|cgi|xhtml)$/i.test(last) || /^index$/i.test(last)) {
      segments.pop();
    }
    if (!segments.length) return "";
    return "/" + segments.join("/");
  } catch (_err) {
    return "";
  }
}

function mergeHuntBasePin(existing, url) {
  let origin = "";
  let host = "";
  let path = "";
  try {
    const u = new URL(url);
    origin = u.origin;
    host = u.host;
    path = u.pathname.replace(/\/+$/, "") || "";
    if (path === "/") path = "";
  } catch (_err) {
    return null;
  }

  const prev = normalizeHuntBase(existing);
  if (prev && prev.origin === origin) {
    const pathSet = new Set(prev.paths);
    pathSet.add("");
    if (path) pathSet.add(path);
    const paths = Array.from(pathSet);
    paths.sort((a, b) => a.length - b.length || a.localeCompare(b));
    return {
      origin,
      host,
      url,
      paths,
      pinnedAt: Date.now(),
    };
  }

  const paths = path ? ["", path] : [""];
  return {
    origin,
    host,
    url,
    paths,
    pinnedAt: Date.now(),
  };
}

/** Global missing-page phrases (fallback only after host rules). */
const SOFT_404_RE =
  /post isn.?t available|invite invalid|invalid invite|page not found|sorry,? this page isn.?t available|this page isn.?t available|content isn.?t available|profile may have been removed|broken link|error-404|does not exist|user not found|nobody by that name|there isn.?t a github|hold up!|account suspended|the link you followed may be broken|this invite may be invalid|couldn.?t find this account|unknown invite|dropbox - error|video unavailable|has been removed|no longer available|bad api request|pastebin\.com\/error|not found \(#404\)/i;

/**
 * Auth walls, rate limits, captchas — ambiguous, NOT a soft-404 miss.
 * These must stay visible for manual open/verify (esp. GitHub/GitLab APIs).
 */
const BLOCKED_BODY_RE =
  /api rate limit|rate limit(?:ed|ing)? exceeded|rate.?limit|too many requests|retry later|just a moment\.\.\.|cf-browser-verification|cf-challenge|attention required|enable javascript(?: and cookies)? to continue|access denied|captcha|cloudflare|authentication required|403 forbidden|request blocked|unusual traffic|are you a robot|verify you are (?:a )?human|abuse detection|temporary ban/i;

function isBlockedHttpStatus(status) {
  return (
    status === 401 ||
    status === 403 ||
    status === 429 ||
    status === 502 ||
    status === 503 ||
    status === 504
  );
}

function bodyLooksBlocked(sample) {
  if (!sample) return false;
  return BLOCKED_BODY_RE.test(String(sample).slice(0, 16000));
}

let probeAbort = null;

function normalizeProbeId(raw, mode) {
  let s = String(raw || "").trim().replace(/^@+/, "");
  try {
    if (/^https?:\/\//i.test(s)) {
      const u = new URL(s);
      const parts = u.pathname.split("/").filter(Boolean);
      s = parts[parts.length - 1] || s;
      s = s.replace(/^@/, "");
    }
  } catch (_err) {
    /* keep */
  }
  s = s.replace(/^[#/?]+/, "").trim();
  if (mode === "username") {
    if (!/^[A-Za-z0-9._-]{1,39}$/.test(s)) return "";
    return s;
  }
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(s)) return "";
  return s;
}

function fillTemplate(tpl, id) {
  // Keep @ for YouTube-style templates already in the string.
  return tpl.split("{id}").join(encodeURIComponent(id).replace(/%2D/gi, "-").replace(/%40/gi, "@"));
}

function urlContainsId(url, id) {
  if (!id || !url) return false;
  return url.indexOf(id) !== -1 || url.indexOf(encodeURIComponent(id)) !== -1;
}

function asStringList(v) {
  if (v == null || v === "") return [];
  return Array.isArray(v) ? v.filter(Boolean) : [v];
}

function bodyHasAny(sample, needles) {
  const list = asStringList(needles);
  if (!list.length) return false;
  const s = String(sample || "");
  return list.some((n) => s.indexOf(n) !== -1);
}

function bodyHasAll(sample, needles) {
  const list = asStringList(needles);
  if (!list.length) return true;
  const s = String(sample || "");
  return list.every((n) => s.indexOf(n) !== -1);
}

function matchEString(sample, rule) {
  const needles = asStringList(rule.eString);
  if (!needles.length) return false;
  return rule.eStringMode === "all" ? bodyHasAll(sample, needles) : bodyHasAny(sample, needles);
}

function matchMString(sample, rule) {
  return bodyHasAny(sample, rule.mString);
}

function statusMatches(status, code) {
  if (code == null) return false;
  if (Array.isArray(code)) return code.indexOf(status) !== -1;
  return status === code;
}

/**
 * WMN-style classify: confirmed only with positive e signals.
 * Check e_string before m_string (avoids short m needles like "[]" false-missing).
 * Missing / soft-404 / ambiguous → not a hit.
 */
function classifyWmn(status, text, finalUrl, id, rule) {
  const sample = String(text || "").slice(0, 64000);
  const needId = rule.requireIdInUrl !== false;

  if (needId && id && !urlContainsId(finalUrl, id)) {
    // Login bounce / soft redirect — keep Drive-shaped probes visible when requested.
    if (rule.ambiguousAsBlocked) {
      return { hit: false, kind: "blocked", error: "redirect-lost-id" };
    }
    return { hit: false, kind: "miss", error: "redirect-lost-id" };
  }

  const hasEString = asStringList(rule.eString).length > 0;
  const codeOk = rule.eCode == null || statusMatches(status, rule.eCode);

  // Positive existence first — bare eCode 200 is never enough without eString.
  if (hasEString && codeOk && matchEString(sample, rule)) {
    return { hit: true, kind: "hit", error: "" };
  }

  if (matchMString(sample, rule)) {
    return { hit: false, kind: "miss", error: "m-string" };
  }
  if (rule.mCode != null && statusMatches(status, rule.mCode)) {
    return { hit: false, kind: "miss", error: "m-code" };
  }

  // Auth / rate-limit / captcha body ≠ missing — open to verify.
  if (isBlockedHttpStatus(status) || bodyLooksBlocked(sample)) {
    return { hit: false, kind: "blocked", error: "auth-or-rate-limit" };
  }

  if (!sample || SOFT_404_RE.test(sample.slice(0, 16000))) {
    return { hit: false, kind: "miss", error: "soft-404" };
  }

  // Ambiguous 200 / partial match — do not confirm.
  // Some hosts (Drive folder/file) must stay visible for manual check.
  if (rule.ambiguousAsBlocked) {
    return {
      hit: false,
      kind: "blocked",
      error: hasEString ? "unconfirmed-manual" : "no-e-string-manual",
    };
  }
  return { hit: false, kind: "miss", error: hasEString ? "unconfirmed" : "no-e-string" };
}

function buildProbeTargets(id, pageUrl, huntBase, mode) {
  const targets = [];
  const seen = new Set();
  const templates = mode === "username" ? USERNAME_TEMPLATES : BACKLINK_TEMPLATES;

  function add(tpl, group) {
    if (!tpl || tpl.valid === false) return;
    // "skip" = never probe. "hint" = always surface as manual-check without fetch.
    if (tpl.check === "skip") return;
    if (tpl.idShape && id && !tpl.idShape.test(id)) return;
    const displayUrl = fillTemplate(tpl.url, id);
    if (!displayUrl || seen.has(displayUrl)) return;
    seen.add(displayUrl);
    targets.push({
      label: tpl.label,
      url: displayUrl,
      checkUrl: tpl.checkUrl ? fillTemplate(tpl.checkUrl, id) : "",
      group: group || "service",
      check: tpl.check || "wmn",
      priority: tpl.priority == null ? 5 : tpl.priority,
      eCode: tpl.eCode,
      eString: tpl.eString,
      eStringMode: tpl.eStringMode || "any",
      mCode: tpl.mCode,
      mString: tpl.mString,
      requireIdInUrl: tpl.requireIdInUrl,
      ambiguousAsBlocked: Boolean(tpl.ambiguousAsBlocked),
      tabHost: tpl.tabHost || "",
      tabSettleMs: tpl.tabSettleMs || 2500,
      bodyBytes: tpl.bodyBytes || 0,
      soft404Body: Boolean(tpl.soft404Body),
    });
  }

  const sorted = templates.slice().sort((a, b) => (a.priority || 0) - (b.priority || 0));
  for (const t of sorted) {
    add(t, "service");
  }

  const pageDir = directoryPathFromUrl(pageUrl || "");
  let pageOrigin = "";
  try {
    if (pageUrl && !INTERNAL_URL.test(pageUrl)) {
      pageOrigin = new URL(pageUrl).origin;
    }
  } catch (_err) {
    pageOrigin = "";
  }

  // This-site: origin root + current directory (e.g. /practice/) with same path templates.
  if (pageOrigin) {
    const sitePrefixes = [{ prefix: pageOrigin, tag: "This site", isDir: false }];
    if (pageDir) {
      sitePrefixes.push({
        prefix: pageOrigin + pageDir,
        tag: "This site " + pageDir,
        isDir: true,
      });
    }
    for (const { prefix, tag, isDir } of sitePrefixes) {
      for (const path of huntBasePathsForProbe(mode, isDir)) {
        add(
          {
            label: tag + " " + path.replace("{id}", "…"),
            url: prefix + fillTemplate(path, id),
            check: "status",
            priority: 6,
            requireIdInUrl: true,
            soft404Body: true,
          },
          "current"
        );
      }
    }
  }

  // Hunt base: saved roots/subpaths + active-tab directory when host-only pin.
  if (huntBase) {
    const prefixes = huntBasePrefixes(huntBase);
    const hb = normalizeHuntBase(huntBase);
    if (hb && pageOrigin && pageOrigin === hb.origin && pageDir) {
      const already = hb.paths.indexOf(pageDir) !== -1;
      if (!already) {
        prefixes.push({
          prefix: hb.origin + pageDir,
          pathLabel: pageDir,
        });
      }
    }
    for (const { prefix, pathLabel } of prefixes) {
      const baseTag = pathLabel ? "Hunt base " + pathLabel : "Hunt base";
      const isDir = Boolean(pathLabel);
      for (const path of huntBasePathsForProbe(mode, isDir)) {
        add(
          {
            label: baseTag + " " + path.replace("{id}", "…"),
            url: prefix + fillTemplate(path, id),
            check: "status",
            priority: 6,
            requireIdInUrl: true,
            soft404Body: true,
          },
          "hunt-base"
        );
      }
    }
  }

  return targets;
}

/** Serialize hidden-tab probes so we never open a burst of tabs. */
let tabProbeChain = Promise.resolve();
function withTabProbeLock(fn) {
  const run = tabProbeChain.then(fn, fn);
  tabProbeChain = run.then(
    () => undefined,
    () => undefined
  );
  return run;
}

function waitTabComplete(tabId, timeoutMs) {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        browser.tabs.onUpdated.removeListener(onUpdated);
      } catch (_e) {
        /* ignore */
      }
      if (err) reject(err);
      else resolve();
    };
    const timer = setTimeout(() => finish(new Error("tab-timeout")), timeoutMs);
    function onUpdated(id, info) {
      if (id === tabId && info.status === "complete") finish(null);
    }
    browser.tabs.onUpdated.addListener(onUpdated);
    browser.tabs
      .get(tabId)
      .then((tab) => {
        if (tab && tab.status === "complete") finish(null);
      })
      .catch(() => {});
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Stronger existence check for JS shells (Pinterest): open one inactive tab,
 * ask content.js for DOM signals, close the tab. Default probes stay on fetch.
 */
async function probeViaHiddenTab(target, id) {
  return withTabProbeLock(async () => {
    let tabId = null;
    try {
      const tab = await browser.tabs.create({ url: target.url, active: false });
      tabId = tab.id;
      await waitTabComplete(tabId, 20000);
      await sleep(target.tabSettleMs || 2500);
      let page = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          page = await browser.tabs.sendMessage(
            tabId,
            {
              type: MSG.PROBE_PAGE_CHECK,
              id,
              host: target.tabHost || "",
            },
            { frameId: 0 }
          );
          if (page) break;
        } catch (_err) {
          await sleep(700);
        }
      }
      const finalUrl = (page && page.href) || target.url;
      if (!page) {
        return {
          url: target.url,
          finalUrl,
          status: 0,
          hit: false,
          kind: "miss",
          error: "tab-no-content-script",
        };
      }
      if (page.blocked) {
        return {
          url: target.url,
          finalUrl,
          status: page.status || 0,
          hit: false,
          kind: "blocked",
          error: "tab-blocked",
        };
      }
      if (page.missing) {
        return {
          url: target.url,
          finalUrl,
          status: page.status || 200,
          hit: false,
          kind: "miss",
          error: "tab-missing",
        };
      }
      if (page.exists) {
        return {
          url: target.url,
          finalUrl,
          status: page.status || 200,
          hit: true,
          kind: "hit",
          error: "",
        };
      }
      return {
        url: target.url,
        finalUrl,
        status: page.status || 200,
        hit: false,
        kind: "miss",
        error: "tab-unconfirmed",
      };
    } catch (err) {
      return {
        url: target.url,
        finalUrl: target.url,
        status: 0,
        hit: false,
        kind: "error",
        error: String(err && err.message ? err.message : err),
      };
    } finally {
      if (tabId != null) {
        try {
          await browser.tabs.remove(tabId);
        } catch (_err) {
          /* ignore */
        }
      }
    }
  });
}

async function probeOne(target, id) {
  const displayUrl = target.url;
  const fetchUrl = target.checkUrl || target.url;
  const check = target.check || "wmn";

  // Shape-matched hosts that cannot be auto-confirmed — still show in UI.
  if (check === "hint") {
    return {
      url: displayUrl,
      finalUrl: displayUrl,
      status: 0,
      hit: false,
      kind: "blocked",
      error: "manual-check",
    };
  }

  if (check === "tab") {
    return probeViaHiddenTab(target, id);
  }

  try {
    const res = await fetch(fetchUrl, {
      method: "GET",
      redirect: "follow",
      credentials: "omit",
      cache: "no-store",
      headers: {
        Accept: "text/html,application/json;q=0.9,*/*;q=0.8",
      },
    });
    const status = res.status;
    // Prefer display URL when we used an API checkUrl; keep fetch final for shape checks.
    const fetchFinal = res.url || fetchUrl;
    const finalUrl = target.checkUrl ? displayUrl : fetchFinal;

    // Auth / rate-limit / gateway — not a miss; UI surfaces for manual check.
    if (isBlockedHttpStatus(status)) {
      return {
        url: displayUrl,
        finalUrl,
        status,
        hit: false,
        kind: "blocked",
        error: "http-" + status,
      };
    }

    // status-only shorteners: 2xx + id survives redirect; 404/410 = miss.
    // this-site / hunt-base also reject soft-404 HTML bodies (demo returns 200).
    if (check === "status") {
      if (status === 404 || status === 410) {
        return { url: displayUrl, finalUrl: fetchFinal, status, hit: false, kind: "miss", error: "" };
      }
      if (status < 200 || status >= 400) {
        return { url: displayUrl, finalUrl: fetchFinal, status, hit: false, kind: "miss", error: "" };
      }
      if (target.soft404Body || target.group === "current" || target.group === "hunt-base") {
        try {
          const buf = await res.arrayBuffer();
          const sample = new TextDecoder("utf-8", { fatal: false }).decode(
            buf.slice(0, 16000)
          );
          if (SOFT_404_RE.test(sample)) {
            return {
              url: displayUrl,
              finalUrl: fetchFinal,
              status,
              hit: false,
              kind: "miss",
              error: "soft-404",
            };
          }
        } catch (_err) {
          /* fall through to shape check */
        }
      }
      const needId = target.requireIdInUrl !== false;
      const idOk = !needId || !id || urlContainsId(fetchFinal, id);
      // Reject bounce to bare origins (soft catch-alls).
      let shapeOk = idOk;
      if (idOk && id) {
        try {
          const u = new URL(fetchFinal);
          const path = (u.pathname || "/").replace(/\/+$/, "") || "/";
          if (path === "/" || path === "") shapeOk = false;
        } catch (_err) {
          /* keep */
        }
      }
      return {
        url: displayUrl,
        finalUrl: fetchFinal,
        status,
        hit: shapeOk,
        kind: shapeOk ? "hit" : "miss",
        error: shapeOk ? "" : "status-unconfirmed",
      };
    }

    const maxBytes = target.bodyBytes || (check === "raw" ? 48000 : 256000);
    const buf = await res.arrayBuffer();
    const bytes = new Uint8Array(buf.slice(0, maxBytes));
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);

    if (check === "raw") {
      const trimmed = text.trim();
      const isHtml = /<!doctype html|<html/i.test(trimmed);
      const empty = trimmed.length < 2;
      if (bodyLooksBlocked(trimmed)) {
        return {
          url: displayUrl,
          finalUrl: fetchFinal,
          status,
          hit: false,
          kind: "blocked",
          error: "auth-or-rate-limit",
        };
      }
      const err =
        /bad api request|not found|paste not found|error/i.test(trimmed) && trimmed.length < 200;
      const hit = status >= 200 && status < 300 && !empty && !isHtml && !err;
      return {
        url: displayUrl,
        finalUrl: fetchFinal,
        status,
        hit,
        kind: hit ? "hit" : "miss",
        error: hit ? "" : "raw-miss",
      };
    }

    // Hard HTTP misses (before WMN string checks — still allow mCode 404 with body).
    if (status === 404 || status === 410) {
      return { url: displayUrl, finalUrl, status, hit: false, kind: "miss", error: "" };
    }
    // Body-level auth/captcha/rate-limit before treating other 4xx as miss.
    if (bodyLooksBlocked(text)) {
      return {
        url: displayUrl,
        finalUrl,
        status,
        hit: false,
        kind: "blocked",
        error: "auth-or-rate-limit",
      };
    }
    if (status < 200 || status >= 400) {
      return { url: displayUrl, finalUrl, status, hit: false, kind: "miss", error: "" };
    }

    // WMN-style (default): positive e_string required.
    const shapeUrl = fetchFinal;
    const classified = classifyWmn(status, text, shapeUrl, id, target);
    return {
      url: displayUrl,
      finalUrl,
      status,
      hit: classified.hit,
      kind: classified.kind,
      error: classified.error || "",
    };
  } catch (err) {
    // Network / abort / CORS — open to verify, not a soft miss.
    return {
      url: displayUrl,
      finalUrl: displayUrl,
      status: 0,
      hit: false,
      kind: "blocked",
      error: "fetch-failed",
    };
  }
}

function shapeLikely(id, mode) {
  if (mode === "username") {
    return [
      { label: "GitHub", url: "https://github.com/" + id, group: "likely" },
      { label: "Reddit user", url: "https://www.reddit.com/user/" + id, group: "likely" },
    ];
  }
  const out = [];
  if (/^\d{12,20}$/.test(id)) {
    out.push({
      label: "Pinterest pin",
      url: "https://www.pinterest.com/pin/" + id + "/",
      group: "likely",
    });
  }
  if (/^[A-Za-z0-9]{8}$/.test(id)) {
    out.push({ label: "Pastebin", url: "https://pastebin.com/" + id, group: "likely" });
    out.push({ label: "Pastebin raw", url: "https://pastebin.com/raw/" + id, group: "likely" });
  }
  if (/^[a-z0-9]{6}$/i.test(id)) {
    out.push({ label: "Lightshot", url: "https://prnt.sc/" + id, group: "likely" });
  }
  if (/^[A-Za-z0-9_-]{11}$/.test(id)) {
    out.push({ label: "YouTube", url: "https://youtu.be/" + id, group: "likely" });
  }
  if (GOOGLE_FILE_ID_RE.test(id)) {
    out.push({
      label: "Google Drive folder",
      url: "https://drive.google.com/drive/folders/" + id,
      group: "likely",
    });
    out.push({
      label: "Google Drive file",
      url: "https://drive.google.com/file/d/" + id + "/view",
      group: "likely",
    });
    out.push({
      label: "Google Sheets",
      url: "https://docs.google.com/spreadsheets/d/" + id + "/edit",
      group: "likely",
    });
    out.push({
      label: "Google Docs",
      url: "https://docs.google.com/document/d/" + id + "/edit",
      group: "likely",
    });
  }
  return out;
}

function priorityOfLabel(label) {
  const all = BACKLINK_TEMPLATES.concat(USERNAME_TEMPLATES);
  const found = all.find((t) => t.label === label);
  return found && found.priority != null ? found.priority : 9;
}

async function runBacklinkProbe(id, pageUrl, mode) {
  mode = mode === "username" ? "username" : "id";
  if (probeAbort) {
    try {
      probeAbort.abort();
    } catch (_err) {
      /* ignore */
    }
  }
  probeAbort = { aborted: false, abort() { this.aborted = true; } };

  const huntBase = normalizeHuntBase(await storeGetLocal(STORE.HUNT_BASE, null));
  const resolvedPageUrl = pageUrl || "";
  const pageDir = directoryPathFromUrl(resolvedPageUrl);
  const targets = buildProbeTargets(id, resolvedPageUrl, huntBase, mode);
  const siteDirQueued = pageDir
    ? targets.filter((t) => (t.label || "").indexOf(pageDir) !== -1).length
    : 0;
  const likely = shapeLikely(id, mode).map((row) => ({
    ...row,
    status: null,
    hit: false,
    kind: "likely",
    error: "",
  }));

  const state = {
    id,
    mode,
    status: "running",
    running: true,
    total: targets.length,
    tried: 0,
    hits: [],
    likely,
    misses: [],
    blocked: [],
    startedAt: Date.now(),
    finishedAt: null,
    pageUrl: resolvedPageUrl,
    pageDir: pageDir || "",
    siteDirQueued,
  };
  await storeSet(STORE.PROBE, state);
  await notifySidebar({ type: MSG.PROBE_PROGRESS, probe: { ...state } });

  const concurrency = 4;
  let idx = 0;

  async function worker() {
    while (idx < targets.length) {
      if (probeAbort.aborted) return;
      const my = idx++;
      const target = targets[my];
      const result = await probeOne(target, id);
      if (probeAbort.aborted) return;

      state.tried += 1;
      const row = {
        label: target.label,
        group: target.group,
        url: result.finalUrl || target.url,
        status: result.status,
        hit: result.hit,
        kind: result.kind,
        error: result.error || "",
        priority: target.priority,
      };
      if (result.hit) {
        state.hits.push(row);
        state.hits.sort(
          (a, b) =>
            (a.priority != null ? a.priority : priorityOfLabel(a.label)) -
              (b.priority != null ? b.priority : priorityOfLabel(b.label)) ||
            a.label.localeCompare(b.label)
        );
      } else if (result.kind === "blocked") {
        state.blocked.push(row);
        state.blocked.sort(
          (a, b) =>
            (a.priority != null ? a.priority : priorityOfLabel(a.label)) -
              (b.priority != null ? b.priority : priorityOfLabel(b.label)) ||
            a.label.localeCompare(b.label)
        );
      } else state.misses.push(row);

      await storeSet(STORE.PROBE, state);
      await notifySidebar({
        type: MSG.PROBE_PROGRESS,
        probe: {
          ...state,
          hits: state.hits.slice(),
          likely: state.likely.slice(),
          blocked: state.blocked.slice(),
          misses: state.misses.slice(-80),
        },
      });
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  if (!probeAbort.aborted) {
    state.status = "done";
    state.running = false;
    state.finishedAt = Date.now();
    // Cap stored misses for UI
    state.misses = (state.misses || []).slice(-120);
    await storeSet(STORE.PROBE, state);
    await notifySidebar({ type: MSG.PROBE_RESULT, probe: state });
  }
}

// ---------------------------------------------------------------------------
// robots.txt + light sitemap discovery (Live Assets)
// ---------------------------------------------------------------------------

const ROBOTS_MAX_BYTES = 256 * 1024;
const SITEMAP_MAX_BYTES = 2 * 1024 * 1024;
const SITEMAP_LOC_CAP = 50;

async function fetchTextCapped(url, maxBytes) {
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      credentials: "omit",
      cache: "no-store",
    });
    if (!res.ok) {
      return { ok: false, status: res.status, text: "", finalUrl: res.url || url };
    }
    const buf = await res.arrayBuffer();
    const slice = buf.byteLength > maxBytes ? buf.slice(0, maxBytes) : buf;
    const text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    return {
      ok: true,
      status: res.status,
      text,
      finalUrl: res.url || url,
      truncated: buf.byteLength > maxBytes,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      text: "",
      finalUrl: url,
      error: err && err.message ? err.message : "fetch-failed",
    };
  }
}

function parseRobotsTxt(text) {
  const disallows = [];
  const allows = [];
  const sitemaps = [];
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const cleaned = line.replace(/#.*$/, "").trim();
    if (!cleaned) continue;
    const m = cleaned.match(/^(Disallow|Allow|Sitemap)\s*:\s*(.*)$/i);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = String(m[2] || "").trim();
    if (!val && key !== "disallow") continue;
    if (key === "disallow") disallows.push(val || "/");
    else if (key === "allow") allows.push(val);
    else if (key === "sitemap") sitemaps.push(val);
  }
  return { disallows, allows, sitemaps };
}

function parseSitemapLocs(text, limit) {
  const cap = limit == null ? SITEMAP_LOC_CAP : limit;
  const locs = [];
  const seen = new Set();
  const re = /<loc>\s*([^<]+?)\s*<\/loc>/gi;
  let m;
  while ((m = re.exec(String(text || ""))) && locs.length < cap) {
    let loc = String(m[1] || "").trim();
    if (!loc) continue;
    try {
      loc = loc.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"');
    } catch (_err) {
      /* keep */
    }
    if (seen.has(loc)) continue;
    seen.add(loc);
    locs.push(loc);
  }
  return locs;
}

function absoluteFromOrigin(origin, pathOrUrl) {
  const s = String(pathOrUrl || "").trim();
  if (!s) return "";
  if (/^https?:\/\//i.test(s)) return s;
  try {
    return new URL(s, origin + "/").href;
  } catch (_err) {
    return "";
  }
}

/** Last path segment that looks like an ID-mode probe token. */
function tokenishLastSegment(pathOrUrl) {
  try {
    let path = pathOrUrl;
    if (/^https?:\/\//i.test(pathOrUrl)) {
      path = new URL(pathOrUrl).pathname;
    }
    const parts = String(path || "")
      .split("/")
      .filter(Boolean);
    if (!parts.length) return "";
    let last = parts[parts.length - 1].replace(/\.(html?|xml|txt|php)$/i, "");
    last = last.replace(/^@+/, "").trim();
    if (/^[A-Za-z0-9_-]{4,64}$/.test(last)) return last;
  } catch (_err) {
    /* ignore */
  }
  return "";
}

async function fetchSiteDiscovery(pageUrl, opts) {
  const options = opts || {};
  const includeHuntBase = options.includeHuntBase !== false;
  const origins = [];
  const seenOrigin = new Set();

  function addOrigin(raw) {
    if (!raw) return;
    try {
      const o = new URL(raw).origin;
      if (!o || seenOrigin.has(o) || INTERNAL_URL.test(o + "/")) return;
      seenOrigin.add(o);
      origins.push(o);
    } catch (_err) {
      /* ignore */
    }
  }

  addOrigin(pageUrl);
  if (includeHuntBase) {
    const hb = normalizeHuntBase(await storeGetLocal(STORE.HUNT_BASE, null));
    if (hb) addOrigin(hb.origin);
  }

  if (!origins.length) {
    return { ok: false, error: "No http(s) page origin" };
  }

  const robotsReports = [];
  const pathRows = [];
  const sitemapUrlSet = new Set();
  const pathSeen = new Set();

  for (const origin of origins) {
    const robotsUrl = origin + "/robots.txt";
    const fetched = await fetchTextCapped(robotsUrl, ROBOTS_MAX_BYTES);
    if (!fetched.ok) {
      robotsReports.push({
        origin,
        url: robotsUrl,
        ok: false,
        status: fetched.status,
        error: fetched.error || "missing",
      });
      sitemapUrlSet.add(origin + "/sitemap.xml");
      continue;
    }
    const parsed = parseRobotsTxt(fetched.text);
    robotsReports.push({
      origin,
      url: fetched.finalUrl || robotsUrl,
      ok: true,
      status: fetched.status,
      allowCount: parsed.allows.length,
      disallowCount: parsed.disallows.length,
      sitemapCount: parsed.sitemaps.length,
    });

    for (const p of parsed.allows) {
      const abs = absoluteFromOrigin(origin, p);
      const key = "allow:" + (abs || p);
      if (pathSeen.has(key)) continue;
      pathSeen.add(key);
      pathRows.push({
        rule: "Allow",
        path: p,
        url: abs,
        origin,
        token: tokenishLastSegment(p),
      });
    }
    for (const p of parsed.disallows) {
      const abs = absoluteFromOrigin(origin, p);
      const key = "disallow:" + (abs || p);
      if (pathSeen.has(key)) continue;
      pathSeen.add(key);
      pathRows.push({
        rule: "Disallow",
        path: p,
        url: abs,
        origin,
        token: tokenishLastSegment(p),
      });
    }
    for (const sm of parsed.sitemaps) {
      const abs = absoluteFromOrigin(origin, sm);
      if (abs) sitemapUrlSet.add(abs);
    }
    sitemapUrlSet.add(origin + "/sitemap.xml");
  }

  const sitemapEntries = [];
  const locSeen = new Set();
  for (const smUrl of sitemapUrlSet) {
    if (sitemapEntries.length >= SITEMAP_LOC_CAP) break;
    const fetched = await fetchTextCapped(smUrl, SITEMAP_MAX_BYTES);
    if (!fetched.ok) continue;
    // Skip obvious non-XML (HTML error pages)
    const head = String(fetched.text || "")
      .slice(0, 200)
      .toLowerCase();
    if (head.indexOf("<html") !== -1 && head.indexOf("<urlset") === -1 && head.indexOf("<sitemapindex") === -1) {
      continue;
    }
    const locs = parseSitemapLocs(fetched.text, SITEMAP_LOC_CAP - sitemapEntries.length);
    for (const loc of locs) {
      if (locSeen.has(loc)) continue;
      locSeen.add(loc);
      let path = loc;
      try {
        path = new URL(loc).pathname || loc;
      } catch (_err) {
        /* keep */
      }
      sitemapEntries.push({
        url: loc,
        path,
        source: smUrl,
        token: tokenishLastSegment(loc),
      });
      if (sitemapEntries.length >= SITEMAP_LOC_CAP) break;
    }
  }

  return {
    ok: true,
    origins,
    robots: robotsReports,
    paths: pathRows,
    sitemaps: sitemapEntries,
  };
}

// Message hub
// ---------------------------------------------------------------------------

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const type = message && message.type;
  if (!type) return;

  // Content script → store + broadcast Live Assets
  if (type === MSG.LIVE_ASSETS) {
    const tabId = sender.tab && sender.tab.id;
    if (tabId == null) return;
    ingestLiveAssets(tabId, sender, message).then(() => pushState(tabId));
    return;
  }

  if (type === MSG.GET_REVEAL) {
    const tabId = sender.tab && sender.tab.id;
    const reply = (enabled) => sendResponse({ enabled: Boolean(enabled) });
    if (tabId == null) {
      reply(false);
      return true;
    }
    storeGet(STORE.REVEAL, {}).then((map) => reply(map[tabId])).catch(() => reply(false));
    return true; // async sendResponse
  }

  if (type === MSG.TOGGLE_REVEAL) {
    handleToggleReveal(message, sender).then(sendResponse);
    return true;
  }

  if (type === MSG.RESCAN) {
    handleRescan(message, sender).then(sendResponse);
    return true;
  }

  if (type === MSG.GET_STATE) {
    resolveTabId(message, sender).then((tabId) => buildState(tabId)).then(sendResponse);
    return true;
  }

  if (type === MSG.CLEAR_PENDING_INGEST) {
    (async () => {
      const which = message && message.which;
      if (which === "image" || which === "both") {
        const img = await storeGet(STORE.IMAGE, null);
        if (img && img.pendingIngest) {
          const next = { ...img };
          delete next.pendingIngest;
          await storeSet(STORE.IMAGE, next);
        }
      }
      if (which === "archive" || which === "both") {
        const arch = await storeGet(STORE.ARCHIVE, null);
        if (arch && arch.pendingIngest) {
          const next = { ...arch };
          delete next.pendingIngest;
          await storeSet(STORE.ARCHIVE, next);
        }
      }
      if (which === "audio" || which === "both") {
        const aud = await storeGet(STORE.AUDIO, null);
        if (aud && aud.pendingIngest) {
          const next = { ...aud };
          delete next.pendingIngest;
          await storeSet(STORE.AUDIO, next);
        }
      }
      sendResponse({ ok: true });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (type === MSG.CIPHER_INPUT) {
    const text = message.text == null ? "" : String(message.text);
    const fromSidebar = Boolean(sender.url && sender.url.includes("sidebar.html"));
    const auto = Boolean(message.auto);
    (async () => {
      await storeSet(STORE.CIPHER, text);
      if (fromSidebar) return;
      // Selection auto-decode and other content sends: open if closed.
      await openSidebarSafe();
      await notifySidebar({ type: MSG.CIPHER_INPUT, text, auto });
      // Cold-start: sidebar may not be listening yet; session state still loads on boot.
      if (auto) {
        setTimeout(() => {
          notifySidebar({ type: MSG.CIPHER_INPUT, text, auto }).catch(() => {});
        }, 150);
      }
    })().catch(() => {});
    return;
  }

  if (type === MSG.ARCHIVE_INFO && message.archiveInfo) {
    const fromSidebar = Boolean(sender.url && sender.url.includes("sidebar.html"));
    if (fromSidebar) {
      storeSet(STORE.ARCHIVE, message.archiveInfo).catch(() => {});
    }
    return;
  }

  if (type === MSG.PROBE_BACKLINK) {
    resolveTabId(message, sender).then(async (tabId) => {
      let pageUrl = message.pageUrl || "";
      if (!pageUrl && tabId != null) {
        try {
          const tab = await browser.tabs.get(tabId);
          pageUrl = tab.url || "";
        } catch (_err) {
          /* ignore */
        }
      }
      // Fallback: last Live Assets page URL for this tab (sidebar sometimes races).
      if ((!pageUrl || INTERNAL_URL.test(pageUrl)) && tabId != null) {
        try {
          const assetsByTab = await storeGet(STORE.ASSETS, {});
          const cached = assetsByTab[tabId] && assetsByTab[tabId].pageUrl;
          if (cached && !INTERNAL_URL.test(cached)) pageUrl = cached;
        } catch (_err) {
          /* ignore */
        }
      }
      const mode = message.mode === "username" ? "username" : "id";
      const id = normalizeProbeId(message.id || message.text || "", mode);
      if (!id) {
        sendResponse({
          ok: false,
          error:
            mode === "username"
              ? "Need a username like octocat"
              : "Need a token like jGJuVGiK",
        });
        return;
      }
      runBacklinkProbe(id, pageUrl, mode).catch(() => {});
      sendResponse({
        ok: true,
        id,
        mode,
        pageUrl,
        pageDir: directoryPathFromUrl(pageUrl || ""),
      });
    });
    return true;
  }

  if (type === MSG.DNS_LOOKUP) {
    const domain = normalizeDomain(message.domain || message.text || "");
    if (!domain) {
      sendResponse({ ok: false, error: "Need a domain like example.com" });
      runDnsLookup(message.domain || "").catch(() => {});
      return true;
    }
    runDnsLookup(domain)
      .then(() => sendResponse({ ok: true, domain }))
      .catch(() => sendResponse({ ok: false, error: "DNS lookup failed" }));
    return true;
  }

  if (type === MSG.IMAGE_HEX) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No image URL" });
      return true;
    }
    analyzeImageHex(url)
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          ok: false,
          error: (err && err.message) || "Hex analysis failed",
        })
      );
    return true;
  }

  if (type === MSG.IMAGE_HEX_PATCH) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No image URL" });
      return true;
    }
    patchImageHex(url, message.editOffset, message.editHex)
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          ok: false,
          error: (err && err.message) || "Hex patch failed",
        })
      );
    return true;
  }

  if (type === MSG.IMAGE_EXTRACT_PART) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No image URL" });
      return true;
    }
    extractImagePart(url, message.offset, message.length, message.mime)
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          ok: false,
          error: (err && err.message) || "Part extract failed",
        })
      );
    return true;
  }

  if (type === MSG.IMAGE_META) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No image URL" });
      return true;
    }
    analyzeImageMeta(url)
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          ok: false,
          error: (err && err.message) || "Meta analysis failed",
        })
      );
    return true;
  }

  if (type === MSG.STEGSTRUCK_SCAN) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No image URL" });
      return true;
    }
    sendImageToStegStruck(url, {
      tier: message.tier || "quick",
      passphrase: message.passphrase || "",
      llm: Boolean(message.llm),
    })
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          ok: false,
          error: (err && err.message) || "StegStruck scan failed",
        })
      );
    return true;
  }

  if (type === MSG.AUDIO_CAPTURE) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No audio URL" });
      return true;
    }
    captureAudioAsset(url, message.pageUrl || "", {
      focus: message.focus !== false,
      analyze: message.analyze !== false && /^https?:\/\//i.test(url),
    })
      .then((asset) => sendResponse({ ok: true, audioAsset: asset }))
      .catch((err) =>
        sendResponse({ ok: false, error: (err && err.message) || "Capture failed" })
      );
    return true;
  }

  if (type === MSG.AUDIO_ANALYZE) {
    const url = (message.url || "").trim();
    if (url) {
      analyzeAudioFromUrl(url)
        .then((result) => sendResponse(result))
        .catch((err) =>
          sendResponse({
            ok: false,
            error: (err && err.message) || "Audio analysis failed",
          })
        );
      return true;
    }
    if (message.buffer instanceof ArrayBuffer) {
      analyzeAudioFromArrayBuffer(message.buffer, message.filename || "audio")
        .then((result) => sendResponse(result))
        .catch((err) =>
          sendResponse({
            ok: false,
            error: (err && err.message) || "Audio analysis failed",
          })
        );
      return true;
    }
    sendResponse({ ok: false, error: "No audio URL or buffer" });
    return true;
  }

  if (type === MSG.AUDIO_ASSET && message.audioAsset) {
    // Extension pages (sidebar) have no sender.tab; content scripts do.
    // Do not rely on sender.url.includes("sidebar.html") — it can be missing
    // and then local drops never reach STORE.AUDIO, so the next pushState wipes UI.
    const fromExtensionPage = !sender.tab;
    if (fromExtensionPage) {
      storeSet(STORE.AUDIO, message.audioAsset)
        .then(() => sendResponse({ ok: true }))
        .catch(() => sendResponse({ ok: false }));
      return true;
    }
    return;
  }

  if (type === MSG.OPEN_URL) {
    const url = (message.url || "").trim();
    if (!url) {
      sendResponse({ ok: false, error: "No URL" });
      return true;
    }
    const active = Boolean(message.active);
    browser.tabs
      .create({ url, active })
      .then(() => sendResponse({ ok: true }))
      .catch((err) =>
        sendResponse({ ok: false, error: (err && err.message) || "tabs.create failed" })
      );
    return true;
  }

  if (type === MSG.ANALYZE_ARCHIVE) {
    (async () => {
      const filename = message.filename || "";
      const url = (message.url || "").trim();
      if (message.bufferBase64) {
        try {
          const bin = atob(message.bufferBase64);
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          if (bytes.byteLength > ARCHIVE_MAX_BYTES) {
            sendResponse({
              ok: false,
              error: "Archive too large (>" + Math.round(ARCHIVE_MAX_BYTES / (1024 * 1024)) + " MB)",
            });
            return;
          }
          const info = await inspectArchiveBuffer(bytes, {
            filename,
            url,
            source: "manual",
          });
          sendResponse({ ok: true, archiveInfo: info });
        } catch (err) {
          sendResponse({
            ok: false,
            error: (err && err.message) || "Archive analyze failed",
          });
        }
        return;
      }
      if (url) {
        const info = await inspectArchiveFromUrl(url, filename || basenameFromPath(url), "manual");
        sendResponse({ ok: Boolean(info && info.ok), archiveInfo: info });
        return;
      }
      sendResponse({ ok: false, error: "Need file bytes or URL" });
    })().catch((err) =>
      sendResponse({
        ok: false,
        error: (err && err.message) || "Archive analyze failed",
      })
    );
    return true;
  }

  if (type === MSG.PIN_HUNT_BASE) {
    resolveTabId(message, sender).then(async (tabId) => {
      let url = message.url || "";
      if (!url && tabId != null) {
        try {
          const tab = await browser.tabs.get(tabId);
          url = tab.url || "";
        } catch (_err) {
          /* ignore */
        }
      }
      if (!url || INTERNAL_URL.test(url)) {
        sendResponse({ ok: false, error: "Cannot pin this page" });
        return;
      }
      const existing = await storeGetLocal(STORE.HUNT_BASE, null);
      const huntBase = mergeHuntBasePin(existing, url);
      if (!huntBase) {
        sendResponse({ ok: false, error: "Bad URL" });
        return;
      }
      await storeSetLocal(STORE.HUNT_BASE, huntBase);
      await notifySidebar({ type: MSG.STATE, huntBase });
      if (tabId != null) await pushState(tabId);
      sendResponse({ ok: true, huntBase });
    });
    return true;
  }

  if (type === MSG.CLEAR_HUNT_BASE) {
    storeSetLocal(STORE.HUNT_BASE, null).then(async () => {
      await notifySidebar({ type: MSG.STATE, huntBase: null });
      sendResponse({ ok: true });
    });
    return true;
  }

  if (type === MSG.FETCH_SITE_DISCOVERY) {
    resolveTabId(message, sender).then(async (tabId) => {
      let pageUrl = message.pageUrl || "";
      if (!pageUrl && tabId != null) {
        try {
          const tab = await browser.tabs.get(tabId);
          pageUrl = tab.url || "";
        } catch (_err) {
          /* ignore */
        }
      }
      try {
        const result = await fetchSiteDiscovery(pageUrl, {
          includeHuntBase: message.includeHuntBase !== false,
        });
        sendResponse(result);
      } catch (_err) {
        sendResponse({ ok: false, error: "Discovery failed" });
      }
    });
    return true;
  }
});

async function ingestLiveAssets(tabId, sender, message) {
  const pageUrl = (sender.tab && sender.tab.url) || message.pageUrl || "";
  const frameUrl = message.frameUrl || (sender.url || "");
  const frameKey = String(sender.frameId != null ? sender.frameId : frameUrl);

  const assetsByTab = await storeGet(STORE.ASSETS, {});
  const existing = assetsByTab[tabId] || { pageUrl: "", frames: {}, updatedAt: 0 };

  // New top-level document: wipe leftover iframe payloads from the previous page.
  if (existing.pageUrl && pageUrl && existing.pageUrl !== pageUrl) {
    existing.frames = {};
  }

  existing.pageUrl = pageUrl || existing.pageUrl;
  existing.updatedAt = Date.now();
  existing.frames[frameKey] = {
    frameUrl,
    comments: message.comments || [],
    base64: message.base64 || [],
    zeroWidth: message.zeroWidth || [],
    flags: message.flags || [],
    meta: message.meta || [],
    revealedHidden: message.revealedHidden || [],
    backlinks: message.backlinks || [],
    mediaUrls: message.mediaUrls || [],
    candidates: message.candidates || [],
  };
  assetsByTab[tabId] = existing;
  await storeSet(STORE.ASSETS, assetsByTab);
}

async function resolveTabId(message, sender) {
  if (message.tabId != null) return message.tabId;
  if (sender.tab && sender.tab.id != null) return sender.tab.id;
  const windowId = message.windowId;
  const query = windowId != null
    ? { active: true, windowId }
    : { active: true, currentWindow: true };
  const tabs = await browser.tabs.query(query);
  return tabs[0] ? tabs[0].id : null;
}

async function handleToggleReveal(message, sender) {
  const tabId = await resolveTabId(message, sender);
  if (tabId == null) return { ok: false, error: "No active tab" };

  const map = await storeGet(STORE.REVEAL, {});
  const enabled = Boolean(message.enabled);
  map[tabId] = enabled;
  await storeSet(STORE.REVEAL, map);

  try {
    await browser.tabs.sendMessage(tabId, {
      type: MSG.APPLY_REVEAL,
      enabled,
    });
  } catch (_err) {
    // Restricted page (about:, AMO, etc.) — content script is absent.
  }

  await pushState(tabId);
  return { ok: true, enabled };
}

async function handleRescan(message, sender) {
  const tabId = await resolveTabId(message, sender);
  if (tabId == null) return { ok: false, error: "No active tab" };

  try {
    await browser.tabs.sendMessage(tabId, { type: MSG.RESCAN });
  } catch (_err) {
    return { ok: false, error: "Cannot scan this page" };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Archive / ZIP download comment inspection
// ---------------------------------------------------------------------------

function basenameFromPath(pathOrUrl) {
  const s = String(pathOrUrl || "");
  try {
    if (/^https?:\/\//i.test(s)) {
      const u = new URL(s);
      const seg = (u.pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
      if (seg) return decodeURIComponent(seg);
    }
  } catch (_err) {
    /* fall through */
  }
  const parts = s.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || s;
}

/**
 * @param {object} partial
 */
async function publishArchiveInfo(partial) {
  const zip = typeof ZIP_ARCHIVE !== "undefined" ? ZIP_ARCHIVE : null;
  const comment = partial.comment == null ? "" : String(partial.comment);
  const hexHint =
    partial.hexHint != null
      ? partial.hexHint
      : zip
        ? zip.hexDecodeHint(comment)
        : null;

  const payload = {
    filename: partial.filename || "",
    comment,
    encrypted: typeof partial.encrypted === "boolean" ? partial.encrypted : null,
    url: partial.url || "",
    format: partial.format || "unknown",
    supported: Boolean(partial.supported),
    error: partial.error || null,
    source: partial.source || "download",
    capturedAt: partial.capturedAt || Date.now(),
    hexHint: hexHint || null,
    ok: partial.ok !== false && !partial.error,
  };

  if (partial.ingestToast || partial.pendingIngest) {
    payload.pendingIngest = {
      toast: partial.ingestToast || null,
      focus: partial.focus !== false,
      at: Date.now(),
    };
  }

  await storeSet(STORE.ARCHIVE, payload);
  await openSidebarSafe();
  await notifySidebarReliable({
    type: MSG.ARCHIVE_INFO,
    archiveInfo: payload,
    focus: partial.focus !== false,
    ingestToast: partial.ingestToast || null,
  });
  return payload;
}

/**
 * @param {ArrayBuffer|Uint8Array} buffer
 * @param {{ filename?: string, url?: string, source?: string, ingestToast?: string|null }} meta
 */
async function inspectArchiveBuffer(buffer, meta) {
  const zip = typeof ZIP_ARCHIVE !== "undefined" ? ZIP_ARCHIVE : null;
  if (!zip) {
    return publishArchiveInfo({
      ok: false,
      filename: (meta && meta.filename) || "",
      url: (meta && meta.url) || "",
      source: (meta && meta.source) || "manual",
      supported: false,
      error: "ZIP parser unavailable",
      ingestToast: (meta && meta.ingestToast) || null,
    });
  }

  const result = zip.inspect(buffer, { filename: (meta && meta.filename) || "" });
  return publishArchiveInfo({
    ok: result.ok,
    filename: (meta && meta.filename) || "",
    url: (meta && meta.url) || "",
    source: (meta && meta.source) || "manual",
    format: result.format,
    supported: result.supported,
    comment: result.comment || "",
    encrypted: result.encrypted,
    error: result.error,
    ingestToast: (meta && meta.ingestToast) || null,
  });
}

/**
 * Re-fetch an http(s) URL and inspect as ZIP (size-capped).
 * @param {string} url
 * @param {string} filename
 * @param {string} source
 * @param {{ ingestToast?: string|null }} [opts]
 */
async function inspectArchiveFromUrl(url, filename, source, opts) {
  const o = opts || {};
  const toast = o.ingestToast || null;

  if (!/^https?:\/\//i.test(url)) {
    return publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: source || "download",
      supported: false,
      format: "unknown",
      error: "Cannot re-fetch non-http URL — drop the file in Analyze archive",
      ingestToast: toast,
    });
  }

  let resp;
  try {
    resp = await fetch(url, { credentials: "include", cache: "no-store" });
  } catch (err) {
    return publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: source || "download",
      supported: true,
      format: "zip",
      error: "Re-fetch failed: " + ((err && err.message) || "network error"),
      ingestToast: toast,
    });
  }

  if (!resp.ok) {
    return publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: source || "download",
      supported: true,
      format: "zip",
      error: "Re-fetch HTTP " + resp.status,
      ingestToast: toast,
    });
  }

  const cl = Number(resp.headers.get("content-length") || 0);
  if (cl > ARCHIVE_MAX_BYTES) {
    return publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: source || "download",
      supported: true,
      format: "zip",
      error:
        "Archive too large to re-fetch (>" +
        Math.round(ARCHIVE_MAX_BYTES / (1024 * 1024)) +
        " MB)",
      ingestToast: toast,
    });
  }

  const buf = await resp.arrayBuffer();
  if (buf.byteLength > ARCHIVE_MAX_BYTES) {
    return publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: source || "download",
      supported: true,
      format: "zip",
      error:
        "Archive too large to re-fetch (>" +
        Math.round(ARCHIVE_MAX_BYTES / (1024 * 1024)) +
        " MB)",
      ingestToast: toast,
    });
  }

  return inspectArchiveBuffer(buf, {
    filename: filename || basenameFromPath(url),
    url,
    source: source || "download",
    ingestToast: toast,
  });
}

function isHttpUrl(url) {
  return /^https?:\/\//i.test(String(url || ""));
}

function isBlobOrDataUrl(url) {
  return /^(blob:|data:)/i.test(String(url || ""));
}

function isFileUrl(url) {
  return /^file:/i.test(String(url || ""));
}

/**
 * Classify a completed download for auto-ingest.
 * @param {string} filename
 * @param {string} [mime]
 * @param {string} [url]
 * @returns {"archive"|"image"|"audio"|"text"|null}
 */
function classifyDownload(filename, mime, url) {
  const zip = typeof ZIP_ARCHIVE !== "undefined" ? ZIP_ARCHIVE : null;
  if (zip && zip.isArchiveCandidate(filename, mime)) return "archive";

  const name = String(filename || "").toLowerCase();
  const m = String(mime || "").toLowerCase();
  const u = String(url || "");

  if (isAudioDownloadCandidate(filename, mime, url)) return "audio";

  // data:image/... is always an image even without a filename extension
  if (/^data:image\//i.test(u)) return "image";

  if (
    /\.(png|jpe?g|gif|webp|bmp)$/i.test(name) ||
    /^image\/(png|jpe?g|jpg|gif|webp|bmp|x-png)\b/.test(m) ||
    (/^image\//.test(m) && !/^image\/svg\+xml\b/.test(m))
  ) {
    return "image";
  }

  // Extension on the download URL path (filename may still be empty)
  try {
    if (/^https?:\/\//i.test(u)) {
      const path = new URL(u).pathname || "";
      if (/\.(png|jpe?g|gif|webp|bmp)$/i.test(path)) return "image";
      if (/\.(mp3|wav|ogg|m4a|flac|aac|webm)$/i.test(path)) return "audio";
      if (/\.(txt|csv|json|md|log|nfo)$/i.test(path)) return "text";
      if (/\.(zip|jar|apk|rar|7z)$/i.test(path)) return "archive";
    }
  } catch (_err) {
    /* ignore */
  }

  if (
    /\.(txt|csv|json|md|log|nfo)$/i.test(name) ||
    /^(text\/|application\/(json|csv|xml))\b/.test(m)
  ) {
    return "text";
  }

  return null;
}

async function isAutoIngestEnabled() {
  try {
    const bag = await browser.storage.local.get(AUTO_INGEST_KEY);
    if (bag[AUTO_INGEST_KEY] === false) return false;
    return true;
  } catch (_err) {
    return true;
  }
}

function ingestToastLabel(filename, target) {
  const name = filename || "download";
  return "Download: " + name + " → " + target;
}

/**
 * @param {string} text
 * @param {{ ingestToast?: string|null, appendNote?: string|null, auto?: boolean }} [opts]
 */
async function publishCipherFromDownload(text, opts) {
  const o = opts || {};
  await storeSet(STORE.CIPHER, text);
  await openSidebarSafe();
  await notifySidebarReliable({
    type: MSG.CIPHER_INPUT,
    text,
    auto: o.auto !== false,
    focus: true,
    ingestToast: o.ingestToast || null,
    appendNote: o.appendNote || null,
  });
}

async function ingestArchiveDownload(item, filename, url) {
  const toast = ingestToastLabel(filename, "Archive");
  const zip = typeof ZIP_ARCHIVE !== "undefined" ? ZIP_ARCHIVE : null;

  if (!zip) {
    await publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: "download",
      supported: false,
      error: "ZIP parser unavailable",
      ingestToast: toast,
    });
    return;
  }

  if (!zip.isZipFamily(filename, item.mime)) {
    const format = /\.rar$/i.test(filename)
      ? "rar"
      : /\.7z$/i.test(filename)
        ? "7z"
        : "unknown";
    await publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: "download",
      format,
      supported: false,
      comment: "",
      encrypted: null,
      error:
        format.toUpperCase() +
        " comments are not supported yet — ZIP / JAR / APK only",
      ingestToast: toast,
    });
    return;
  }

  if (typeof item.fileSize === "number" && item.fileSize > ARCHIVE_MAX_BYTES) {
    await publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: "download",
      format: "zip",
      supported: true,
      error:
        "Archive too large to re-fetch (>" +
        Math.round(ARCHIVE_MAX_BYTES / (1024 * 1024)) +
        " MB)",
      ingestToast: toast,
    });
    return;
  }

  if (!isHttpUrl(url)) {
    const dropToast =
      toast + " — drop the file into Image/Audio/Archive (URL not re-fetchable)";
    await publishArchiveInfo({
      ok: false,
      filename,
      url,
      source: "download",
      supported: true,
      format: "zip",
      error: "Cannot re-fetch non-http URL — drop the file in Analyze archive",
      ingestToast: dropToast,
    });
    return;
  }

  await inspectArchiveFromUrl(url, filename, "download", { ingestToast: toast });
}

async function ingestImageDownload(filename, url) {
  const toast = ingestToastLabel(filename, "Image");
  await openSidebarSafe();

  if (isHttpUrl(url)) {
    await captureImageAsset(url, "", {
      filename,
      focus: true,
      analyzeHex: true,
      ingestToast: toast,
      pendingIngest: true,
    });
    return;
  }

  const dropToast =
    toast + " — drop the file into Image/Audio/Archive (blob/data URL not re-fetchable)";
  await captureImageAsset(url || "", "", {
    filename,
    needsDrop: true,
    focus: true,
    analyzeHex: false,
    ingestToast: dropToast,
    pendingIngest: true,
  });
}

async function ingestAudioDownload(filename, url) {
  const toast = ingestToastLabel(filename, "Audio");
  await openSidebarSafe();

  if (isHttpUrl(url)) {
    await captureAudioAsset(url, "", {
      filename,
      focus: true,
      analyze: true,
      ingestToast: toast,
      pendingIngest: true,
    });
    return;
  }

  const dropToast =
    toast + " — drop the file into Audio (blob/file URL not re-fetchable)";
  await captureAudioAsset(url || "", "", {
    filename,
    needsDrop: true,
    focus: true,
    analyze: false,
    ingestToast: dropToast,
    pendingIngest: true,
  });
}

/**
 * blob:/data:/file: download we could not classify — never silent.
 */
async function ingestUnclassifiedLocalDownload(filename, url) {
  const name = filename || "download";
  const toast =
    "Download: " +
    name +
    " — drop the file into Image/Audio/Archive (could not classify)";
  await openSidebarSafe();
  await captureImageAsset(url || "", "", {
    filename,
    needsDrop: true,
    focus: true,
    analyzeHex: false,
    ingestToast: toast,
    pendingIngest: true,
  });
}

async function ingestTextDownload(item, filename, url) {
  const toast = ingestToastLabel(filename, "Cipher");
  const noteLine = "[download] " + (filename || "file");

  async function focusCipherOnly(extraToast, note) {
    await openSidebarSafe();
    await notifySidebarReliable({
      type: MSG.CIPHER_INPUT,
      auto: true,
      focus: true,
      ingestToast: extraToast || toast,
      appendNote: note || null,
    });
  }

  if (!isHttpUrl(url)) {
    await focusCipherOnly(
      toast + " (drop / paste to analyze)",
      noteLine + " — drop/paste to analyze"
    );
    return;
  }

  if (typeof item.fileSize === "number" && item.fileSize > TEXT_INGEST_MAX_BYTES) {
    await focusCipherOnly(toast + " (too large to re-fetch)", noteLine + " — too large to re-fetch");
    return;
  }

  let resp;
  try {
    resp = await fetch(url, { credentials: "include", cache: "no-store" });
  } catch (err) {
    await focusCipherOnly(
      toast + " (re-fetch failed)",
      noteLine +
        " — re-fetch failed: " +
        ((err && err.message) || "network error")
    );
    return;
  }

  if (!resp.ok) {
    await focusCipherOnly(
      toast + " (HTTP " + resp.status + ")",
      noteLine + " — re-fetch HTTP " + resp.status
    );
    return;
  }

  const cl = Number(resp.headers.get("content-length") || 0);
  if (cl > TEXT_INGEST_MAX_BYTES) {
    await focusCipherOnly(toast + " (too large)", noteLine + " — too large to re-fetch");
    return;
  }

  const buf = await resp.arrayBuffer();
  if (buf.byteLength > TEXT_INGEST_MAX_BYTES) {
    await focusCipherOnly(toast + " (too large)", noteLine + " — too large to re-fetch");
    return;
  }

  let text = "";
  try {
    text = new TextDecoder("utf-8", { fatal: false }).decode(buf);
  } catch (_err) {
    text = "";
  }

  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  if (!text) {
    await focusCipherOnly(toast + " (empty)", noteLine + " — empty after re-fetch");
    return;
  }

  await publishCipherFromDownload(text, {
    ingestToast: toast,
    appendNote: noteLine + " → Cipher",
  });
}

/** Dedup download completions briefly (onChanged can fire more than once). */
const ingestHandledDownloads = new Map();
/** Early metadata from downloads.onCreated (Firefox often fills filename late). */
const downloadHints = new Map();
/** Soft retries when search returns nothing right after complete. */
const ingestLookupRetries = new Map();

function rememberDownloadHint(item) {
  if (!item || item.id == null) return;
  const prev = downloadHints.get(item.id) || {};
  downloadHints.set(item.id, {
    url: item.url || prev.url || "",
    filename: item.filename || prev.filename || "",
    mime: item.mime || prev.mime || "",
    // Firefox DownloadItem may expose suggested filename via filename early on create
    fileSize: typeof item.fileSize === "number" ? item.fileSize : prev.fileSize,
  });
  if (downloadHints.size > 80) {
    const first = downloadHints.keys().next().value;
    downloadHints.delete(first);
  }
}

async function lookupDownloadItem(downloadId) {
  let items = [];
  try {
    items = await browser.downloads.search({ id: downloadId });
  } catch (_err) {
    return null;
  }
  const item = items && items[0];
  if (!item) return null;
  const hint = downloadHints.get(downloadId) || {};
  return {
    ...item,
    url: item.url || hint.url || "",
    filename: item.filename || hint.filename || "",
    mime: item.mime || hint.mime || "",
    fileSize:
      typeof item.fileSize === "number"
        ? item.fileSize
        : typeof hint.fileSize === "number"
          ? hint.fileSize
          : item.fileSize,
  };
}

/**
 * Firefox may fire state=complete before filename/mime are populated.
 * Retry search a few times; merge onCreated hints.
 */
async function resolveCompletedDownload(downloadId) {
  let last = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    if (attempt > 0) await sleepMs(80 * attempt);
    const item = await lookupDownloadItem(downloadId);
    if (!item) continue;
    last = item;
    const url = item.url || "";
    const filename = basenameFromPath(item.filename || "") || basenameFromPath(url);
    const kind = classifyDownload(filename, item.mime, url);
    const metaReady = Boolean(
      item.filename || item.mime || (url && !isBlobOrDataUrl(url)) || kind
    );
    if (kind || (metaReady && attempt >= 2) || attempt === 5) {
      return { item, url, filename, kind };
    }
  }
  if (!last) return null;
  const url = last.url || "";
  const filename = basenameFromPath(last.filename || "") || basenameFromPath(url);
  return {
    item: last,
    url,
    filename,
    kind: classifyDownload(filename, last.mime, url),
  };
}

function markDownloadHandled(downloadId) {
  ingestHandledDownloads.set(downloadId, Date.now());
  if (ingestHandledDownloads.size > 40) {
    const cutoff = Date.now() - 60_000;
    for (const [id, t] of ingestHandledDownloads) {
      if (t < cutoff) ingestHandledDownloads.delete(id);
    }
  }
}

async function handleDownloadComplete(downloadId) {
  if (ingestHandledDownloads.has(downloadId)) return;

  if (!(await isAutoIngestEnabled())) {
    markDownloadHandled(downloadId);
    console.log("[Hunt] download complete: id=" + downloadId + " (auto-ingest off)");
    return;
  }

  const resolved = await resolveCompletedDownload(downloadId);
  if (!resolved) {
    const n = (ingestLookupRetries.get(downloadId) || 0) + 1;
    ingestLookupRetries.set(downloadId, n);
    console.log(
      "[Hunt] download complete: id=" +
        downloadId +
        " classified as (no item yet), retry " +
        n
    );
    if (n < 3) {
      setTimeout(() => {
        handleDownloadComplete(downloadId).catch(() => {});
      }, 250 * n);
    } else {
      markDownloadHandled(downloadId);
      ingestLookupRetries.delete(downloadId);
    }
    return;
  }

  ingestLookupRetries.delete(downloadId);

  const { item, url, filename, kind } = resolved;

  // Mark handled only once we have a definitive outcome (ingest or skip).
  markDownloadHandled(downloadId);
  downloadHints.delete(downloadId);

  console.log(
    "[Hunt] download complete: " +
      (filename || url || "#" + downloadId) +
      " classified as " +
      (kind ||
        (isBlobOrDataUrl(url) || isFileUrl(url) ? "local-untyped" : "skip"))
  );

  if (kind === "archive") {
    await ingestArchiveDownload(item, filename, url);
    return;
  }
  if (kind === "image") {
    await ingestImageDownload(filename, url);
    return;
  }
  if (kind === "audio") {
    await ingestAudioDownload(filename, url);
    return;
  }
  if (kind === "text") {
    await ingestTextDownload(item, filename, url);
    return;
  }

  // Never silent for blob:/data:/file: — ask user to drop into Image/Audio/Archive.
  if (isBlobOrDataUrl(url) || isFileUrl(url)) {
    await ingestUnclassifiedLocalDownload(filename, url);
  }
}

if (browser.downloads && browser.downloads.onCreated) {
  browser.downloads.onCreated.addListener((item) => {
    rememberDownloadHint(item);
  });
}

if (browser.downloads && browser.downloads.onChanged) {
  browser.downloads.onChanged.addListener((delta) => {
    if (!delta || delta.id == null) return;
    const state = delta.state && delta.state.current;
    if (state !== "complete") {
      // Filename / mime can arrive in later deltas — keep hints fresh.
      if (delta.filename || delta.mime || delta.url) {
        rememberDownloadHint({
          id: delta.id,
          filename: delta.filename && delta.filename.current,
          mime: delta.mime && delta.mime.current,
          url: delta.url && delta.url.current,
        });
      }
      return;
    }
    handleDownloadComplete(delta.id).catch((err) => {
      console.warn(
        "[Hunt] download ingest failed:",
        (err && err.message) || err
      );
    });
  });
  console.log("[Hunt] downloads.onChanged listener registered");
} else {
  console.warn(
    "[Hunt] downloads API unavailable — check manifest permission + reload extension"
  );
}

