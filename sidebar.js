/**
 * The Hunt Engine — sidebar panel.
 *
 * Pulls Live Assets / redirect chains / reveal state from the event page,
 * runs all cipher translations locally, and never talks to the network.
 */

"use strict";

const MSG = {
  LIVE_ASSETS: "LIVE_ASSETS",
  TOGGLE_REVEAL: "TOGGLE_REVEAL",
  RESCAN: "RESCAN",
  GET_STATE: "GET_STATE",
  STATE: "STATE",
  CIPHER_INPUT: "CIPHER_INPUT",
  PROBE_BACKLINK: "PROBE_BACKLINK",
  PROBE_PROGRESS: "PROBE_PROGRESS",
  PROBE_RESULT: "PROBE_RESULT",
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
  CLEAR_PENDING_INGEST: "CLEAR_PENDING_INGEST",
};

const PANEL_ORDER_KEY = "sidebarPanelOrder";
const PANEL_OPEN_KEY = "sidebarPanelOpen";
const NOTES_KEY = "sidebarNotes";
const AUTO_INGEST_KEY = "autoIngestDownloads";
const GROUP_ORDER_KEY = "groupOrder";
const GROUP_OPEN_KEY = "groupOpenState";
const CIPHER_AUTO_DECODE_KEY = "cipherAutoDecode";
const CIPHER_ROT_N_KEY = "cipherRotN";

/** Top-level accordion groups (drag-reorder these). */
const DEFAULT_GROUP_ORDER = ["group-hunt", "group-page", "group-media", "group-decode"];
const GROUP_CHILDREN = {
  "group-hunt": ["panel-probe"],
  "group-page": ["panel-assets", "panel-redirects"],
  "group-media": ["panel-image", "panel-audio", "panel-archive"],
  "group-decode": ["panel-cipher", "panel-notes", "panel-geohash", "panel-dns"],
};
const PANEL_TO_GROUP = (() => {
  /** @type {Record<string, string>} */
  const map = {};
  for (const [gid, kids] of Object.entries(GROUP_CHILDREN)) {
    for (const pid of kids) map[pid] = gid;
  }
  return map;
})();

/** Nested tool panels (open state still persisted). */
const DEFAULT_PANEL_ORDER = [
  "panel-probe",
  "panel-assets",
  "panel-redirects",
  "panel-image",
  "panel-audio",
  "panel-archive",
  "panel-cipher",
  "panel-notes",
  "panel-geohash",
  "panel-dns",
];

/** First-load defaults: Hunt + Page open; Media + Decode collapsed. */
const DEFAULT_GROUP_OPEN = {
  "group-hunt": true,
  "group-page": true,
  "group-media": false,
  "group-decode": false,
};
const DEFAULT_PANEL_OPEN = {
  "panel-probe": true,
  "panel-assets": true,
  "panel-redirects": false,
  "panel-image": true,
  "panel-audio": true,
  "panel-archive": true,
  "panel-cipher": true,
  "panel-notes": false,
  "panel-geohash": false,
  "panel-dns": false,
};

const CIPHER_SPECS = [
  { id: "b64", label: "Base64 decode", run: decodeBase64, guess: "Base64" },
  { id: "hex", label: "Hex decode", run: decodeHex, guess: "Hex" },
  { id: "oct", label: "Octal decode", run: decodeOctal, guess: "Octal" },
  { id: "dec", label: "Decimal / ASCII", run: decodeDecimal, guess: "Decimal" },
  { id: "bin", label: "Binary decode", run: decodeBinary, guess: "Binary" },
  {
    id: "binmorse",
    label: "Binary → Morse",
    run: decodeBinaryMorse,
    guess: "Bin→Morse",
  },
  { id: "ternary", label: "Ternary / Base-3", run: decodeTernary, guess: "Ternary" },
  { id: "a1z26", label: "A1Z26", run: decodeA1Z26, guess: "A1Z26" },
  { id: "bacon", label: "Bacon’s cipher", run: decodeBacon, guess: "Bacon" },
  { id: "t9", label: "Phone keypad (T9)", run: decodeT9, guess: "T9" },
  { id: "rot13", label: "ROT13", run: decodeRot13 },
  { id: "rotn", label: "ROT-N (manual)", run: decodeRotNManual },
  { id: "rotn-ascii", label: "ROT-N ASCII", run: decodeRotNAscii },
  { id: "caesar", label: "Caesar crib", run: decodeCaesarCrib, guess: "Caesar" },
  { id: "rot47", label: "ROT47", run: decodeRot47 },
  { id: "url", label: "URL decode", run: decodeUrl },
  { id: "reverse", label: "Reverse", run: decodeReverse },
  { id: "atbash", label: "Atbash", run: decodeAtbash },
  { id: "morse", label: "Morse decode", run: decodeMorse, guess: "Morse" },
];

/** Extra cipher cards gated on a non-empty session key (not in CIPHER_SPECS). */
const CIPHER_KEY_SPECS = [
  { id: "vigenere", label: "Vigenère (key)", run: decodeVigenereKey },
  { id: "xor", label: "XOR (key)", run: decodeXorKey },
];

/** Session-only cipher password — never written to storage. */
let cipherSessionKey = "";
const CIPHER_ROT_SLIDER_MAX = 100;
const els = {
  host: document.getElementById("active-host"),
  reveal: document.getElementById("btn-reveal"),
  rescan: document.getElementById("btn-rescan"),
  scanStatus: document.getElementById("scan-status"),
  badgeAssets: document.getElementById("badge-assets"),
  badgeRedirects: document.getElementById("badge-redirects"),
  listComments: document.getElementById("list-comments"),
  listBase64: document.getElementById("list-base64"),
  listZw: document.getElementById("list-zw"),
  listFlags: document.getElementById("list-flags"),
  listMeta: document.getElementById("list-meta"),
  listRevealed: document.getElementById("list-revealed"),
  listBacklinks: document.getElementById("list-backlinks"),
  listMedia: document.getElementById("list-media"),
  countMedia: document.getElementById("count-media"),
  listHeaders: document.getElementById("list-headers"),
  listRobots: document.getElementById("list-robots"),
  listSitemap: document.getElementById("list-sitemap"),
  sectionRobots: document.getElementById("section-robots"),
  sectionSitemap: document.getElementById("section-sitemap"),
  btnRobots: document.getElementById("btn-robots"),
  robotsStatus: document.getElementById("robots-status"),
  countRobots: document.getElementById("count-robots"),
  countSitemap: document.getElementById("count-sitemap"),
  countComments: document.getElementById("count-comments"),
  countBase64: document.getElementById("count-base64"),
  countZw: document.getElementById("count-zw"),
  countFlags: document.getElementById("count-flags"),
  countMeta: document.getElementById("count-meta"),
  countRevealed: document.getElementById("count-revealed"),
  countBacklinks: document.getElementById("count-backlinks"),
  countHeaders: document.getElementById("count-headers"),
  badgeProbe: document.getElementById("badge-probe"),
  probeInput: document.getElementById("probe-input"),
  btnProbe: document.getElementById("btn-probe"),
  probeStatus: document.getElementById("probe-status"),
  probeHits: document.getElementById("probe-hits"),
  probeFiltered: document.getElementById("probe-filtered"),
  probeFilteredBody: document.getElementById("probe-filtered-body"),
  countFiltered: document.getElementById("count-filtered"),
  btnPinHunt: document.getElementById("btn-pin-hunt"),
  btnClearHunt: document.getElementById("btn-clear-hunt"),
  huntBaseLabel: document.getElementById("hunt-base-label"),
  autoIngestDownloads: document.getElementById("auto-ingest-downloads"),
  ingestToast: document.getElementById("ingest-toast"),
  panelStack: document.getElementById("panel-stack"),
  listCandidates: document.getElementById("list-candidates"),
  countCandidates: document.getElementById("count-candidates"),
  modeId: document.getElementById("mode-id"),
  modeUsername: document.getElementById("mode-username"),
  badgeImage: document.getElementById("badge-image"),
  imageEmpty: document.getElementById("image-empty"),
  imageCard: document.getElementById("image-card"),
  imageUrl: document.getElementById("image-url"),
  btnImageOpen: document.getElementById("btn-image-open"),
  btnImageCopy: document.getElementById("btn-image-copy"),
  btnImageLens: document.getElementById("btn-image-lens"),
  btnImageYandex: document.getElementById("btn-image-yandex"),
  btnImageTineye: document.getElementById("btn-image-tineye"),
  btnImageForensics: document.getElementById("btn-image-forensics"),
  btnImageStegstruck: document.getElementById("btn-image-stegstruck"),
  btnImageProbe: document.getElementById("btn-image-probe"),
  btnImageHex: document.getElementById("btn-image-hex"),
  btnImageSplit: document.getElementById("btn-image-split"),
  btnImageMeta: document.getElementById("btn-image-meta"),
  imageForensicsStatus: document.getElementById("image-forensics-status"),
  imageForensicsFallback: document.getElementById("image-forensics-fallback"),
  btnImageCopyFallback: document.getElementById("btn-image-copy-fallback"),
  imageMetaPanel: document.getElementById("image-meta-panel"),
  imageMetaStatus: document.getElementById("image-meta-status"),
  imageMetaList: document.getElementById("image-meta-list"),
  imageHexPanel: document.getElementById("image-hex-panel"),
  imageHexMeta: document.getElementById("image-hex-meta"),
  imageSplitPanel: document.getElementById("image-split-panel"),
  imageSplitStatus: document.getElementById("image-split-status"),
  imageSplitActions: document.getElementById("image-split-actions"),
  imageSplitList: document.getElementById("image-split-list"),
  imageSplitPreviewWrap: document.getElementById("image-split-preview-wrap"),
  imageSplitPreviews: document.getElementById("image-split-previews"),
  imageHexStrings: document.getElementById("image-hex-strings"),
  imageHexHead: document.getElementById("image-hex-head"),
  imageHexTail: document.getElementById("image-hex-tail"),
  imageHexEdit: document.getElementById("image-hex-edit"),
  imageHexEditLabel: document.getElementById("image-hex-edit-label"),
  imageHexEditStatus: document.getElementById("image-hex-edit-status"),
  btnHexApply: document.getElementById("btn-hex-apply"),
  btnHexReset: document.getElementById("btn-hex-reset"),
  btnHexDownload: document.getElementById("btn-hex-download"),
  imageHexPreviewWrap: document.getElementById("image-hex-preview-wrap"),
  imageHexPreview: document.getElementById("image-hex-preview"),
  btnOpenBlocked: document.getElementById("btn-open-blocked"),
  probeActions: document.getElementById("probe-actions"),
  dnsInput: document.getElementById("dns-input"),
  btnDns: document.getElementById("btn-dns"),
  dnsStatus: document.getElementById("dns-status"),
  dnsResults: document.getElementById("dns-results"),
  badgeDns: document.getElementById("badge-dns"),
  geohashInput: document.getElementById("geohash-input"),
  btnGeohash: document.getElementById("btn-geohash"),
  geohashStatus: document.getElementById("geohash-status"),
  geohashResults: document.getElementById("geohash-results"),
  redirects: document.getElementById("list-redirects"),
  cipherInput: document.getElementById("cipher-input"),
  cipherAutoDecode: document.getElementById("cipher-auto-decode"),
  cipherRotN: document.getElementById("cipher-rot-n"),
  cipherRotSlider: document.getElementById("cipher-rot-slider"),
  cipherKey: document.getElementById("cipher-key"),
  cipherGuesses: document.getElementById("cipher-guesses"),
  cipherCards: document.getElementById("cipher-cards"),
  notesInput: document.getElementById("notes-input"),
  notesStatus: document.getElementById("notes-status"),
  notesResults: document.getElementById("notes-results"),
  btnNotesCount: document.getElementById("btn-notes-count"),
  btnNotesAnalyze: document.getElementById("btn-notes-analyze"),
  btnNotesToCipher: document.getElementById("btn-notes-to-cipher"),
  btnNotesToProbe: document.getElementById("btn-notes-to-probe"),
  badgeAudio: document.getElementById("badge-audio"),
  audioEmpty: document.getElementById("audio-empty"),
  audioCard: document.getElementById("audio-card"),
  audioUrl: document.getElementById("audio-url"),
  audioPreview: document.getElementById("audio-preview"),
  audioDrop: document.getElementById("audio-drop"),
  audioFile: document.getElementById("audio-file"),
  audioStatus: document.getElementById("audio-status"),
  btnAudioOpen: document.getElementById("btn-audio-open"),
  btnAudioCopy: document.getElementById("btn-audio-copy"),
  btnAudioAnalyze: document.getElementById("btn-audio-analyze"),
  btnAudioProbe: document.getElementById("btn-audio-probe"),
  btnAudioAudacity: document.getElementById("btn-audio-audacity"),
  btnAudioSpectrum: document.getElementById("btn-audio-spectrum"),
  btnAudioMorse: document.getElementById("btn-audio-morse"),
  btnAudioSstv: document.getElementById("btn-audio-sstv"),
  audioAnalyzePanel: document.getElementById("audio-analyze-panel"),
  audioId3Status: document.getElementById("audio-id3-status"),
  audioId3List: document.getElementById("audio-id3-list"),
  audioStrings: document.getElementById("audio-strings"),
  audioMorsePanel: document.getElementById("audio-morse-panel"),
  audioMorseList: document.getElementById("audio-morse-list"),
  badgeArchive: document.getElementById("badge-archive"),
  archiveEmpty: document.getElementById("archive-empty"),
  archiveCard: document.getElementById("archive-card"),
  archiveFilename: document.getElementById("archive-filename"),
  archiveEncrypted: document.getElementById("archive-encrypted"),
  archiveComment: document.getElementById("archive-comment"),
  archiveHexHint: document.getElementById("archive-hex-hint"),
  archiveHexDecoded: document.getElementById("archive-hex-decoded"),
  archiveStatus: document.getElementById("archive-status"),
  archiveDrop: document.getElementById("archive-drop"),
  archiveFile: document.getElementById("archive-file"),
  btnArchiveCopy: document.getElementById("btn-archive-copy"),
  btnArchiveCipher: document.getElementById("btn-archive-cipher"),
  btnArchiveNotes: document.getElementById("btn-archive-notes"),
  btnArchiveProbe: document.getElementById("btn-archive-probe"),
};

let revealEnabled = false;
let cipherTimer = 0;
let notesTimer = 0;
let probeMode = "id";
/** Last known active-tab URL from STATE (sidebar passes this into probes). */
let lastKnownPageUrl = "";
let currentImage = null;
let currentAudio = null;
let audioPreviewObjectUrl = null;
/** Key for the active preview: http(s) URL or `local:<filename>`. */
let audioPreviewSourceKey = null;
/** Local drop bytes kept for re-analyze / blob preview (not persisted). */
let audioLocalBuffer = null;
let audioLocalFilename = "";
/** @type {null | {
 *   filename: string,
 *   comment: string,
 *   encrypted: boolean|null,
 *   url: string,
 *   format: string,
 *   supported: boolean,
 *   error: string|null,
 *   hexHint: string|null,
 *   source: string,
 *   ok?: boolean
 * }} */
let currentArchive = null;
/** @type {string[]} */
let notesAnalyzedCandidates = [];
/** @type {string[]} */
let lastBlockedUrls = [];
let lastForensicsUrl = "";
/** @type {null | { url: string, editOffset: number, editHex: string, editScope: string, editSize: number }} */
let hexEditSession = null;
/** @type {string | null} */
let hexPreviewObjectUrl = null;
/** @type {Blob | null} */
let hexPatchedBlob = null;
/** @type {null | { url: string, splits: object[], markers: object | null, concatenated: boolean }} */
let imageSplitSession = null;
/** @type {string[]} */
let splitPreviewObjectUrls = [];

// ---------------------------------------------------------------------------
// Window / tab identity for this sidebar instance
// ---------------------------------------------------------------------------

async function currentWindowId() {
  const win = await browser.windows.getCurrent();
  return win.id;
}

async function requestState() {
  const windowId = await currentWindowId();
  const state = await browser.runtime.sendMessage({
    type: MSG.GET_STATE,
    windowId,
  });
  if (state) applyState(state);
}

function applyState(state) {
  if (!state) return;

  const url = state.pageUrl || "";
  lastKnownPageUrl = url;
  els.host.textContent = hostLabel(url);
  els.host.title = url || "";

  if (typeof state.revealEnabled === "boolean") {
    revealEnabled = state.revealEnabled;
    els.reveal.setAttribute("aria-pressed", revealEnabled ? "true" : "false");
    els.reveal.textContent = revealEnabled
      ? "Hidden Layers: ON"
      : "Reveal Hidden Layers";
  }

  if (state.assets) renderAssets(state.assets);
  if (state.responseHeaders) renderResponseHeaders(state.responseHeaders);
  else if ("responseHeaders" in state) renderResponseHeaders(null);
  if (state.redirectLog) renderRedirects(state.redirectLog);
  // Sync probe/image from state without stealing scroll — dedicated
  // message handlers (PROBE_*, IMAGE_ASSET, CIPHER_INPUT) own focus.
  // Exception: pendingIngest from auto-download (sidebar may have been closed).
  if (state.probe) renderProbe(state.probe, { focus: false });
  if ("huntBase" in state) renderHuntBase(state.huntBase);
  if ("imageAsset" in state) {
    const asset = state.imageAsset;
    const pending = takePendingIngest(asset && asset.pendingIngest);
    renderImageAsset(asset, { focus: Boolean(pending && pending.focus !== false) });
    if (pending) {
      if (pending.toast) showIngestToast(pending.toast);
      const imgUrl = (asset && asset.url) || "";
      if (pending.analyzeHex && /^https?:\/\//i.test(imgUrl)) {
        runImageHex(imgUrl);
      }
      clearPendingIngest("image");
    }
  }
  if ("archiveInfo" in state) {
    const info = state.archiveInfo;
    const pending = takePendingIngest(info && info.pendingIngest);
    renderArchiveInfo(info, { focus: Boolean(pending && pending.focus !== false) });
    if (pending) {
      if (pending.toast) showIngestToast(pending.toast);
      clearPendingIngest("archive");
    }
  }
  if ("audioAsset" in state) {
    const asset = state.audioAsset;
    // pushState after tabs.create (deep tools) always includes audioAsset.
    // An empty store must not wipe an active local drop / blob preview.
    if (!isAudioAssetPresent(asset) && hasSidebarLocalAudio()) {
      if (currentAudio) persistAudioAsset(currentAudio);
    } else {
      const pending = takePendingIngest(asset && asset.pendingIngest);
      renderAudioAsset(asset, { focus: Boolean(pending && pending.focus !== false) });
      if (pending) {
        if (pending.toast) showIngestToast(pending.toast);
        const audUrl = (asset && asset.url) || "";
        if (pending.analyze && /^https?:\/\//i.test(audUrl)) {
          runAudioAnalyze(audUrl);
        }
        clearPendingIngest("audio");
      }
    }
  }

  if (typeof state.cipherInput === "string" && state.cipherInput !== els.cipherInput.value) {
    if (!els.cipherInput.matches(":focus")) {
      els.cipherInput.value = state.cipherInput;
      renderCiphers(state.cipherInput);
    }
  }
}

function hostLabel(url) {
  if (!url) return "no active tab";
  try {
    const u = new URL(url);
    return u.host || u.protocol.replace(":", "");
  } catch (_err) {
    return url.slice(0, 48);
  }
}

// ---------------------------------------------------------------------------
// Live Assets
// ---------------------------------------------------------------------------

function renderAssets(assets) {
  const comments = assets.comments || [];
  const base64 = assets.base64 || [];
  const zeroWidth = assets.zeroWidth || [];
  const flags = assets.flags || [];
  const meta = assets.meta || [];
  const revealedHidden = assets.revealedHidden || [];
  const backlinks = assets.backlinks || [];
  const mediaUrls = assets.mediaUrls || [];
  const candidates = assets.candidates || [];

  fillList(els.listBacklinks, backlinks, (item) => {
    const card = assetCard(
      item.preview || item.url || item.text,
      item.frame,
      item.url || item.text,
      item.label ? item.label + (item.source ? " · " + item.source : "") : ""
    );
    const url = item.url || "";
    if (/^https?:\/\//i.test(url)) {
      const meta = card.querySelector(".meta-line");
      if (meta) {
        const open = document.createElement("a");
        open.className = "copy-btn";
        open.href = url;
        open.target = "_blank";
        open.rel = "noopener noreferrer";
        open.textContent = "Open";
        meta.insertBefore(open, meta.lastChild);
      }
    }
    return card;
  });

  if (els.listMedia) {
    fillList(els.listMedia, mediaUrls, (item) => {
      const card = assetCard(
        item.preview || item.url,
        item.frame,
        item.url,
        (item.label || "Media") + (item.source ? " · " + item.source : "")
      );
      const url = item.url || "";
      const meta = card.querySelector(".meta-line");
      if (meta && /^https?:\/\//i.test(url)) {
        const open = document.createElement("a");
        open.className = "copy-btn";
        open.href = url;
        open.target = "_blank";
        open.rel = "noopener noreferrer";
        open.textContent = "Open";
        meta.insertBefore(open, meta.lastChild);
      }
      if (meta && url) {
        meta.appendChild(
          handoffButton("Audio", () => {
            browser.runtime
              .sendMessage({
                type: MSG.AUDIO_CAPTURE,
                url,
                analyze: /^https?:\/\//i.test(url),
                focus: true,
              })
              .catch(() => {});
          })
        );
      }
      return card;
    });
  }

  fillList(els.listCandidates, candidates, (item) => {
    const li = document.createElement("li");
    li.className = "asset-item";
    const body = document.createElement("div");
    body.className = "preview";
    body.textContent = item.text || item.id || "";
    li.appendChild(body);
    const meta = document.createElement("div");
    meta.className = "meta-line";
    const hint = document.createElement("span");
    hint.textContent = item.hint || "token";
    meta.appendChild(hint);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "cand-btn";
    btn.textContent = "Probe";
    btn.addEventListener("click", () => {
      setProbeMode("id");
      els.probeInput.value = item.text || item.id || "";
      startProbe();
    });
    meta.appendChild(btn);
    li.appendChild(meta);
    return li;
  });

  fillList(els.listRevealed, revealedHidden, (item) =>
    assetCard(item.preview || item.text, item.frame, item.text, item.reason ? "why: " + item.reason : "", {
      handoff: true,
    })
  );
  fillList(els.listComments, comments, (item) =>
    assetCard(item.preview || item.text, item.frame, item.text, "", {
      handoff: true,
      decodePreview: true,
    })
  );
  fillList(els.listBase64, base64, (item) =>
    assetCard(
      item.preview || item.text,
      item.frame,
      item.text,
      item.decodedPreview ? "decoded: " + item.decodedPreview : "",
      { handoff: true, decodePreview: !item.decodedPreview }
    )
  );
  fillList(els.listZw, zeroWidth, (item) =>
    assetCard(
      item.preview || item.text,
      item.frame,
      item.text,
      (item.codes || []).join(" ") + (item.count ? " ×" + item.count : ""),
      { handoff: true }
    )
  );
  fillList(els.listFlags, flags, (item) =>
    assetCard(item.preview || item.text, item.frame, item.text, "", { handoff: true })
  );
  fillList(els.listMeta, meta, (item) =>
    assetCard(item.preview || item.text, item.frame, item.text, item.kind || "", {
      handoff: true,
    })
  );

  setCount(els.countBacklinks, backlinks.length);
  if (els.countMedia) setCount(els.countMedia, mediaUrls.length);
  setCount(els.countCandidates, candidates.length);
  setCount(els.countRevealed, revealedHidden.length);
  setCount(els.countComments, comments.length);
  setCount(els.countBase64, base64.length);
  setCount(els.countZw, zeroWidth.length);
  setCount(els.countFlags, flags.length);
  setCount(els.countMeta, meta.length);

  const headerCount =
    (els.countHeaders && Number(els.countHeaders.textContent)) || 0;
  const robotsCount =
    (els.countRobots && Number(els.countRobots.textContent)) || 0;
  const sitemapCount =
    (els.countSitemap && Number(els.countSitemap.textContent)) || 0;
  const total =
    comments.length +
    base64.length +
    zeroWidth.length +
    flags.length +
    meta.length +
    revealedHidden.length +
    backlinks.length +
    mediaUrls.length +
    headerCount +
    robotsCount +
    sitemapCount;
  els.badgeAssets.textContent = String(total);
}

const HEADER_CLUE_RE = /hint|clue|next|flag|secret|token|key|puzzle|cipher|hunt|ctf/i;

function isSuspiciousHeader(name, value) {
  const n = String(name || "");
  const v = String(value || "");
  if (/^x-/i.test(n)) return true;
  if (HEADER_CLUE_RE.test(n)) return true;
  if (/^set-cookie$/i.test(n) && HEADER_CLUE_RE.test(v)) return true;
  if (HEADER_CLUE_RE.test(v) && !/^(content-|cache-|strict-|access-|referrer|server|date|etag|vary|age|expires|pragma|connection|keep-alive|transfer-|accept-|content-length|content-type|content-encoding)/i.test(n)) {
    return true;
  }
  // Custom non-standard names (not common HTTP headers)
  if (
    n &&
    !/^(content-|cache-|strict-|access-|referrer|server|date|etag|vary|age|expires|pragma|connection|keep-alive|transfer-|accept-|location|set-cookie|www-authenticate|retry-after|link|alt-svc|nel|report-to|permissions-policy|cross-origin|x-content-type|x-frame|x-xss|x-powered|x-request|x-amz|cf-|report-to)/i.test(
      n
    ) &&
    !/^(content-type|content-length|content-encoding|content-security-policy|content-disposition|last-modified|if-|host|user-agent)$/i.test(n)
  ) {
    // Only flag unusual short custom names that look clue-ish or non-IANA-ish
    if (/^[a-z0-9_-]{2,40}$/i.test(n) && !/^(server|date|etag|vary|age|expires|pragma|connection|location|link)$/i.test(n)) {
      if (HEADER_CLUE_RE.test(n + " " + v) || /^x-/i.test(n)) return true;
    }
  }
  return false;
}

function renderResponseHeaders(payload) {
  if (!els.listHeaders) return;
  const headers = (payload && payload.headers) || [];
  const url = (payload && payload.url) || "";
  fillList(els.listHeaders, headers, (item) => {
    const name = item.name || "";
    const value = item.value || "";
    const full = name + ": " + value;
    const suspicious = Boolean(item.suspicious) || isSuspiciousHeader(name, value);
    const li = assetCard(
      name + ": " + (value.length > 120 ? value.slice(0, 120) + "…" : value),
      url || "main",
      full,
      suspicious ? "suspicious / non-standard" : "",
      { handoff: true }
    );
    if (suspicious) {
      li.classList.add("is-suspicious");
      const body = li.querySelector(".preview");
      if (body) {
        const flag = document.createElement("span");
        flag.className = "header-flag";
        flag.textContent = "clue?";
        body.appendChild(flag);
      }
    }
    return li;
  });
  setCount(els.countHeaders, headers.length);
  // Refresh badge with header count folded in
  if (els.badgeAssets) {
    const n =
      (Number(els.countBacklinks && els.countBacklinks.textContent) || 0) +
      (Number(els.countRevealed && els.countRevealed.textContent) || 0) +
      (Number(els.countComments && els.countComments.textContent) || 0) +
      (Number(els.countBase64 && els.countBase64.textContent) || 0) +
      (Number(els.countZw && els.countZw.textContent) || 0) +
      (Number(els.countFlags && els.countFlags.textContent) || 0) +
      (Number(els.countMeta && els.countMeta.textContent) || 0) +
      (Number(els.countMedia && els.countMedia.textContent) || 0) +
      (Number(els.countRobots && els.countRobots.textContent) || 0) +
      (Number(els.countSitemap && els.countSitemap.textContent) || 0) +
      headers.length;
    els.badgeAssets.textContent = String(n);
  }
}

function refreshAssetsBadge() {
  if (!els.badgeAssets) return;
  const n =
    (Number(els.countBacklinks && els.countBacklinks.textContent) || 0) +
    (Number(els.countRevealed && els.countRevealed.textContent) || 0) +
    (Number(els.countComments && els.countComments.textContent) || 0) +
    (Number(els.countBase64 && els.countBase64.textContent) || 0) +
    (Number(els.countZw && els.countZw.textContent) || 0) +
    (Number(els.countFlags && els.countFlags.textContent) || 0) +
    (Number(els.countMeta && els.countMeta.textContent) || 0) +
    (Number(els.countMedia && els.countMedia.textContent) || 0) +
    (Number(els.countHeaders && els.countHeaders.textContent) || 0) +
    (Number(els.countRobots && els.countRobots.textContent) || 0) +
    (Number(els.countSitemap && els.countSitemap.textContent) || 0);
  els.badgeAssets.textContent = String(n);
}

function probeTokenFromDiscovery(token) {
  if (!token || !els.probeInput) return;
  setProbeMode("id");
  els.probeInput.value = String(token).trim().slice(0, 200);
  focusProbePanel();
  startProbe();
}

function discoveryPathCard(item) {
  const li = document.createElement("li");
  li.className = "asset-item";
  const path = item.path || item.url || "";
  const body = document.createElement("div");
  body.className = "preview";
  body.textContent = path;
  li.appendChild(body);

  const extra = document.createElement("div");
  extra.className = "decoded";
  const bits = [];
  if (item.rule) bits.push(item.rule);
  if (item.origin) bits.push(item.origin.replace(/^https?:\/\//i, ""));
  extra.textContent = bits.join(" · ");
  li.appendChild(extra);

  const meta = document.createElement("div");
  meta.className = "meta-line";
  const hint = document.createElement("span");
  hint.textContent = item.token ? "token?" : "path";
  meta.appendChild(hint);

  const openUrl = item.url || "";
  if (/^https?:\/\//i.test(openUrl)) {
    meta.appendChild(
      handoffButton("Open", () => {
        browser.runtime
          .sendMessage({ type: MSG.OPEN_URL, url: openUrl, active: true })
          .catch(() => {});
      })
    );
  }
  meta.appendChild(copyButton(openUrl || path));
  if (item.token) {
    meta.appendChild(
      handoffButton("Probe", () => probeTokenFromDiscovery(item.token))
    );
  }
  li.appendChild(meta);
  return li;
}

function discoverySitemapCard(item) {
  const li = document.createElement("li");
  li.className = "asset-item";
  const url = item.url || "";
  const body = document.createElement("div");
  body.className = "preview";
  body.textContent = item.path || url;
  li.appendChild(body);

  const meta = document.createElement("div");
  meta.className = "meta-line";
  const hint = document.createElement("span");
  hint.textContent = item.token ? "loc · token?" : "loc";
  meta.appendChild(hint);
  if (/^https?:\/\//i.test(url)) {
    meta.appendChild(
      handoffButton("Open", () => {
        browser.runtime
          .sendMessage({ type: MSG.OPEN_URL, url, active: true })
          .catch(() => {});
      })
    );
  }
  meta.appendChild(copyButton(url));
  if (item.token) {
    meta.appendChild(
      handoffButton("Probe", () => probeTokenFromDiscovery(item.token))
    );
  }
  li.appendChild(meta);
  return li;
}

function renderSiteDiscovery(result) {
  const paths = (result && result.paths) || [];
  const sitemaps = (result && result.sitemaps) || [];
  const robots = (result && result.robots) || [];

  if (els.sectionRobots) {
    els.sectionRobots.hidden = false;
  }
  if (els.sectionSitemap) {
    els.sectionSitemap.hidden = false;
  }

  if (els.listRobots) {
    fillList(els.listRobots, paths, discoveryPathCard);
  }
  if (els.listSitemap) {
    fillList(els.listSitemap, sitemaps, discoverySitemapCard);
  }
  if (els.countRobots) setCount(els.countRobots, paths.length);
  if (els.countSitemap) setCount(els.countSitemap, sitemaps.length);

  if (els.robotsStatus) {
    els.robotsStatus.hidden = false;
    const okOrigins = robots.filter((r) => r.ok).map((r) => r.origin);
    const miss = robots.filter((r) => !r.ok);
    const parts = [];
    if (okOrigins.length) {
      parts.push("robots OK: " + okOrigins.map((o) => o.replace(/^https?:\/\//i, "")).join(", "));
    }
    if (miss.length) {
      parts.push(
        "missing: " +
          miss
            .map((r) => (r.origin || "").replace(/^https?:\/\//i, "") || "?")
            .join(", ")
      );
    }
    parts.push(paths.length + " paths");
    parts.push(sitemaps.length + " sitemap locs");
    els.robotsStatus.textContent = parts.join(" · ");
  }

  refreshAssetsBadge();
}

async function fetchSiteDiscovery() {
  if (els.btnRobots) els.btnRobots.disabled = true;
  if (els.robotsStatus) {
    els.robotsStatus.hidden = false;
    els.robotsStatus.textContent = "Fetching robots.txt…";
  }
  try {
    const windowId = await currentWindowId();
    const res = await browser.runtime.sendMessage({
      type: MSG.FETCH_SITE_DISCOVERY,
      windowId,
      includeHuntBase: true,
    });
    if (!res || !res.ok) {
      if (els.robotsStatus) {
        els.robotsStatus.textContent =
          (res && res.error) || "No robots.txt / sitemap found.";
      }
      if (els.sectionRobots) els.sectionRobots.hidden = false;
      if (els.sectionSitemap) els.sectionSitemap.hidden = false;
      if (els.listRobots) fillList(els.listRobots, [], discoveryPathCard);
      if (els.listSitemap) fillList(els.listSitemap, [], discoverySitemapCard);
      if (els.countRobots) setCount(els.countRobots, 0);
      if (els.countSitemap) setCount(els.countSitemap, 0);
      refreshAssetsBadge();
      return;
    }
    renderSiteDiscovery(res);
  } catch (_err) {
    if (els.robotsStatus) {
      els.robotsStatus.textContent = "Fetch failed on this page.";
    }
  } finally {
    if (els.btnRobots) els.btnRobots.disabled = false;
  }
}

function setCount(el, n) {
  el.textContent = String(n);
}

function fillList(ul, items, render) {
  ul.replaceChildren();
  for (const item of items) {
    ul.appendChild(render(item));
  }
}

function assetCard(preview, frame, fullText, extra, options) {
  const opts = options || {};
  const text = fullText || preview || "";
  const li = document.createElement("li");
  li.className = "asset-item";

  const body = document.createElement("div");
  body.className = "preview";
  body.textContent = preview || "(empty)";
  li.appendChild(body);

  if (extra) {
    const decoded = document.createElement("div");
    decoded.className = "decoded";
    decoded.textContent = extra;
    li.appendChild(decoded);
  }

  if (opts.decodePreview) {
    const tip = suggestDecodePreview(text);
    if (tip) {
      const chip = document.createElement("div");
      chip.className = "decode-chip";
      chip.textContent = tip.label + " → " + tip.preview;
      chip.title = tip.full;
      chip.addEventListener("click", () => sendTextToCipher(tip.full));
      li.appendChild(chip);
    }
  }

  const meta = document.createElement("div");
  meta.className = "meta-line";

  const src = document.createElement("span");
  src.textContent = frameLabel(frame);
  meta.appendChild(src);
  meta.appendChild(copyButton(text));

  if (opts.handoff && text) {
    meta.appendChild(
      handoffButton("Cipher", () => sendTextToCipher(text))
    );
    meta.appendChild(
      handoffButton("Probe", () => {
        setProbeMode("id");
        els.probeInput.value = text.trim().slice(0, 200);
        focusProbePanel();
        startProbe();
      })
    );
    meta.appendChild(
      handoffButton("Notes", () => {
        if (!els.notesInput) return;
        const cur = els.notesInput.value || "";
        els.notesInput.value = cur ? cur + "\n" + text : text;
        persistNotesSoon();
        focusNotesPanel();
      })
    );
    const maybeDomain = text.trim().match(/(?:https?:\/\/)?([a-z0-9.-]+\.[a-z]{2,})(?:\/|\s|$)/i);
    if (maybeDomain) {
      meta.appendChild(
        handoffButton("DNS", () => {
          focusDnsPanel();
          els.dnsInput.value = maybeDomain[1];
          runDnsLookup();
        })
      );
    }
  }

  li.appendChild(meta);
  return li;
}

function handoffButton(label, onClick) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "cand-btn";
  btn.textContent = label;
  btn.addEventListener("click", (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    onClick();
  });
  return btn;
}

function looksMostlyPrintable(s) {
  if (!s || s.length < 2) return false;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) ok++;
  }
  return ok / s.length >= 0.85;
}

function bytesToGroupedHex(bytes, maxBytes) {
  const n = maxBytes == null ? bytes.length : Math.min(bytes.length, maxBytes);
  const parts = [];
  for (let i = 0; i < n; i++) {
    parts.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return parts.join(" ");
}

/** Turn decoded bytes into text, or a clear hex dump when non-printable. */
function formatDecodedBytes(bytes) {
  if (!bytes || !bytes.length) {
    return { ok: true, text: "" };
  }
  const text = bytesToText(bytes);
  const printable =
    text.length >= 2
      ? looksMostlyPrintable(text)
      : (() => {
          const c = text.charCodeAt(0);
          return c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126);
        })();
  if (printable) {
    return { ok: true, text };
  }
  const preview = bytesToGroupedHex(bytes, 128);
  const truncated = bytes.length > 128 ? " …" : "";
  const n = bytes.length;
  return {
    ok: true,
    binary: true,
    text: "binary (" + n + " byte" + (n === 1 ? "" : "s") + ")\n" + preview + truncated,
    copyText: bytesToGroupedHex(bytes),
  };
}

function suggestDecodePreview(raw) {
  const text = String(raw || "").trim();
  if (!text || text.length < 8) return null;

  const tryOct = decodeOctal(text);
  if (
    tryOct.ok &&
    !tryOct.binary &&
    looksMostlyPrintable(tryOct.text) &&
    tryOct.text.length >= 2
  ) {
    return {
      label: "Octal",
      preview: tryOct.text.slice(0, 80),
      full: tryOct.text,
    };
  }
  const tryTern = decodeTernary(text);
  if (tryTern.ok && tryTern.copyText && looksMostlyPrintable(tryTern.copyText) && tryTern.copyText.length >= 2) {
    return {
      label: "Ternary",
      preview: tryTern.copyText.slice(0, 80),
      full: tryTern.copyText,
    };
  }
  const tryDec = decodeDecimal(text);
  if (
    tryDec.ok &&
    !tryDec.binary &&
    looksMostlyPrintable(tryDec.text) &&
    tryDec.text.length >= 2
  ) {
    return {
      label: "Decimal",
      preview: tryDec.text.slice(0, 80),
      full: tryDec.text,
    };
  }
  const tryB64 = decodeBase64(text);
  if (
    tryB64.ok &&
    !tryB64.binary &&
    looksMostlyPrintable(tryB64.text) &&
    tryB64.text.length >= 2
  ) {
    return {
      label: "Base64",
      preview: tryB64.text.slice(0, 80),
      full: tryB64.text,
    };
  }
  return null;
}

function sendTextToCipher(text) {
  const t = String(text || "");
  els.cipherInput.value = t;
  renderCiphers(t);
  focusCipherPanel();
  browser.runtime.sendMessage({ type: MSG.CIPHER_INPUT, text: t }).catch(() => {});
}

function persistNotesSoon() {
  scheduleNotesSave();
}

function focusNotesPanel() {
  focusPanel("panel-notes");
  if (els.notesInput) els.notesInput.focus();
}

function focusDnsPanel() {
  focusPanel("panel-dns");
  if (els.dnsInput) els.dnsInput.focus();
}

function focusGeohashPanel() {
  focusPanel("panel-geohash");
  if (els.geohashInput) els.geohashInput.focus();
}

function frameLabel(frame) {
  if (!frame) return "main";
  try {
    const u = new URL(frame);
    return u.host + u.pathname;
  } catch (_err) {
    return String(frame).slice(0, 40);
  }
}

function copyButton(text) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  btn.addEventListener("click", async (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    const ok = await copyText(text);
    btn.textContent = ok ? "Copied" : "Fail";
    setTimeout(() => {
      btn.textContent = "Copy";
    }, 900);
  });
  return btn;
}

// ---------------------------------------------------------------------------
// Redirect log
// ---------------------------------------------------------------------------

function renderRedirects(log) {
  const list = Array.isArray(log) ? log : [];
  els.badgeRedirects.textContent = String(list.length);
  els.redirects.replaceChildren();

  for (const chain of list) {
    const wrap = document.createElement("article");
    wrap.className = "chain";

    const head = document.createElement("div");
    head.className = "chain-head";
    const when = document.createElement("span");
    when.textContent = formatTime(chain.completedAt);
    const hops = document.createElement("span");
    hops.textContent = (chain.hops ? chain.hops.length : 0) + " hops";
    head.append(when, hops);
    wrap.appendChild(head);

    (chain.hops || []).forEach((hop, idx) => {
      const row = document.createElement("div");
      row.className = "hop";

      const n = document.createElement("span");
      n.className = "hop-idx";
      n.textContent = String(idx + 1);

      const url = document.createElement("span");
      url.className = "hop-url";
      url.textContent = hop.url;
      url.title = hop.url;

      const via = document.createElement("span");
      via.className = "via";
      via.textContent = hop.statusCode
        ? hop.via + " " + hop.statusCode
        : hop.via || "nav";

      row.append(n, url, via);
      wrap.appendChild(row);
    });

    const copyRow = document.createElement("div");
    copyRow.className = "meta-line";
    copyRow.style.marginTop = "4px";
    const chainText = (chain.hops || []).map((h) => h.url).join("\n→ ");
    copyRow.appendChild(copyButton(chainText));
    wrap.appendChild(copyRow);

    els.redirects.appendChild(wrap);
  }
}

function formatTime(ts) {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleTimeString();
  } catch (_err) {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Cipher clipboard — all translations are local
// ---------------------------------------------------------------------------

/** Higher = more useful to show first. Failures always sort below valids. */
function cipherCardSortKey(spec, result, guessIds, specIndex, input) {
  if (!result || !result.ok) {
    return { tier: 1, quality: 0, index: specIndex };
  }

  let quality = 0;
  const text = String(result.text || "");
  const scoreTarget = String(result.copyText || text);
  const scoreBody =
    typeof result.score === "number" && Number.isFinite(result.score)
      ? result.score
      : scoreEnglishish(scoreTarget);

  if (result.binary) {
    // Hex/binary dumps beat failures but lose to clean text.
    quality = 20 + Math.min(text.length, 40) * 0.05;
  } else {
    quality = 100;
    if (looksMostlyPrintable(scoreTarget)) quality += 25;
    if (/\s/.test(scoreTarget)) quality += 8;
    if (/[A-Za-z]{3,}/.test(scoreTarget)) quality += 12;
    quality += scoreBody * 12;

    // Caesar crib / manual keyed transforms with strong English scores float up.
    if (
      (spec.id === "caesar" ||
        spec.id === "rotn" ||
        spec.id === "rotn-ascii" ||
        spec.id === "vigenere" ||
        spec.id === "xor") &&
      typeof result.score === "number"
    ) {
      quality += 40 + result.score * 8;
    }

    // Encode-only transforms (numbers/symbols) are less actionable than plaintext.
    if (/encode/i.test(result.label || spec.label) && !/[A-Za-z]{3,}/.test(text)) {
      quality -= 35;
    }

    if (spec.id === "dec" && looksLikeDecimalAscii(input)) {
      quality += 60;
    }
    if (
      (spec.id === "rotn" || spec.id === "rotn-ascii" || spec.id === "rot13") &&
      looksLikeDecimalAscii(input)
    ) {
      quality -= 45;
    }
  }

  if (guessIds.has(spec.id)) quality += 30;

  return { tier: 0, quality, index: specIndex };
}

function compareCipherCards(a, b) {
  if (a.key.tier !== b.key.tier) return a.key.tier - b.key.tier;
  if (b.key.quality !== a.key.quality) return b.key.quality - a.key.quality;
  return a.key.index - b.key.index;
}

function renderCiphers(raw) {
  const input = raw == null ? "" : String(raw);
  els.cipherCards.replaceChildren();
  if (els.cipherGuesses) {
    els.cipherGuesses.replaceChildren();
    els.cipherGuesses.hidden = true;
  }
  if (!input.trim()) return;

  const guesses = guessCipherKinds(input);
  const guessIds = new Set(guesses.map((g) => g.id));
  if (els.cipherGuesses && guesses.length) {
    els.cipherGuesses.hidden = false;
    for (const g of guesses) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "cipher-guess";
      chip.textContent = g.label;
      chip.title = g.reason || g.label;
      chip.addEventListener("click", () => focusCipherCard(g.id));
      els.cipherGuesses.appendChild(chip);
    }
  }

  const cards = CIPHER_SPECS.map((spec, index) => {
    const result = spec.run(input);
    return {
      spec,
      result,
      key: cipherCardSortKey(spec, result, guessIds, index, input),
    };
  });

  const key = getCipherSessionKey();
  if (key.trim()) {
    const baseIndex = CIPHER_SPECS.length;
    CIPHER_KEY_SPECS.forEach((spec, i) => {
      const result = spec.run(input);
      cards.push({
        spec,
        result,
        key: cipherCardSortKey(spec, result, guessIds, baseIndex + i, input),
      });
    });
  }

  cards.sort(compareCipherCards);

  const topId = cards[0]?.spec?.id || "";
  const decCard = cards.find((c) => c.spec.id === "dec");
  if (
    els.cipherGuesses &&
    decCard?.result?.ok &&
    looksLikeDecimalAscii(input) &&
    (topId === "rotn" || topId === "rotn-ascii" || topId === "rot13")
  ) {
    const hint = document.createElement("span");
    hint.className = "cipher-decimal-hint";
    hint.textContent = "Try Decimal";
    hint.title = "Input looks like decimal ASCII codes — check the Decimal card";
    hint.addEventListener("click", () => focusCipherCard("dec"));
    els.cipherGuesses.appendChild(hint);
    els.cipherGuesses.hidden = false;
  }

  for (const { spec, result } of cards) {
    const card = document.createElement("article");
    card.className =
      "cipher-card" +
      (result.ok ? "" : " invalid") +
      (result.binary ? " is-binary" : "");
    card.id = "cipher-card-" + spec.id;
    card.dataset.cipherId = spec.id;

    const header = document.createElement("header");
    const title = document.createElement("div");
    title.className = "cipher-card-title";
    const h3 = document.createElement("h3");
    h3.textContent = result.label || spec.label;
    title.appendChild(h3);
    if (result.binary) {
      const badge = document.createElement("span");
      badge.className = "cipher-binary-badge";
      badge.textContent = "binary / not text";
      title.appendChild(badge);
    }
    header.appendChild(title);
    if (result.ok) header.appendChild(copyButton(result.copyText || result.text));
    card.appendChild(header);

    const pre = document.createElement("pre");
    pre.textContent = result.text;
    card.appendChild(pre);
    els.cipherCards.appendChild(card);
  }
}

function focusCipherCard(id) {
  const card = document.getElementById("cipher-card-" + id);
  if (!card) return;
  focusCipherPanel();
  card.scrollIntoView({ block: "nearest", behavior: "smooth" });
  card.classList.add("is-flash");
  setTimeout(() => card.classList.remove("is-flash"), 900);
}

function guessCipherKinds(raw) {
  const input = String(raw || "").trim();
  if (!input) return [];
  const out = [];
  const push = (id, label, reason) => {
    if (out.some((g) => g.id === id)) return;
    out.push({ id, label, reason });
  };

  const compact = input.replace(/\s+/g, "");
  const letters = (input.match(/[a-zA-Z]/g) || []).length;
  const digits = (input.match(/\d/g) || []).length;
  const len = input.length;

  // Morse
  if (/^[.\-\s_–—/−•·‧∙/|]+$/.test(input) && /[.\-]/.test(input)) {
    push("morse", "Morse", "dot/dash alphabet");
  }

  // Binary
  const bits = input.replace(/[^01]/g, "");
  if (bits.length >= 8 && bits.length % 8 === 0 && bits.length / len > 0.7) {
    push("bin", "Binary", "0/1 groups");
  }

  // Binary → Morse (0=· 1=−), including short runs like 0101
  if (bits.length >= 2 && bits.length / Math.max(compact.length, 1) >= 0.75) {
    const spacedBitGroups =
      /[\s/]/.test(input) &&
      input
        .trim()
        .split(/[\s/]+/)
        .filter(Boolean)
        .every((p) => /^[01]+$/.test(p));
    const shortOrUnaligned = bits.length < 8 || bits.length % 8 !== 0;
    if (spacedBitGroups || shortOrUnaligned) {
      push("binmorse", "Bin→Morse", "0/1 as dot/dash");
    }
  }

  // Hex
  const hexOnly = compact.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
  if (hexOnly.length >= 4 && hexOnly.length % 2 === 0 && /^[0-9a-f]+$/i.test(hexOnly)) {
    const printableRatio = letters + digits;
    if (hexOnly.length >= len * 0.6) push("hex", "Hex", "hex charset");
  }

  // Octal token groups
  const octTokens = input.trim().split(/[\s,;|/\\]+/).filter(Boolean);
  if (octTokens.length >= 3 && octTokens.every((t) => /^[0-7]{1,3}$/.test(t))) {
    push("oct", "Octal", "octal codes");
  }

  // Decimal ASCII — hash/star or space-separated codes (32–126)
  if (looksLikeDecimalAscii(input)) {
    push("dec", "Decimal", "decimal ASCII codes");
  }

  // Ternary / base-3 (digits 0–2; often 5-trit ASCII or letter groups)
  const ternTokens = input.trim().split(/[\s,;|/\\]+/).filter(Boolean);
  const ternJoined = ternTokens.join("");
  if (
    ternTokens.length >= 2 &&
    ternTokens.every((t) => /^[0-2]{2,12}$/.test(t)) &&
    (/2/.test(ternJoined) || ternTokens.every((t) => t.length >= 3 && t.length <= 6))
  ) {
    push("ternary", "Ternary", "base-3 digit groups");
  } else {
    const tritRun = compact.replace(/[^0-2]/g, "");
    if (
      tritRun.length >= 10 &&
      /2/.test(tritRun) &&
      tritRun.length === compact.replace(/[\s,;|/\\]+/g, "").length &&
      (tritRun.length % 5 === 0 || tritRun.length % 4 === 0 || tritRun.length % 3 === 0)
    ) {
      push("ternary", "Ternary", "base-3 digit run");
    }
  }

  // Base64
  if (
    compact.length >= 8 &&
    compact.length % 4 === 0 &&
    /^[A-Za-z0-9+/]+=*$/.test(compact) &&
    /[+/=]/.test(compact)
  ) {
    push("b64", "Base64", "Base64 alphabet");
  } else if (
    compact.length >= 12 &&
    /^[A-Za-z0-9+/]{8,}={0,2}$/.test(compact) &&
    /[A-Z]/.test(compact) &&
    /[a-z]/.test(compact) &&
    /\d/.test(compact)
  ) {
    push("b64", "Base64", "mixed Base64-like");
  }

  // A1Z26 — mostly numbers 1–26
  const a1Tokens = input.trim().split(/[\s,;|.-]+/).filter(Boolean);
  if (
    a1Tokens.length >= 3 &&
    a1Tokens.every((t) => /^(?:[1-9]|1\d|2[0-6])$/.test(t))
  ) {
    push("a1z26", "A1Z26", "1–26 letter codes");
  }

  // T9 multi-tap
  const t9Tokens = input.trim().split(/[\s,;|]+/).filter(Boolean);
  if (t9Tokens.length >= 2 && t9Tokens.every((t) => /^([2-9])\1{0,3}$/.test(t))) {
    push("t9", "T9", "multi-tap keypad");
  }

  // Bacon A/B or 0/1 in groups of 5
  const baconBits = input.replace(/[^abAB01]/g, "");
  if (baconBits.length >= 15 && baconBits.length % 5 === 0) {
    push("bacon", "Bacon", "A/B or 0/1 ×5");
  } else if (looksLikeBaconCase(input)) {
    push("bacon", "Bacon", "alternating case pattern");
  }

  // Polyalphabetic / Caesar-ish: letters only with unusual letter frequencies
  const alpha = input.replace(/[^a-zA-Z]/g, "");
  if (alpha.length >= 8 && alpha.length / Math.max(len, 1) > 0.7) {
    const unique = new Set(alpha.toLowerCase()).size;
    if (unique >= 8 && unique <= 20) {
      push("caesar", "Caesar", "letter-heavy — try ROT crib");
    }
    // Light polyalphabetic hint only (no full Vigenère brute)
    if (unique >= 12 && alpha.length >= 16) {
      push("caesar", "Polyalphabetic?", "letter soup — Caesar crib first");
    }
  }

  // Entropy-ish: high unique chars in alphanumeric blob
  if (compact.length >= 16) {
    const uniq = new Set(compact).size;
    if (uniq / compact.length > 0.55 && /^[A-Za-z0-9+/=]+$/.test(compact)) {
      push("b64", "Base64", "high entropy alphanumeric");
    }
  }

  return out.slice(0, 6);
}

function looksLikeBaconCase(input) {
  const letters = (String(input).match(/[a-zA-Z]/g) || []).join("");
  if (letters.length < 15 || letters.length % 5 !== 0) return false;
  let flips = 0;
  for (let i = 1; i < letters.length; i++) {
    const a = letters[i - 1] === letters[i - 1].toUpperCase();
    const b = letters[i] === letters[i].toUpperCase();
    if (a !== b) flips++;
  }
  return flips / (letters.length - 1) >= 0.35;
}

function bytesToText(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch (_err) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }
}

function decodeBase64(input) {
  const compact = input.replace(/\s+/g, "");
  try {
    const bin = atob(compact);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return formatDecodedBytes(bytes);
  } catch (_err) {
    return { ok: false, text: "not valid Base64" };
  }
}

function decodeHex(input) {
  const hex = input.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
  if (hex.length < 2 || hex.length % 2 !== 0) {
    return { ok: false, text: "not valid hex (need even length)" };
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return formatDecodedBytes(bytes);
}

function decodeBinary(input) {
  const bits = input.replace(/[^01]/g, "");
  if (bits.length < 8 || bits.length % 8 !== 0) {
    return { ok: false, text: "not valid binary (need 8-bit groups)" };
  }
  const bytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 8) {
    bytes[i / 8] = parseInt(bits.slice(i, i + 8), 2);
  }
  return formatDecodedBytes(bytes);
}

function mapBitsToMorse(bits, zeroIsDot) {
  const dot = zeroIsDot ? "." : "-";
  const dash = zeroIsDot ? "-" : ".";
  return bits
    .split("")
    .map((b) => (b === "0" ? dot : dash))
    .join("");
}

/** Space-separated bit groups = letters; / or 2+ spaces = word breaks. */
function binaryToMorseString(input, zeroIsDot) {
  const trimmed = String(input || "").trim();
  if (!trimmed) return "";

  const words = trimmed.split(/\s*\/\s*|\s{2,}/);
  const outWords = [];
  for (const word of words) {
    const letters = [];
    for (const part of word.trim().split(/\s+/).filter(Boolean)) {
      const bits = part.replace(/[^01]/g, "");
      if (bits) letters.push(mapBitsToMorse(bits, zeroIsDot));
    }
    if (letters.length) outWords.push(letters.join(" "));
  }
  return outWords.join(" / ");
}

function decodeBinaryMorse(input) {
  const trimmed = String(input || "").trim();
  if (!trimmed) return { ok: false, text: "not valid binary Morse" };

  const bitsOnly = trimmed.replace(/[^01]/g, "");
  if (bitsOnly.length < 2) {
    return { ok: false, text: "need at least 2 bits (0=· 1=−)" };
  }
  if (bitsOnly.length / trimmed.replace(/\s+/g, "").length < 0.5) {
    return { ok: false, text: "not enough 0/1 digits" };
  }

  const hasBreaks = /[\s/]/.test(trimmed);
  const morse0 = hasBreaks
    ? binaryToMorseString(trimmed, true)
    : mapBitsToMorse(bitsOnly, true);
  const morse1 = hasBreaks
    ? binaryToMorseString(trimmed, false)
    : mapBitsToMorse(bitsOnly, false);

  if (!morse0) return { ok: false, text: "not valid binary Morse" };

  const lines = [];
  const dec0 = decodeMorse(morse0);
  lines.push("0=· 1=−: " + morse0);
  if (dec0.ok) lines.push("→ " + dec0.text);

  if (morse1 !== morse0) {
    const dec1 = decodeMorse(morse1);
    lines.push("0=− 1=·: " + morse1);
    if (dec1.ok) lines.push("→ " + dec1.text);
  }

  return { ok: true, text: lines.join("\n") };
}

function codesToText(values, radix, label) {
  if (!values.length) {
    return { ok: false, text: "not valid " + label };
  }
  const bytes = new Uint8Array(values.length);
  for (let i = 0; i < values.length; i++) {
    const n = parseInt(values[i], radix);
    if (!Number.isFinite(n) || n < 0 || n > 255) {
      return { ok: false, text: "not valid " + label + " (codes must be 0–255)" };
    }
    bytes[i] = n;
  }
  return formatDecodedBytes(bytes);
}

function decodeOctal(input) {
  // Space / comma / slash / pipe / backslash-separated tokens (e.g. 110 145 154)
  const tokens = input
    .trim()
    .replace(/\\([0-7]+)/g, " $1 ")
    .split(/[\s,;|/\\]+/)
    .filter(Boolean);
  if (tokens.length >= 1 && tokens.every((t) => /^[0-7]{1,3}$/.test(t))) {
    return codesToText(tokens, 8, "octal");
  }

  // Continuous octal digits in 3-digit groups (e.g. 110145154154157)
  const oct = input.replace(/[^0-7]/g, "");
  if (oct.length < 3 || oct.length % 3 !== 0) {
    return { ok: false, text: "not valid octal (need groups or 3-digit runs)" };
  }
  const groups = [];
  for (let i = 0; i < oct.length; i += 3) groups.push(oct.slice(i, i + 3));
  return codesToText(groups, 8, "octal");
}

const DECIMAL_ASCII_MIN = 32;
const DECIMAL_ASCII_MAX = 126;

function isDecimalAsciiCode(n) {
  return Number.isFinite(n) && n >= DECIMAL_ASCII_MIN && n <= DECIMAL_ASCII_MAX;
}

/**
 * Greedy split of a digit run into printable ASCII codes (32–126).
 * Prefers 3-digit codes in 100–126, else 2-digit codes in 32–99.
 * @param {string} digits
 * @returns {string[] | null}
 */
function greedySplitDecimalAscii(digits) {
  const codes = [];
  let i = 0;
  while (i < digits.length) {
    let took = false;
    if (i + 3 <= digits.length) {
      const n3 = parseInt(digits.slice(i, i + 3), 10);
      if (n3 >= 100 && n3 <= DECIMAL_ASCII_MAX) {
        codes.push(digits.slice(i, i + 3));
        i += 3;
        took = true;
      }
    }
    if (!took && i + 2 <= digits.length) {
      const n2 = parseInt(digits.slice(i, i + 2), 10);
      if (n2 >= DECIMAL_ASCII_MIN && n2 <= 99) {
        codes.push(digits.slice(i, i + 2));
        i += 2;
        took = true;
      }
    }
    if (!took && i + 3 <= digits.length) {
      const n3 = parseInt(digits.slice(i, i + 3), 10);
      if (isDecimalAsciiCode(n3)) {
        codes.push(digits.slice(i, i + 3));
        i += 3;
        took = true;
      }
    }
    if (!took) return null;
  }
  return codes;
}

/**
 * Expand one digit token into printable ASCII code strings (drops noise < 32).
 * @param {string} token
 * @returns {string[]}
 */
function expandDecimalAsciiToken(token) {
  const t = String(token || "").trim();
  if (!/^\d+$/.test(t)) return [];
  if (t.length <= 3) {
    const n = parseInt(t, 10);
    return isDecimalAsciiCode(n) ? [t] : [];
  }
  return greedySplitDecimalAscii(t) || [];
}

/**
 * Parse hunt-style decimal ASCII from hash/star noise or spaced numbers.
 * @param {string} input
 * @returns {string[] | null}
 */
function parseDecimalAsciiCodes(input) {
  const raw = String(input || "").trim();
  if (!raw) return null;

  /** @type {string[]} */
  const codes = [];

  if (/[#*]/.test(raw)) {
    for (const tok of raw.split(/[#*]+/).filter(Boolean)) {
      if (/^\d+$/.test(tok)) codes.push(...expandDecimalAsciiToken(tok));
    }
    return codes.length ? codes : null;
  }

  const parts = raw.split(/[\s,;|]+/).filter(Boolean);
  if (!parts.length) return null;

  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    codes.push(...expandDecimalAsciiToken(part));
  }
  return codes.length ? codes : null;
}

/** Input mostly space/hash-separated decimal ASCII codes (not letter ciphers). */
function looksLikeDecimalAscii(raw) {
  const input = String(raw || "").trim();
  if (!input || input.length < 4) return false;

  if (/^(\d{2,3})([\s,;|]+\d{2,3})+$/.test(input)) return true;

  if (/[#*]/.test(input)) {
    const tokens = input.split(/[#*]+/).filter((t) => /^\d+$/.test(t));
    if (tokens.length >= 2) return true;
  }

  const parts = input.split(/[\s,;|]+/).filter(Boolean);
  if (parts.length < 2) return false;
  let digitParts = 0;
  for (const p of parts) {
    if (/^\d+$/.test(p)) digitParts++;
  }
  return digitParts >= 2 && digitParts / parts.length >= 0.6;
}

function decodeDecimal(input) {
  const codes = parseDecimalAsciiCodes(input);
  if (!codes || !codes.length) {
    return { ok: false, text: "not valid decimal ASCII (need space-separated codes)" };
  }
  return codesToText(codes, 10, "decimal ASCII");
}

/** Split input into base-3 digit groups, or null if not clearly ternary. */
function parseTernaryGroups(input) {
  const raw = String(input || "").trim();
  if (!raw) return null;

  const tokens = raw.split(/[\s,;|/\\]+/).filter(Boolean);
  if (tokens.length >= 2 && tokens.every((t) => /^[0-2]{1,12}$/.test(t))) {
    const joined = tokens.join("");
    const hasTwo = /2/.test(joined);
    const tritSized = tokens.every((t) => t.length >= 2 && t.length <= 6);
    // Need a 2, or consistent short trit groups (not lone bits / 8-bit binary).
    if (hasTwo || (tritSized && tokens.length >= 3 && !tokens.every((t) => t.length === 8))) {
      return tokens;
    }
  }

  // Continuous 0–2 run — require a 2 so we don't steal binary bitstreams.
  const compact = raw.replace(/[\s,;|/\\]+/g, "");
  if (!/^[0-2]+$/.test(compact) || !/2/.test(compact) || compact.length < 6) {
    return null;
  }
  let width = 0;
  if (compact.length % 5 === 0) width = 5;
  else if (compact.length % 4 === 0) width = 4;
  else if (compact.length % 3 === 0) width = 3;
  else return null;

  const groups = [];
  for (let i = 0; i < compact.length; i += width) {
    groups.push(compact.slice(i, i + width));
  }
  return groups.length >= 2 ? groups : null;
}

function decodeTernary(input) {
  const groups = parseTernaryGroups(input);
  if (!groups) {
    return { ok: false, text: "not valid ternary (need 0–2 digit groups)" };
  }

  const decimals = [];
  for (const g of groups) {
    const n = parseInt(g, 3);
    if (!Number.isFinite(n) || n < 0) {
      return { ok: false, text: "not valid ternary" };
    }
    decimals.push(n);
  }

  const asciiChars = decimals.map((n) =>
    n >= 32 && n <= 126 ? String.fromCharCode(n) : null
  );
  const asciiAll = asciiChars.every((c) => c != null);
  const asciiText = asciiAll ? asciiChars.join("") : null;

  const letters0 = decimals.map((n) =>
    n >= 0 && n <= 25 ? String.fromCharCode(65 + n) : null
  );
  const letters1 = decimals.map((n) =>
    n >= 1 && n <= 26 ? String.fromCharCode(64 + n) : null
  );
  const a0 = letters0.every((c) => c != null) ? letters0.join("") : null;
  const a1 = letters1.every((c) => c != null) ? letters1.join("") : null;

  // Prefer ASCII when every code is printable; else letter maps (A=0 / A=1).
  const candidates = [];
  if (asciiText) candidates.push({ kind: "ascii", text: asciiText });
  if (a0) candidates.push({ kind: "A=0", text: a0 });
  if (a1 && a1 !== a0) candidates.push({ kind: "A=1", text: a1 });

  if (!candidates.length) {
    // Still useful: show decimals so hunters can map manually.
    return {
      ok: true,
      text: "dec: " + decimals.join(" "),
      copyText: decimals.join(" "),
      score: 0,
    };
  }

  candidates.sort((a, b) => {
    const sa = scoreEnglishish(a.text) + (looksMostlyPrintable(a.text) ? 2 : 0);
    const sb = scoreEnglishish(b.text) + (looksMostlyPrintable(b.text) ? 2 : 0);
    if (sb !== sa) return sb - sa;
    // Prefer ASCII over letter-offset labels when scores tie.
    if (a.kind === "ascii" && b.kind !== "ascii") return -1;
    if (b.kind === "ascii" && a.kind !== "ascii") return 1;
    return 0;
  });

  const best = candidates[0];
  const lines = [];
  lines.push(best.kind === "ascii" ? best.text : best.kind + ": " + best.text);
  for (let i = 1; i < candidates.length; i++) {
    const c = candidates[i];
    if (c.text === best.text) continue;
    lines.push(c.kind === "ascii" ? "ASCII: " + c.text : c.kind + ": " + c.text);
  }
  lines.push("dec: " + decimals.join(" "));

  return {
    ok: true,
    text: lines.join("\n"),
    copyText: best.text,
    score: scoreEnglishish(best.text),
    label: best.kind === "ascii" ? "Ternary → ASCII" : "Ternary → letters (" + best.kind + ")",
  };
}

function decodeRot13(input) {
  const text = input.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
  return { ok: true, text };
}

/** Clamp manual ROT-N (0–100). Letters card uses N % 26; ASCII card uses full N. */
function clampCipherRotN(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 13;
  return Math.max(0, Math.min(CIPHER_ROT_SLIDER_MAX, Math.trunc(v)));
}

function getCipherRotN() {
  if (els.cipherRotN) return clampCipherRotN(els.cipherRotN.value);
  if (els.cipherRotSlider) return clampCipherRotN(els.cipherRotSlider.value);
  return 13;
}

function setCipherRotN(n, opts) {
  const v = clampCipherRotN(n);
  if (els.cipherRotN) els.cipherRotN.value = String(v);
  if (els.cipherRotSlider) els.cipherRotSlider.value = String(v);
  if (!opts || opts.persist !== false) {
    browser.storage.local.set({ [CIPHER_ROT_N_KEY]: v }).catch(() => {});
  }
  return v;
}

function getCipherSessionKey() {
  return cipherSessionKey;
}

function setCipherSessionKey(raw) {
  cipherSessionKey = String(raw == null ? "" : raw);
  return cipherSessionKey;
}

/** Shift printable ASCII 32–126 by N (95-char ring). */
function asciiPrintableShift(text, shift) {
  const span = 95;
  const n = ((Number(shift) % span) + span) % span;
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 32 && c <= 126) {
      out += String.fromCharCode(32 + ((c - 32 + n) % span));
    } else {
      out += text[i];
    }
  }
  return out;
}

/** Manual ROT-N letters: shift by N mod 26. */
function decodeRotNManual(input) {
  const n = getCipherRotN();
  const equiv = n % 26;
  const text = caesarShift(String(input || ""), equiv);
  const score = scoreEnglishish(text);
  return {
    ok: true,
    text,
    score,
    label:
      n === equiv
        ? "ROT-N · letters · " + equiv
        : "ROT-N · letters · " + n + " ≡ " + equiv,
  };
}

/** Manual ROT-N ASCII printable 32–126 (full N) — no extra mode UI. */
function decodeRotNAscii(input) {
  const n = getCipherRotN();
  const text = asciiPrintableShift(String(input || ""), n);
  return {
    ok: true,
    text,
    score: scoreEnglishish(text),
    label: "ROT-N · ASCII · +" + n,
  };
}

function decodeVigenereKey(input) {
  const keyRaw = getCipherSessionKey();
  const keyLetters = keyRaw.replace(/[^a-zA-Z]/g, "");
  if (!keyLetters) {
    return { ok: false, text: "key needs A–Z letters for Vigenère" };
  }
  const raw = String(input || "");
  let ki = 0;
  const text = raw.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    const shift = keyLetters[ki % keyLetters.length].toUpperCase().charCodeAt(0) - 65;
    ki += 1;
    return String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26) % 26) + base);
  });
  if (ki === 0) {
    return { ok: false, text: "ciphertext needs letters for Vigenère" };
  }
  const score = scoreEnglishish(text);
  return {
    ok: true,
    text,
    score,
    label: "Vigenère (key)",
  };
}

function decodeXorKey(input) {
  const key = getCipherSessionKey();
  if (!key) {
    return { ok: false, text: "need a key for XOR" };
  }
  const raw = String(input || "");
  if (!raw.length) {
    return { ok: false, text: "empty input" };
  }
  const bytes = [];
  for (let i = 0; i < raw.length; i++) {
    bytes.push(raw.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  let asText = "";
  for (let i = 0; i < bytes.length; i++) asText += String.fromCharCode(bytes[i]);
  if (
    looksMostlyPrintable(asText) ||
    bytes.every((b) => b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126))
  ) {
    return {
      ok: true,
      text: asText,
      score: scoreEnglishish(asText),
      label: "XOR (key)",
    };
  }
  const hex = bytesToGroupedHex(bytes);
  return {
    ok: true,
    text: hex,
    copyText: bytes.map((b) => b.toString(16).padStart(2, "0")).join(""),
    binary: true,
    label: "XOR (key) · hex",
  };
}

function decodeRot47(input) {
  let text = "";
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c >= 33 && c <= 126) {
      text += String.fromCharCode(33 + ((c - 33 + 47) % 94));
    } else {
      text += input[i];
    }
  }
  return { ok: true, text };
}

function decodeUrl(input) {
  try {
    return { ok: true, text: decodeURIComponent(input.replace(/\+/g, " ")) };
  } catch (_err) {
    return { ok: false, text: "not valid URL encoding" };
  }
}

function decodeReverse(input) {
  return { ok: true, text: Array.from(input).reverse().join("") };
}

function decodeAtbash(input) {
  const text = input.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(base + 25 - (ch.charCodeAt(0) - base));
  });
  return { ok: true, text };
}

const MORSE_TABLE = {
  ".-": "A",
  "-...": "B",
  "-.-.": "C",
  "-..": "D",
  ".": "E",
  "..-.": "F",
  "--.": "G",
  "....": "H",
  "..": "I",
  ".---": "J",
  "-.-": "K",
  ".-..": "L",
  "--": "M",
  "-.": "N",
  "---": "O",
  ".--.": "P",
  "--.-": "Q",
  ".-.": "R",
  "...": "S",
  "-": "T",
  "..-": "U",
  "...-": "V",
  ".--": "W",
  "-..-": "X",
  "-.--": "Y",
  "--..": "Z",
  "-----": "0",
  ".----": "1",
  "..---": "2",
  "...--": "3",
  "....-": "4",
  ".....": "5",
  "-....": "6",
  "--...": "7",
  "---..": "8",
  "----.": "9",
  ".-.-.-": ".",
  "--..--": ",",
  "..--..": "?",
  "-.-.--": "!",
  "-....-": "-",
  "-..-.": "/",
  ".--.-.": "@",
  "-.--.": "(",
  "-.--.-": ")",
};

function decodeMorse(input) {
  const normalized = input
    .trim()
    .replace(/[•·‧∙]/g, ".")
    .replace(/[_–—−]/g, "-")
    .replace(/\\/g, "/")
    .replace(/\|/g, "/");
  if (!/[.\-]/.test(normalized)) {
    return { ok: false, text: "not valid Morse (need . and -)" };
  }

  // Word breaks: / or 2+ spaces; letter breaks: single space
  const words = normalized.split(/\s*\/\s*|\s{2,}/);
  const out = [];
  let unknown = 0;
  for (let w = 0; w < words.length; w++) {
    const letters = words[w].trim().split(/\s+/).filter(Boolean);
    if (!letters.length) continue;
    let word = "";
    for (const token of letters) {
      const key = token.replace(/[^.\-]/g, "");
      if (!key) continue;
      const ch = MORSE_TABLE[key];
      if (ch == null) {
        unknown += 1;
        word += "?";
      } else {
        word += ch;
      }
    }
    if (word) out.push(word);
  }
  if (!out.length) {
    return { ok: false, text: "not valid Morse" };
  }
  const text = out.join(" ");
  if (unknown > 0 && unknown >= Math.ceil(text.replace(/\s/g, "").length / 2)) {
    return { ok: false, text: "not valid Morse (too many unknown codes)" };
  }
  return { ok: true, text };
}

function looksLikeMorse(text) {
  const t = String(text || "").trim();
  if (t.length < 4) return false;
  if (!/[.\-•·_–—−]/.test(t)) return false;
  const compact = t.replace(/[\s/|]+/g, "");
  const morseChars = (compact.match(/[.\-•·_–—−]/g) || []).length;
  return morseChars >= 4 && morseChars / Math.max(compact.length, 1) >= 0.75;
}

function sendMorseToCipher(morseText, opts) {
  const text = String(morseText || "").trim();
  if (!text) return;
  if (els.cipherInput) {
    els.cipherInput.value = text;
    renderCiphers(text);
  }
  browser.runtime.sendMessage({ type: MSG.CIPHER_INPUT, text }).catch(() => {});
  focusCipherPanel({ focusInput: !(opts && opts.auto) });
  focusCipherCard("morse");
}

/** Map 1–26 → A–Z; otherwise null. Shared by Cipher and Notes Analyze. */
function a1z26LetterFromNumber(n) {
  const num = Number(n);
  if (!Number.isInteger(num) || num < 1 || num > 26) return null;
  return String.fromCharCode(64 + num);
}

function decodeA1Z26(input) {
  const raw = String(input || "").trim();
  if (!raw) return { ok: false, text: "not valid A1Z26" };

  const letterish = (raw.match(/[a-zA-Z]/g) || []).length;
  const digitish = (raw.match(/\d/g) || []).length;

  // Encode letters → numbers when mostly letters
  if (letterish >= 3 && letterish >= digitish * 2) {
    const parts = [];
    for (const ch of raw) {
      if (/[a-zA-Z]/.test(ch)) {
        parts.push(String(ch.toUpperCase().charCodeAt(0) - 64));
      } else if (/\s/.test(ch)) {
        if (parts.length && parts[parts.length - 1] !== "/") parts.push("/");
      }
    }
    const text = parts.join(" ").replace(/\s*\/\s*/g, " / ").trim();
    if (!text || !/\d/.test(text)) return { ok: false, text: "not valid A1Z26" };
    return { ok: true, text, label: "A1Z26 encode" };
  }

  // Decode numbers → letters
  const tokens = raw.split(/[\s,;|./\\-]+/).filter(Boolean);
  if (tokens.length < 1 || !tokens.every((t) => /^(?:[1-9]|1\d|2[0-6])$/.test(t))) {
    return { ok: false, text: "not valid A1Z26 (need 1–26 codes or letters)" };
  }
  let text = "";
  for (const t of tokens) {
    const letter = a1z26LetterFromNumber(Number(t));
    if (!letter) return { ok: false, text: "not valid A1Z26 (need 1–26 codes or letters)" };
    text += letter;
  }
  return { ok: true, text, label: "A1Z26 decode" };
}

const BACON_TABLE = {
  aaaaa: "A",
  aaaab: "B",
  aaaba: "C",
  aaabb: "D",
  aabaa: "E",
  aabab: "F",
  aabba: "G",
  aabbb: "H",
  abaaa: "I",
  abaab: "J",
  ababa: "K",
  ababb: "L",
  abbaa: "M",
  abbab: "N",
  abbba: "O",
  abbbb: "P",
  baaaa: "Q",
  baaab: "R",
  baaba: "S",
  baabb: "T",
  babaa: "U",
  babab: "V",
  babba: "W",
  babbb: "X",
  bbaaa: "Y",
  bbaab: "Z",
};

function baconBitsFromInput(input) {
  const s = String(input || "");
  // Explicit A/B or 0/1 stream
  const explicit = s.replace(/[^abAB01]/g, "");
  if (explicit.length >= 5) {
    return explicit
      .toLowerCase()
      .replace(/0/g, "a")
      .replace(/1/g, "b")
      .replace(/[^ab]/g, "");
  }
  // Alternating case → A=lowercase, B=uppercase (common hunt convention)
  const letters = (s.match(/[a-zA-Z]/g) || []).join("");
  if (letters.length >= 5 && looksLikeBaconCase(s)) {
    let bits = "";
    for (const ch of letters) {
      bits += ch === ch.toUpperCase() ? "b" : "a";
    }
    return bits;
  }
  return "";
}

function decodeBacon(input) {
  const bits = baconBitsFromInput(input);
  if (bits.length < 5 || bits.length % 5 !== 0) {
    return { ok: false, text: "not valid Bacon (need A/B, 0/1, or case ×5)" };
  }
  let text = "";
  let unknown = 0;
  for (let i = 0; i < bits.length; i += 5) {
    const group = bits.slice(i, i + 5);
    const ch = BACON_TABLE[group];
    if (!ch) {
      unknown++;
      text += "?";
    } else {
      text += ch;
    }
  }
  if (!text || unknown > text.length / 2) {
    return { ok: false, text: "not valid Bacon" };
  }
  return { ok: true, text };
}

const T9_MAP = {
  2: "ABC",
  3: "DEF",
  4: "GHI",
  5: "JKL",
  6: "MNO",
  7: "PQRS",
  8: "TUV",
  9: "WXYZ",
};

function decodeT9(input) {
  const tokens = String(input || "")
    .trim()
    .split(/[\s,;|]+/)
    .filter(Boolean);
  if (tokens.length < 1 || !tokens.every((t) => /^([2-9])\1{0,3}$/.test(t))) {
    return { ok: false, text: "not valid T9 (e.g. 44 33 555 555 666)" };
  }
  let text = "";
  for (const tok of tokens) {
    const digit = tok[0];
    const letters = T9_MAP[digit];
    if (!letters) return { ok: false, text: "not valid T9" };
    const idx = Math.min(tok.length, letters.length) - 1;
    text += letters[idx];
  }
  return { ok: true, text };
}

const CAESAR_CRIBS = [
  "THE",
  "AND",
  "FLAG",
  "NEXT",
  "FIND",
  "KEY",
  "FOR",
  "YOU",
  "ARE",
  "THIS",
  "THAT",
  "WITH",
  "FROM",
  "HAVE",
  "WHAT",
  "WHEN",
  "WHERE",
  "YOUR",
  "CODE",
  "PASS",
  "HUNT",
  "CTF",
];

function caesarShift(text, shift) {
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function scoreEnglishish(text) {
  const upper = String(text || "").toUpperCase();
  if (!/[A-Z]{3,}/.test(upper)) return 0;
  let score = 0;
  for (const crib of CAESAR_CRIBS) {
    if (upper.includes(crib)) score += crib.length >= 4 ? 4 : 2;
  }
  // Common letter bonus
  const letters = (upper.match(/[A-Z]/g) || []).join("");
  if (!letters.length) return score;
  const freq = { E: 0, T: 0, A: 0, O: 0, I: 0, N: 0, S: 0, H: 0, R: 0 };
  for (const ch of letters) {
    if (freq[ch] != null) freq[ch]++;
  }
  const n = letters.length;
  score += (freq.E + freq.T + freq.A + freq.O + freq.I + freq.N) / n * 6;
  return score;
}

function decodeCaesarCrib(input) {
  const raw = String(input || "");
  const alpha = (raw.match(/[a-zA-Z]/g) || []).length;
  if (alpha < 4) {
    return { ok: false, text: "need more letters for Caesar crib" };
  }
  const hits = [];
  for (let shift = 1; shift <= 25; shift++) {
    const text = caesarShift(raw, shift);
    const score = scoreEnglishish(text);
    if (score > 0) hits.push({ shift, text, score });
  }
  hits.sort((a, b) => b.score - a.score || a.shift - b.shift);
  const best = hits.slice(0, 5).filter((h) => h.score >= hits[0].score * 0.4 || h.score >= 3);
  if (!best.length || best[0].score < 2) {
    return { ok: false, text: "no strong Caesar crib (try ROT13 card)" };
  }
  const lines = best.map(
    (h) => "ROT" + h.shift + " (score " + h.score.toFixed(1) + "): " + h.text
  );
  return {
    ok: true,
    score: best[0].score,
    text: lines.join("\n"),
    label: "Caesar crib · best " + best.length,
  };
}

// ---------------------------------------------------------------------------
// Backlink identifier UI
// ---------------------------------------------------------------------------

function renderHuntBase(huntBase) {
  const hb = huntBase && huntBase.host ? huntBase : null;
  const pinned = Boolean(hb);
  const pathCount = pinned
    ? Array.isArray(hb.paths) && hb.paths.length
      ? hb.paths.length
      : 1
    : 0;
  if (els.btnPinHunt) {
    els.btnPinHunt.setAttribute("aria-pressed", pinned ? "true" : "false");
    els.btnPinHunt.textContent = pinned ? "Pinned" : "Pin";
    els.btnPinHunt.title = pinned
      ? "Add this tab’s path to hunt base (same host accumulates; other host replaces)"
      : "Pin active tab as hunt base (stores origin + path)";
  }
  if (!els.huntBaseLabel) return;
  if (pinned) {
    const bases = (Array.isArray(hb.paths) ? hb.paths : [""]).map((p) =>
      p ? hb.host + p : hb.host
    );
    els.huntBaseLabel.textContent =
      pathCount > 1 ? hb.host + " · " + pathCount + " bases" : hb.host;
    els.huntBaseLabel.title = bases.join("\n");
    els.huntBaseLabel.classList.add("is-pinned");
  } else {
    els.huntBaseLabel.textContent = "No hunt base";
    els.huntBaseLabel.title = "";
    els.huntBaseLabel.classList.remove("is-pinned");
  }
}

// ---------------------------------------------------------------------------
// Panel order (drag handle + browser.storage.local)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Panel / group order & open state
// ---------------------------------------------------------------------------

function normalizeGroupOrder(order) {
  const known = new Set(DEFAULT_GROUP_ORDER);
  const seen = new Set();
  const next = [];
  if (Array.isArray(order)) {
    for (const id of order) {
      if (typeof id !== "string" || !known.has(id) || seen.has(id)) continue;
      seen.add(id);
      next.push(id);
    }
  }
  for (const id of DEFAULT_GROUP_ORDER) {
    if (!seen.has(id)) next.push(id);
  }
  return next;
}

/**
 * Migrate legacy flat panel-id order → group order (first-seen group wins),
 * or accept already-migrated group ids.
 */
function migrateStoredOrder(order) {
  if (!Array.isArray(order) || !order.length) return DEFAULT_GROUP_ORDER.slice();
  const looksLikeGroups = order.some(
    (id) => typeof id === "string" && id.indexOf("group-") === 0
  );
  if (looksLikeGroups) return normalizeGroupOrder(order);

  const seen = new Set();
  const next = [];
  for (const id of order) {
    if (typeof id !== "string") continue;
    const gid = PANEL_TO_GROUP[id];
    if (!gid || seen.has(gid)) continue;
    seen.add(gid);
    next.push(gid);
  }
  return normalizeGroupOrder(next);
}

function applyGroupOrder(order) {
  const stack = els.panelStack;
  if (!stack) return;
  const ids = normalizeGroupOrder(order);
  for (const id of ids) {
    const group = document.getElementById(id);
    if (group && group.parentElement === stack) stack.appendChild(group);
  }
}

async function loadPanelOrder() {
  try {
    const bag = await browser.storage.local.get(PANEL_ORDER_KEY);
    const migrated = migrateStoredOrder(bag[PANEL_ORDER_KEY]);
    applyGroupOrder(migrated);
    // Persist migrated group ids so old panel-id arrays are rewritten once.
    const raw = bag[PANEL_ORDER_KEY];
    const needsWrite =
      !Array.isArray(raw) ||
      raw.length !== migrated.length ||
      raw.some((id, i) => id !== migrated[i]);
    if (needsWrite) {
      await browser.storage.local.set({ [PANEL_ORDER_KEY]: migrated });
    }
  } catch (_err) {
    applyGroupOrder(DEFAULT_GROUP_ORDER);
  }
}

async function loadPanelOpenState() {
  let stored = null;
  try {
    const bag = await browser.storage.local.get(PANEL_OPEN_KEY);
    if (bag[PANEL_OPEN_KEY] && typeof bag[PANEL_OPEN_KEY] === "object") {
      stored = bag[PANEL_OPEN_KEY];
    }
  } catch (_err) {
    stored = null;
  }
  const source = stored || {};

  for (const id of DEFAULT_GROUP_ORDER) {
    const group = document.getElementById(id);
    if (!group) continue;
    const open =
      typeof source[id] === "boolean"
        ? source[id]
        : Boolean(DEFAULT_GROUP_OPEN[id]);
    group.open = open;
  }

  for (const id of DEFAULT_PANEL_ORDER) {
    const panel = document.getElementById(id);
    if (!panel) continue;
    const open =
      typeof source[id] === "boolean"
        ? source[id]
        : Boolean(DEFAULT_PANEL_OPEN[id]);
    panel.open = open;
  }

  if (!stored) {
    try {
      await browser.storage.local.set({
        [PANEL_OPEN_KEY]: { ...DEFAULT_GROUP_OPEN, ...DEFAULT_PANEL_OPEN },
      });
    } catch (_err2) {
      /* ignore */
    }
  }
}

function scheduleSavePanelOpenState() {
  const state = {};
  for (const id of DEFAULT_GROUP_ORDER) {
    const group = document.getElementById(id);
    if (group) state[id] = Boolean(group.open);
  }
  for (const id of DEFAULT_PANEL_ORDER) {
    const panel = document.getElementById(id);
    if (panel) state[id] = Boolean(panel.open);
  }
  browser.storage.local.set({ [PANEL_OPEN_KEY]: state }).catch(() => {});
}

function initPanelOpenPersistence() {
  for (const id of DEFAULT_GROUP_ORDER) {
    const group = document.getElementById(id);
    if (!group) continue;
    group.addEventListener("toggle", () => {
      scheduleSavePanelOpenState();
    });
  }
  for (const id of DEFAULT_PANEL_ORDER) {
    const panel = document.getElementById(id);
    if (!panel) continue;
    panel.addEventListener("toggle", () => {
      scheduleSavePanelOpenState();
    });
  }
}

function initHelpTips() {
  document.querySelectorAll(".help-tip").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
    });
    btn.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
    });
  });
}

async function savePanelOrder() {
  const stack = els.panelStack;
  if (!stack) return;
  const order = Array.from(stack.children)
    .filter((el) => el.classList && el.classList.contains("panel-group"))
    .map((el) => el.id)
    .filter(Boolean);
  try {
    await browser.storage.local.set({ [PANEL_ORDER_KEY]: normalizeGroupOrder(order) });
  } catch (_err) {
    /* ignore */
  }
}

function initPanelReorder() {
  const stack = els.panelStack;
  if (!stack) return;

  /** @type {null | {
   *   panelId: string,
   *   pointerId: number,
   *   startY: number,
   *   dragging: boolean,
   *   targetId: string | null,
   *   place: "before" | "after" | null,
   *   handle: Element
   * }} */
  let active = null;
  const DRAG_THRESHOLD_PX = 5;

  const groups = () =>
    Array.from(stack.children).filter(
      (el) => el.classList && el.classList.contains("panel-group")
    );

  function clearDropMarks() {
    groups().forEach((el) => {
      el.classList.remove("drop-before", "drop-after", "drag-over");
    });
  }

  function removeGhost() {
    const ghost = document.getElementById("panel-drag-ghost");
    if (ghost) ghost.remove();
  }

  function showGhost(source, clientX, clientY) {
    let ghost = document.getElementById("panel-drag-ghost");
    if (!ghost) {
      ghost = document.createElement("div");
      ghost.id = "panel-drag-ghost";
      ghost.className = "panel-drag-ghost";
      ghost.setAttribute("aria-hidden", "true");
      document.body.appendChild(ghost);
    }
    const labelEl = source.querySelector(":scope > summary .summary-label");
    const label = (labelEl && labelEl.textContent ? labelEl.textContent : source.id || "")
      .replace(/\s+/g, " ")
      .trim();
    ghost.textContent = label || "Group";
    ghost.style.transform = `translate(${Math.round(clientX + 12)}px, ${Math.round(clientY + 10)}px)`;
  }

  function moveGhost(clientX, clientY) {
    const ghost = document.getElementById("panel-drag-ghost");
    if (!ghost) return;
    ghost.style.transform = `translate(${Math.round(clientX + 12)}px, ${Math.round(clientY + 10)}px)`;
  }

  function flashMoved(panel) {
    if (!panel) return;
    panel.classList.remove("just-moved");
    void panel.offsetWidth;
    panel.classList.add("just-moved");
    window.setTimeout(() => {
      panel.classList.remove("just-moved");
    }, 450);
  }

  function clearDragState() {
    clearDropMarks();
    groups().forEach((el) => el.classList.remove("is-dragging"));
    document.documentElement.classList.remove("is-panel-reordering");
    removeGhost();
  }

  function hitTest(clientY, excludeId) {
    const list = groups().filter((p) => p.id && p.id !== excludeId);
    if (!list.length) return null;

    for (const panel of list) {
      const rect = panel.getBoundingClientRect();
      if (clientY >= rect.top && clientY <= rect.bottom) {
        const before = clientY < rect.top + rect.height / 2;
        return { panel, place: before ? "before" : "after" };
      }
    }

    const firstRect = list[0].getBoundingClientRect();
    if (clientY < firstRect.top) return { panel: list[0], place: "before" };
    return { panel: list[list.length - 1], place: "after" };
  }

  function onPointerMove(event) {
    if (!active || event.pointerId !== active.pointerId) return;

    const dy = Math.abs(event.clientY - active.startY);
    if (!active.dragging) {
      if (dy < DRAG_THRESHOLD_PX) return;
      active.dragging = true;
      const source = document.getElementById(active.panelId);
      if (source) {
        source.classList.add("is-dragging");
        showGhost(source, event.clientX, event.clientY);
      }
      document.documentElement.classList.add("is-panel-reordering");
    } else {
      moveGhost(event.clientX, event.clientY);
    }

    event.preventDefault();
    clearDropMarks();
    const hit = hitTest(event.clientY, active.panelId);
    if (!hit) {
      active.targetId = null;
      active.place = null;
      return;
    }
    active.targetId = hit.panel.id;
    active.place = hit.place;
    hit.panel.classList.add(hit.place === "before" ? "drop-before" : "drop-after");
  }

  function finishPointer(event) {
    if (!active || event.pointerId !== active.pointerId) return;

    const session = active;
    active = null;

    document.removeEventListener("pointermove", onPointerMove, true);
    document.removeEventListener("pointerup", finishPointer, true);
    document.removeEventListener("pointercancel", finishPointer, true);

    try {
      session.handle.releasePointerCapture(session.pointerId);
    } catch (_err) {
      /* ignore */
    }

    let movedPanel = null;
    if (session.dragging && session.targetId && session.place) {
      const source = document.getElementById(session.panelId);
      const target = document.getElementById(session.targetId);
      if (source && target && source !== target && source.parentElement === stack) {
        if (session.place === "before") stack.insertBefore(source, target);
        else stack.insertBefore(source, target.nextSibling);
        savePanelOrder();
        movedPanel = source;
      }
    }

    clearDragState();
    if (movedPanel) flashMoved(movedPanel);
  }

  groups().forEach((panel) => {
    const summary = panel.firstElementChild;
    if (!summary || summary.tagName !== "SUMMARY") return;
    const handle = summary.querySelector(".drag-handle");
    if (!handle) return;

    handle.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
    });

    handle.addEventListener("pointerdown", (event) => {
      if (event.button != null && event.button !== 0) return;
      if (event.pointerType === "mouse" && event.button !== 0) return;
      if (!panel.id) return;

      event.preventDefault();
      event.stopPropagation();

      active = {
        panelId: panel.id,
        pointerId: event.pointerId,
        startY: event.clientY,
        dragging: false,
        targetId: null,
        place: null,
        handle,
      };

      try {
        handle.setPointerCapture(event.pointerId);
      } catch (_err) {
        /* ignore */
      }

      document.addEventListener("pointermove", onPointerMove, true);
      document.addEventListener("pointerup", finishPointer, true);
      document.addEventListener("pointercancel", finishPointer, true);
    });
  });
}

function focusPanel(panelId) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const group = panel.closest(".panel-group");
  if (group) group.open = true;
  panel.open = true;
  scheduleSavePanelOpenState();
  try {
    panel.scrollIntoView({ block: "nearest", behavior: "smooth" });
  } catch (_err) {
    panel.scrollIntoView();
  }
}

let ingestToastTimer = 0;
/** Avoid duplicate toast/hex when notify retries race GET_STATE cold-start. */
let lastConsumedPendingAt = 0;
let lastIngestToastText = "";
let lastIngestToastAt = 0;

function showIngestToast(text) {
  if (!els.ingestToast) return;
  const msg = String(text || "").trim();
  if (!msg) return;
  const now = Date.now();
  if (msg === lastIngestToastText && now - lastIngestToastAt < 2500) return;
  lastIngestToastText = msg;
  lastIngestToastAt = now;
  els.ingestToast.hidden = false;
  els.ingestToast.textContent = msg;
  clearTimeout(ingestToastTimer);
  ingestToastTimer = setTimeout(() => {
    if (!els.ingestToast) return;
    els.ingestToast.hidden = true;
    els.ingestToast.textContent = "";
  }, 4500);
}

function clearPendingIngest(which) {
  browser.runtime
    .sendMessage({ type: MSG.CLEAR_PENDING_INGEST, which: which || "both" })
    .catch(() => {});
}

/** @returns {object|null} pending if not yet consumed */
function takePendingIngest(pending) {
  if (!pending || pending.at == null) return pending || null;
  if (pending.at === lastConsumedPendingAt) return null;
  lastConsumedPendingAt = pending.at;
  return pending;
}

function appendNoteLine(line) {
  const text = String(line || "").trim();
  if (!text || !els.notesInput) return;
  const cur = els.notesInput.value || "";
  els.notesInput.value = cur ? cur + "\n" + text : text;
  persistNotesSoon();
}

async function loadAutoIngestToggle() {
  if (!els.autoIngestDownloads) return;
  try {
    const bag = await browser.storage.local.get(AUTO_INGEST_KEY);
    els.autoIngestDownloads.checked = bag[AUTO_INGEST_KEY] !== false;
  } catch (_err) {
    els.autoIngestDownloads.checked = true;
  }
}

if (els.autoIngestDownloads) {
  els.autoIngestDownloads.addEventListener("change", () => {
    browser.storage.local
      .set({ [AUTO_INGEST_KEY]: Boolean(els.autoIngestDownloads.checked) })
      .catch(() => {});
  });
}

function focusProbePanel() {
  focusPanel("panel-probe");
}

function focusImagePanel() {
  focusPanel("panel-image");
}

function focusArchivePanel() {
  focusPanel("panel-archive");
}

function focusAudioPanel() {
  focusPanel("panel-audio");
}

function audioDeepToolUrls() {
  return {
    audacity: "https://wiki.audacityteam.org/wiki/Spectrogram_view",
    spectrum: "https://academo.org/demos/spectrum-analyzer/",
    morse: "https://www.dcode.fr/morse-code",
    sstv: "https://www.k0pir.us/sstv/",
  };
}

function setAudioStatus(text) {
  if (els.audioStatus) els.audioStatus.textContent = text || "";
}

function clearAudioAnalyzePanel() {
  if (els.audioAnalyzePanel) els.audioAnalyzePanel.hidden = true;
  if (els.audioId3Status) els.audioId3Status.textContent = "";
  if (els.audioId3List) els.audioId3List.replaceChildren();
  if (els.audioStrings) els.audioStrings.replaceChildren();
  if (els.audioMorsePanel) els.audioMorsePanel.hidden = true;
  if (els.audioMorseList) els.audioMorseList.replaceChildren();
}

function mimeFromAudioFilename(name) {
  const n = String(name || "").toLowerCase();
  if (n.endsWith(".mp3")) return "audio/mpeg";
  if (n.endsWith(".wav")) return "audio/wav";
  if (n.endsWith(".ogg")) return "audio/ogg";
  if (n.endsWith(".m4a") || n.endsWith(".mp4")) return "audio/mp4";
  if (n.endsWith(".flac")) return "audio/flac";
  if (n.endsWith(".aac")) return "audio/aac";
  if (n.endsWith(".webm")) return "audio/webm";
  if (n.endsWith(".opus")) return "audio/opus";
  // Prefer a playable audio MIME over octet-stream so <audio> can decode.
  return "audio/mpeg";
}

function resolveAudioMime(fileOrType, filename) {
  const raw =
    typeof fileOrType === "string"
      ? fileOrType
      : fileOrType && fileOrType.type
        ? fileOrType.type
        : "";
  if (raw && raw !== "application/octet-stream" && /^audio\//i.test(raw)) {
    return raw;
  }
  if (raw && /^video\/webm\b/i.test(raw)) return "audio/webm";
  return mimeFromAudioFilename(filename || (fileOrType && fileOrType.name) || "");
}

function isAudioAssetPresent(asset) {
  return Boolean(asset && (asset.url || asset.filename || asset.needsDrop));
}

function hasSidebarLocalAudio() {
  if (audioLocalBuffer || audioPreviewObjectUrl) return true;
  if (!currentAudio) return false;
  if (currentAudio.local) return true;
  if (!currentAudio.url && currentAudio.filename) return true;
  if (currentAudio.url && !/^https?:\/\//i.test(currentAudio.url)) return true;
  return false;
}

function audioPreviewKeyForAsset(asset) {
  if (!asset) return "";
  if (asset.url && /^https?:\/\//i.test(asset.url)) return asset.url;
  if (asset.filename) return "local:" + asset.filename;
  if (asset.local) return "local:" + (asset.filename || "audio");
  return "";
}

function revokeAudioPreviewUrl() {
  if (audioPreviewObjectUrl) {
    try {
      URL.revokeObjectURL(audioPreviewObjectUrl);
    } catch (_err) {
      /* ignore */
    }
    audioPreviewObjectUrl = null;
  }
  audioPreviewSourceKey = null;
}

function clearAudioLocalBytes() {
  audioLocalBuffer = null;
  audioLocalFilename = "";
}

function bindAudioPreviewSrc(url) {
  if (!els.audioPreview || !url) return;
  els.audioPreview.hidden = false;
  const attr = els.audioPreview.getAttribute("src") || "";
  if (attr !== url) {
    els.audioPreview.src = url;
    try {
      els.audioPreview.load();
    } catch (_err) {
      /* ignore */
    }
  }
}

function updateAudioPreview(url) {
  if (!els.audioPreview) return;
  if (!url) {
    revokeAudioPreviewUrl();
    els.audioPreview.hidden = true;
    els.audioPreview.removeAttribute("src");
    try {
      els.audioPreview.load();
    } catch (_err) {
      /* ignore */
    }
    return;
  }
  const playable = /^https?:\/\//i.test(url) || /^blob:/i.test(url);
  if (!playable) {
    revokeAudioPreviewUrl();
    els.audioPreview.hidden = true;
    els.audioPreview.removeAttribute("src");
    return;
  }
  // Same blob already bound — keep playback position / avoid flicker on pushState.
  if (audioPreviewObjectUrl && url === audioPreviewObjectUrl) {
    bindAudioPreviewSrc(url);
    return;
  }
  if (/^https?:\/\//i.test(url) && els.audioPreview.src === url && !audioPreviewObjectUrl) {
    els.audioPreview.hidden = false;
    return;
  }
  if (audioPreviewObjectUrl && url !== audioPreviewObjectUrl) {
    revokeAudioPreviewUrl();
  }
  bindAudioPreviewSrc(url);
}

/**
 * Bind a Blob/File to the <audio> preview via object URL.
 * @param {Blob} blob
 * @param {string} sourceKey
 */
function setAudioPreviewFromBlob(blob, sourceKey) {
  if (!els.audioPreview || !blob) return;
  const key = sourceKey || "";
  if (audioPreviewObjectUrl && audioPreviewSourceKey === key) {
    els.audioPreview.hidden = false;
    if (!els.audioPreview.getAttribute("src") && audioPreviewObjectUrl) {
      bindAudioPreviewSrc(audioPreviewObjectUrl);
    }
    return;
  }
  revokeAudioPreviewUrl();
  audioPreviewObjectUrl = URL.createObjectURL(blob);
  audioPreviewSourceKey = key;
  bindAudioPreviewSrc(audioPreviewObjectUrl);
}

/** Re-attach preview after Strings/ID3 if src was cleared mid-analyze. */
function rebindAudioPreviewAfterAnalyze() {
  if (!currentAudio || !els.audioPreview) return;
  const wantKey = audioPreviewKeyForAsset(currentAudio);
  if (audioPreviewObjectUrl && audioPreviewSourceKey === wantKey) {
    bindAudioPreviewSrc(audioPreviewObjectUrl);
    return;
  }
  if (audioLocalBuffer && wantKey && wantKey.indexOf("local:") === 0) {
    const mime = resolveAudioMime("", currentAudio.filename || audioLocalFilename);
    try {
      setAudioPreviewFromBlob(new Blob([audioLocalBuffer], { type: mime }), wantKey);
    } catch (_err) {
      setAudioStatus("preview unavailable");
    }
    return;
  }
  if (currentAudio.url && /^https?:\/\//i.test(currentAudio.url)) {
    if (!els.audioPreview.src) updateAudioPreview(currentAudio.url);
    ensureHttpAudioPreview(currentAudio.url);
  }
}

/** Fetch http(s) audio into a blob URL when direct media src is flaky. */
async function ensureHttpAudioPreview(url) {
  if (!url || !/^https?:\/\//i.test(url)) return;
  if (audioPreviewSourceKey === url && audioPreviewObjectUrl) return;
  try {
    const res = await fetch(url);
    if (!res.ok) return;
    const blob = await res.blob();
    if (!currentAudio || currentAudio.url !== url) return;
    const typed =
      blob.type && blob.type !== "application/octet-stream"
        ? blob
        : new Blob([blob], { type: resolveAudioMime(blob.type, url) });
    setAudioPreviewFromBlob(typed, url);
  } catch (_err) {
    /* keep direct http(s) src if already set */
  }
}

async function persistAudioAsset(asset) {
  if (!asset) return;
  try {
    await browser.runtime.sendMessage({ type: MSG.AUDIO_ASSET, audioAsset: asset });
  } catch (_err) {
    /* ignore */
  }
}

function renderAudioAsset(audioAsset, options) {
  const shouldFocus = !options || options.focus !== false;
  const opts = options || {};
  currentAudio = isAudioAssetPresent(audioAsset) ? audioAsset : null;
  if (!els.audioCard || !els.audioEmpty || !els.badgeAudio) return;

  if (!currentAudio) {
    els.badgeAudio.textContent = "0";
    els.audioEmpty.hidden = false;
    els.audioCard.hidden = true;
    if (els.audioUrl) {
      els.audioUrl.textContent = "";
      els.audioUrl.title = "";
    }
    clearAudioAnalyzePanel();
    clearAudioLocalBytes();
    updateAudioPreview("");
    setAudioStatus("");
    return;
  }

  if (shouldFocus) focusAudioPanel();
  els.badgeAudio.textContent = "1";
  els.audioEmpty.hidden = true;
  els.audioCard.hidden = false;

  const label =
    currentAudio.url ||
    currentAudio.filename ||
    (currentAudio.needsDrop ? "(drop file to analyze)" : "");
  if (els.audioUrl) {
    els.audioUrl.textContent = label;
    els.audioUrl.title = currentAudio.url || currentAudio.filename || "";
  }

  const wantKey = audioPreviewKeyForAsset(currentAudio);
  if (opts.previewUrl && /^blob:/i.test(opts.previewUrl)) {
    // Caller already created the object URL (local drop).
    if (audioPreviewObjectUrl && audioPreviewObjectUrl !== opts.previewUrl) {
      revokeAudioPreviewUrl();
    }
    audioPreviewObjectUrl = opts.previewUrl;
    audioPreviewSourceKey = wantKey;
    updateAudioPreview(opts.previewUrl);
  } else if (wantKey && audioPreviewObjectUrl && audioPreviewSourceKey === wantKey) {
    updateAudioPreview(audioPreviewObjectUrl);
  } else if (currentAudio.url && /^https?:\/\//i.test(currentAudio.url)) {
    // Captured URL replaces any prior local drop bytes.
    if (audioLocalBuffer) clearAudioLocalBytes();
    updateAudioPreview(currentAudio.url);
    ensureHttpAudioPreview(currentAudio.url);
  } else if (audioLocalBuffer && wantKey && wantKey.indexOf("local:") === 0) {
    const mime = resolveAudioMime("", currentAudio.filename || audioLocalFilename);
    try {
      setAudioPreviewFromBlob(new Blob([audioLocalBuffer], { type: mime }), wantKey);
    } catch (_err) {
      setAudioStatus("preview unavailable");
    }
  } else if (hasSidebarLocalAudio() && audioPreviewObjectUrl) {
    // Keep live blob even if store metadata is thin.
    updateAudioPreview(audioPreviewObjectUrl);
  } else {
    // Local/needsDrop metadata without bytes (e.g. after reload) — no playable src.
    updateAudioPreview("");
  }

  if (currentAudio.needsDrop) {
    setAudioStatus(
      "Download URL not re-fetchable — drop the file below or use a public http(s) URL"
    );
  } else if (
    !currentAudio.url &&
    currentAudio.filename &&
    !audioPreviewObjectUrl &&
    !audioLocalBuffer
  ) {
    setAudioStatus("Re-drop the file to play and re-analyze (preview bytes are session-only).");
  } else if (!opts.keepStatus) {
    // Keep Strings/ID3 status line across pushState re-syncs.
    if (!(els.audioAnalyzePanel && !els.audioAnalyzePanel.hidden)) {
      setAudioStatus("");
    }
  }
}

function renderAudioAnalyzeResult(result) {
  if (!els.audioAnalyzePanel) return;
  els.audioAnalyzePanel.hidden = false;

  const id3 = (result && result.id3) || [];
  if (els.audioId3Status) {
    els.audioId3Status.textContent = id3.length
      ? id3.length + " ID3 field(s)"
      : "No MP3 ID3 tags in file head (or not MP3).";
  }
  if (els.audioId3List) {
    els.audioId3List.replaceChildren();
    for (const f of id3) {
      const li = document.createElement("li");
      li.className = "asset-item";
      const body = document.createElement("div");
      body.className = "preview mono";
      body.textContent = (f.label || f.id) + ": " + (f.text || "");
      body.title = f.text || "";
      li.appendChild(body);
      const meta = document.createElement("div");
      meta.className = "meta-line";
      meta.appendChild(copyButton(f.text || ""));
      meta.appendChild(handoffButton("Cipher", () => sendTextToCipher(f.text || "")));
      meta.appendChild(
        handoffButton("Probe", () => {
          setProbeMode("id");
          els.probeInput.value = String(f.text || "").trim().slice(0, 200);
          focusProbePanel();
          startProbe();
        })
      );
      if (looksLikeMorse(f.text)) {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "decode-chip is-morse";
        const decoded = decodeMorse(f.text);
        chip.textContent = decoded.ok
          ? "Morse → " + decoded.text
          : "Morse decode";
        chip.title = "Send to Cipher Morse decoder";
        chip.addEventListener("click", () => sendMorseToCipher(f.text, { auto: true }));
        li.appendChild(chip);
      }
      li.appendChild(meta);
      els.audioId3List.appendChild(li);
    }
  }

  const strings = (result && result.strings) || [];
  if (els.audioStrings) {
    els.audioStrings.replaceChildren();
    if (!strings.length) {
      const li = document.createElement("li");
      li.className = "asset-item";
      li.textContent = "No printable strings (≥4 chars) in scan window.";
      els.audioStrings.appendChild(li);
    } else {
      for (const s of strings) {
        const li = document.createElement("li");
        li.className = "asset-item";
        const body = document.createElement("div");
        body.className = "preview mono";
        body.textContent = s.text.length > 160 ? s.text.slice(0, 160) + "…" : s.text;
        body.title = s.text;
        li.appendChild(body);
        const meta = document.createElement("div");
        meta.className = "meta-line";
        const off = document.createElement("span");
        off.textContent =
          "@0x" + Number(s.offset || 0).toString(16) + " · " + (s.len || s.text.length) + " chars";
        meta.appendChild(off);
        meta.appendChild(copyButton(s.text));
        meta.appendChild(handoffButton("Cipher", () => sendTextToCipher(s.text)));
        meta.appendChild(
          handoffButton("Probe", () => {
            setProbeMode("id");
            els.probeInput.value = s.text.trim().slice(0, 200);
            focusProbePanel();
            startProbe();
          })
        );
        if (looksLikeMorse(s.text)) {
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "decode-chip is-morse";
          const decoded = decodeMorse(s.text);
          chip.textContent = decoded.ok ? "Morse → " + decoded.text : "Morse decode";
          chip.addEventListener("click", () => sendMorseToCipher(s.text, { auto: true }));
          li.appendChild(chip);
        }
        li.appendChild(meta);
        els.audioStrings.appendChild(li);
      }
    }
  }

  const morseLike = (result && result.morseLike) || [];
  if (els.audioMorsePanel && els.audioMorseList) {
    if (!morseLike.length) {
      els.audioMorsePanel.hidden = true;
      els.audioMorseList.replaceChildren();
    } else {
      els.audioMorsePanel.hidden = false;
      els.audioMorseList.replaceChildren();
      for (const m of morseLike) {
        const li = document.createElement("li");
        li.className = "asset-item";
        const body = document.createElement("div");
        body.className = "preview mono";
        body.textContent = m.text;
        li.appendChild(body);
        const decoded = decodeMorse(m.text);
        if (decoded.ok) {
          const dec = document.createElement("div");
          dec.className = "audio-morse-decode mono";
          dec.textContent = "→ " + decoded.text;
          li.appendChild(dec);
        }
        const meta = document.createElement("div");
        meta.className = "meta-line";
        if (m.source) {
          const src = document.createElement("span");
          src.textContent = m.source;
          meta.appendChild(src);
        }
        meta.appendChild(
          handoffButton("Cipher", () => sendMorseToCipher(m.text, { auto: true }))
        );
        meta.appendChild(copyButton(decoded.ok ? decoded.text : m.text));
        li.appendChild(meta);
        els.audioMorseList.appendChild(li);
      }
    }
  }

  if (result && result.ok && els.audioAnalyzePanel) {
    els.audioAnalyzePanel.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

async function runAudioAnalyze(urlOrBuffer, filename) {
  if (!urlOrBuffer) return;
  setAudioStatus("Analyzing…");
  if (els.btnAudioAnalyze) els.btnAudioAnalyze.disabled = true;
  clearAudioAnalyzePanel();
  try {
    let result;
    if (typeof urlOrBuffer === "string") {
      result = await browser.runtime.sendMessage({
        type: MSG.AUDIO_ANALYZE,
        url: urlOrBuffer,
      });
    } else {
      // Send a copy so messaging cannot detach the sidebar's owned buffer.
      const payload =
        urlOrBuffer instanceof ArrayBuffer ? urlOrBuffer.slice(0) : urlOrBuffer;
      result = await browser.runtime.sendMessage({
        type: MSG.AUDIO_ANALYZE,
        buffer: payload,
        filename: filename || "audio",
      });
    }
    if (!result || !result.ok) {
      setAudioStatus((result && result.error) || "Audio analysis failed.");
      if (els.audioAnalyzePanel) els.audioAnalyzePanel.hidden = false;
      return;
    }
    const meta =
      formatByteSize(result.size) +
      (result.contentType ? " · " + result.contentType : "") +
      " · " +
      ((result.strings && result.strings.length) || 0) +
      " string(s)" +
      (result.id3 && result.id3.length ? " · " + result.id3.length + " ID3" : "");
    setAudioStatus(meta);
    renderAudioAnalyzeResult(result);
    if (typeof urlOrBuffer === "string" && /^https?:\/\//i.test(urlOrBuffer)) {
      ensureHttpAudioPreview(urlOrBuffer);
    }
  } catch (_err) {
    setAudioStatus("Audio analysis request failed.");
  } finally {
    if (els.btnAudioAnalyze) els.btnAudioAnalyze.disabled = false;
    rebindAudioPreviewAfterAnalyze();
  }
}

async function analyzeAudioLocally(file) {
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    setAudioStatus("Audio too large (>8 MB)");
    return;
  }
  const buf = await file.arrayBuffer();
  // Keep an owned copy in module scope (survives analyze messaging).
  const owned = buf.slice(0);
  const name = file.name || "audio";
  const mime = resolveAudioMime(file, name);
  const blob = new Blob([owned], { type: mime });
  const previewUrl = URL.createObjectURL(blob);
  const asset = {
    url: "",
    filename: name,
    local: true,
    capturedAt: Date.now(),
  };
  audioLocalBuffer = owned;
  audioLocalFilename = name;
  // Paint preview first, then await store write before any deep-tool tabs.create
  // can race a pushState with an empty STORE.AUDIO.
  renderAudioAsset(asset, { focus: true, previewUrl, keepStatus: true });
  await persistAudioAsset(asset);
  await runAudioAnalyze(owned, name);
}

function focusCipherPanel(opts) {
  focusPanel("panel-cipher");
  const focusInput = !opts || opts.focusInput !== false;
  if (!focusInput || !els.cipherInput) return;
  try {
    els.cipherInput.focus({ preventScroll: true });
  } catch (_err) {
    try {
      els.cipherInput.focus();
    } catch (_err2) {
      /* ignore */
    }
  }
}

function setProbeMode(mode) {
  probeMode = mode === "username" ? "username" : "id";
  if (els.modeId) els.modeId.classList.toggle("is-active", probeMode === "id");
  if (els.modeUsername) {
    els.modeUsername.classList.toggle("is-active", probeMode === "username");
  }
  if (els.probeInput) {
    els.probeInput.placeholder =
      probeMode === "username"
        ? "octocat"
        : "jGJuVGiK or 690519146701783042";
  }
}

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

function openUrlInBackground(url) {
  if (!url) return;
  // Never window.open from the sidebar — it can navigate the sidebar panel itself.
  // Only background tabs.create; sidebar DOM/state must stay put.
  browser.runtime
    .sendMessage({ type: MSG.OPEN_URL, url, active: false })
    .catch(() => {
      browser.tabs.create({ url, active: false }).catch(() => {});
    });
}

function setImageForensicsStatus(text, options) {
  if (!els.imageForensicsStatus) return;
  const showFallback = options && options.showCopyFallback;
  if (!text) {
    els.imageForensicsStatus.hidden = true;
    els.imageForensicsStatus.textContent = "";
    if (els.imageForensicsFallback) els.imageForensicsFallback.hidden = true;
    return;
  }
  els.imageForensicsStatus.hidden = false;
  els.imageForensicsStatus.textContent = text;
  if (els.imageForensicsFallback) {
    els.imageForensicsFallback.hidden = !showFallback;
  }
}

async function runImageForensics(imageUrl) {
  if (!imageUrl) return;
  lastForensicsUrl = imageUrl;
  const tools = forensicsToolUrls(imageUrl);
  for (const url of tools) {
    openUrlInBackground(url);
  }
  const copied = await copyText(imageUrl);
  const n = tools.length;
  setImageForensicsStatus(
    copied
      ? "Opened " + n + " tools · URL copied"
      : "Opened " + n + " tools · copy failed — use Copy image URL",
    { showCopyFallback: !copied }
  );
}

async function runStegStruckScan(imageUrl) {
  if (!imageUrl) return;
  if (els.btnImageStegstruck) els.btnImageStegstruck.disabled = true;
  setImageForensicsStatus("Sending to StegStruck…", { showCopyFallback: false });
  try {
    const result = await browser.runtime.sendMessage({
      type: MSG.STEGSTRUCK_SCAN,
      url: imageUrl,
      tier: "quick",
    });
    if (!result || !result.ok) {
      setImageForensicsStatus(
        (result && result.error) || "StegStruck failed",
        { showCopyFallback: false }
      );
      return;
    }
    setImageForensicsStatus(
      "StegStruck opened · job " + (result.jobId || ""),
      { showCopyFallback: false }
    );
  } catch (err) {
    setImageForensicsStatus(
      (err && err.message) || "StegStruck failed",
      { showCopyFallback: false }
    );
  } finally {
    if (els.btnImageStegstruck) els.btnImageStegstruck.disabled = false;
  }
}

function renderImageAsset(imageAsset, options) {
  const shouldFocus = !options || options.focus !== false;
  currentImage =
    imageAsset && (imageAsset.url || imageAsset.filename || imageAsset.needsDrop)
      ? imageAsset
      : null;
  if (!els.imageCard || !els.imageEmpty || !els.badgeImage) return;

  if (!currentImage) {
    els.badgeImage.textContent = "0";
    els.imageEmpty.hidden = false;
    els.imageCard.hidden = true;
    els.imageUrl.textContent = "";
    els.imageUrl.title = "";
    setImageForensicsStatus("");
    clearImageHexPanel();
    return;
  }

  if (shouldFocus) focusImagePanel();
  els.badgeImage.textContent = "1";
  els.imageEmpty.hidden = true;
  els.imageCard.hidden = false;
  const label =
    currentImage.url ||
    currentImage.filename ||
    "(no re-fetchable URL — drop / open file)";
  els.imageUrl.textContent = label;
  els.imageUrl.title = currentImage.url || currentImage.filename || "";
  if (currentImage.needsDrop) {
    setImageForensicsStatus(
      "Download URL not re-fetchable — drop the file or use a public URL for Hex / reverse"
    );
  }
}

function setArchiveStatus(text) {
  if (els.archiveStatus) els.archiveStatus.textContent = text || "";
}

function archiveCommentPayload(info) {
  if (!info) return "";
  return info.comment == null ? "" : String(info.comment);
}

/**
 * @param {object|null} archiveInfo
 * @param {{ focus?: boolean }} [options]
 */
function renderArchiveInfo(archiveInfo, options) {
  const shouldFocus = !options || options.focus !== false;
  currentArchive =
    archiveInfo && (archiveInfo.filename || archiveInfo.comment != null || archiveInfo.error)
      ? archiveInfo
      : null;

  if (!els.archiveCard || !els.archiveEmpty || !els.badgeArchive) return;

  if (!currentArchive) {
    els.badgeArchive.textContent = "0";
    els.archiveEmpty.hidden = false;
    els.archiveCard.hidden = true;
    if (els.archiveFilename) {
      els.archiveFilename.textContent = "";
      els.archiveFilename.title = "";
    }
    if (els.archiveEncrypted) els.archiveEncrypted.textContent = "—";
    if (els.archiveComment) els.archiveComment.textContent = "—";
    if (els.archiveHexHint) els.archiveHexHint.hidden = true;
    return;
  }

  if (shouldFocus) focusArchivePanel();
  els.badgeArchive.textContent = "1";
  els.archiveEmpty.hidden = true;
  els.archiveCard.hidden = false;

  const name = currentArchive.filename || "(unnamed)";
  if (els.archiveFilename) {
    els.archiveFilename.textContent = name;
    els.archiveFilename.title = currentArchive.url || name;
  }

  if (els.archiveEncrypted) {
    if (typeof currentArchive.encrypted === "boolean") {
      els.archiveEncrypted.textContent = currentArchive.encrypted ? "yes" : "no";
    } else {
      els.archiveEncrypted.textContent = "—";
    }
  }

  const comment = archiveCommentPayload(currentArchive);
  if (els.archiveComment) {
    els.archiveComment.textContent = comment || "(empty)";
  }

  const zip = typeof ZIP_ARCHIVE !== "undefined" ? ZIP_ARCHIVE : null;
  const hint =
    currentArchive.hexHint ||
    (zip ? zip.hexDecodeHint(comment) : null) ||
    null;
  if (els.archiveHexHint && els.archiveHexDecoded) {
    if (hint) {
      els.archiveHexHint.hidden = false;
      els.archiveHexDecoded.textContent = hint;
    } else {
      els.archiveHexHint.hidden = true;
      els.archiveHexDecoded.textContent = "";
    }
  }

  if (currentArchive.error) {
    setArchiveStatus(currentArchive.error);
  } else if (currentArchive.source === "download") {
    setArchiveStatus(
      "From download" + (currentArchive.format ? " · " + currentArchive.format : "")
    );
  } else if (currentArchive.source === "manual") {
    setArchiveStatus(
      "Manual analyze" + (currentArchive.format ? " · " + currentArchive.format : "")
    );
  } else {
    setArchiveStatus("");
  }
}

/**
 * Build + persist + render archive info from a local ArrayBuffer.
 * @param {ArrayBuffer} buffer
 * @param {string} filename
 */
async function analyzeArchiveLocally(buffer, filename) {
  const zip = typeof ZIP_ARCHIVE !== "undefined" ? ZIP_ARCHIVE : null;
  if (!zip) {
    setArchiveStatus("ZIP parser unavailable");
    return;
  }

  const MAX = 16 * 1024 * 1024;
  if (buffer.byteLength > MAX) {
    setArchiveStatus("Archive too large (>" + Math.round(MAX / (1024 * 1024)) + " MB)");
    return;
  }

  setArchiveStatus("Analyzing…");
  const result = zip.inspect(buffer, { filename: filename || "" });
  const payload = {
    filename: filename || "",
    comment: result.comment || "",
    encrypted: result.encrypted,
    url: "",
    format: result.format,
    supported: result.supported,
    error: result.error,
    source: "manual",
    capturedAt: Date.now(),
    hexHint: zip.hexDecodeHint(result.comment || ""),
    ok: result.ok,
  };

  try {
    await browser.runtime.sendMessage({ type: MSG.ARCHIVE_INFO, archiveInfo: payload });
  } catch (_err) {
    /* background may be asleep; still render locally */
  }
  renderArchiveInfo(payload, { focus: true });
}

function clearHexPreview() {
  if (hexPreviewObjectUrl) {
    try {
      URL.revokeObjectURL(hexPreviewObjectUrl);
    } catch (_err) {
      /* ignore */
    }
    hexPreviewObjectUrl = null;
  }
  hexPatchedBlob = null;
  if (els.imageHexPreview) {
    els.imageHexPreview.removeAttribute("src");
  }
  if (els.imageHexPreviewWrap) els.imageHexPreviewWrap.hidden = true;
  if (els.btnHexDownload) els.btnHexDownload.hidden = true;
}

function clearSplitPreviews() {
  for (const u of splitPreviewObjectUrls) {
    try {
      URL.revokeObjectURL(u);
    } catch (_err) {
      /* ignore */
    }
  }
  splitPreviewObjectUrls = [];
  if (els.imageSplitPreviews) els.imageSplitPreviews.replaceChildren();
  if (els.imageSplitPreviewWrap) els.imageSplitPreviewWrap.hidden = true;
}

function clearImageSplitPanel() {
  imageSplitSession = null;
  clearSplitPreviews();
  if (els.imageSplitPanel) els.imageSplitPanel.hidden = true;
  if (els.imageSplitStatus) els.imageSplitStatus.textContent = "";
  if (els.imageSplitActions) els.imageSplitActions.replaceChildren();
  if (els.imageSplitList) els.imageSplitList.replaceChildren();
}

function clearImageHexPanel() {
  hexEditSession = null;
  clearHexPreview();
  clearImageSplitPanel();
  if (els.imageHexPanel) els.imageHexPanel.hidden = true;
  if (els.imageHexMeta) els.imageHexMeta.textContent = "";
  if (els.imageHexStrings) els.imageHexStrings.replaceChildren();
  if (els.imageHexHead) els.imageHexHead.textContent = "";
  if (els.imageHexTail) els.imageHexTail.textContent = "";
  if (els.imageHexEdit) els.imageHexEdit.value = "";
  if (els.imageHexEditLabel) els.imageHexEditLabel.textContent = "";
  if (els.imageHexEditStatus) els.imageHexEditStatus.textContent = "";
}

function formatByteSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

function formatHexOffset(n) {
  return "0x" + Number(n || 0).toString(16);
}

function describeHexEditScope(result) {
  const scope = result.editScope || "full";
  const off = Number(result.editOffset) || 0;
  const editSize = Number(result.editSize) || 0;
  if (scope === "tail") {
    return (
      "last " +
      formatByteSize(editSize) +
      " · @0x" +
      off.toString(16) +
      "–EOF (file > 2 MB)"
    );
  }
  return "full file · " + formatByteSize(editSize);
}

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function guessPatchedFilename(url, contentType) {
  let base = "patched-image";
  try {
    const u = new URL(url);
    const seg = (u.pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
    if (seg) base = seg.replace(/\.[^.]+$/, "") || base;
  } catch (_err) {
    /* ignore */
  }
  const ct = String(contentType || "").toLowerCase();
  let ext = ".bin";
  if (ct.includes("png")) ext = ".png";
  else if (ct.includes("jpeg") || ct.includes("jpg")) ext = ".jpg";
  else if (ct.includes("gif")) ext = ".gif";
  else if (ct.includes("webp")) ext = ".webp";
  else if (ct.includes("svg")) ext = ".svg";
  else {
    try {
      const path = new URL(url).pathname.toLowerCase();
      const m = path.match(/\.(png|jpe?g|gif|webp|svg|bmp|ico)(\?|$)/);
      if (m) ext = "." + (m[1] === "jpeg" ? "jpg" : m[1]);
    } catch (_err2) {
      /* ignore */
    }
  }
  return base + "-patched" + ext;
}

function guessSplitPartFilename(url, part) {
  let base = "image";
  try {
    const u = new URL(url);
    const seg = (u.pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
    if (seg) base = seg.replace(/\.[^.]+$/, "") || base;
  } catch (_err) {
    /* ignore */
  }
  const idx = (part.index != null ? part.index : 0) + 1;
  const ext = part.ext || ".bin";
  return base + "-part" + idx + ext;
}

function describeSplitMarkers(markers) {
  if (!markers) return "";
  const bits = [];
  if (markers.jpegEoi != null) {
    bits.push("JPEG EOI @" + formatHexOffset(markers.jpegEoi));
  }
  if (markers.pngIend != null) {
    bits.push("PNG IEND @" + formatHexOffset(markers.pngIend));
  }
  return bits.length ? " · " + bits.join(" · ") : "";
}

async function requestImagePart(url, part) {
  const result = await browser.runtime.sendMessage({
    type: MSG.IMAGE_EXTRACT_PART,
    url,
    offset: part.offset,
    length: part.size,
    mime: part.mime || "application/octet-stream",
  });
  if (!result || !result.ok || !result.base64) {
    throw new Error((result && result.error) || "Extract failed");
  }
  const bytes = base64ToUint8Array(result.base64);
  const type = result.contentType || part.mime || "application/octet-stream";
  return new Blob([bytes], { type });
}

function downloadBlobAs(blob, filename) {
  const a = document.createElement("a");
  const url = URL.createObjectURL(blob);
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => {
    try {
      URL.revokeObjectURL(url);
    } catch (_err) {
      /* ignore */
    }
  }, 1500);
}

async function downloadSplitPart(partIndex) {
  if (!imageSplitSession || !imageSplitSession.url) return;
  const part = (imageSplitSession.splits || [])[partIndex];
  if (!part) return;
  if (els.imageSplitStatus) {
    els.imageSplitStatus.textContent =
      "Downloading part " + (partIndex + 1) + "…";
  }
  try {
    const blob = await requestImagePart(imageSplitSession.url, part);
    downloadBlobAs(blob, guessSplitPartFilename(imageSplitSession.url, part));
    if (els.imageSplitStatus) {
      els.imageSplitStatus.textContent =
        "Downloaded part " +
        (partIndex + 1) +
        " (" +
        (part.label || part.type) +
        " @" +
        formatHexOffset(part.offset) +
        ", " +
        formatByteSize(part.size) +
        ")";
    }
  } catch (err) {
    if (els.imageSplitStatus) {
      els.imageSplitStatus.textContent =
        (err && err.message) || "Download part failed.";
    }
  }
}

async function downloadAllSplitParts() {
  if (!imageSplitSession || !imageSplitSession.splits) return;
  for (let i = 0; i < imageSplitSession.splits.length; i++) {
    await downloadSplitPart(i);
  }
}

async function previewSplitParts(indices) {
  if (!imageSplitSession || !imageSplitSession.url) return;
  const splits = imageSplitSession.splits || [];
  const want = (indices || []).filter((i) => splits[i] && splits[i].previewable);
  if (!want.length) {
    if (els.imageSplitStatus) {
      els.imageSplitStatus.textContent =
        "No image-type parts to preview (ZIP/PDF are download-only).";
    }
    return;
  }
  clearSplitPreviews();
  if (els.imageSplitStatus) els.imageSplitStatus.textContent = "Loading preview…";
  if (els.imageSplitPreviewWrap) els.imageSplitPreviewWrap.hidden = false;
  try {
    for (const i of want) {
      const part = splits[i];
      const blob = await requestImagePart(imageSplitSession.url, part);
      const objUrl = URL.createObjectURL(blob);
      splitPreviewObjectUrls.push(objUrl);
      const wrap = document.createElement("div");
      wrap.className = "split-preview-item";
      const meta = document.createElement("div");
      meta.className = "meta-line";
      meta.textContent =
        "Part " +
        (i + 1) +
        " · " +
        (part.label || part.type) +
        " @" +
        formatHexOffset(part.offset) +
        " · " +
        formatByteSize(part.size);
      const img = document.createElement("img");
      img.className = "hex-preview-img";
      img.alt = "Split part " + (i + 1);
      img.src = objUrl;
      wrap.appendChild(meta);
      wrap.appendChild(img);
      if (els.imageSplitPreviews) els.imageSplitPreviews.appendChild(wrap);
    }
    if (els.imageSplitStatus) {
      els.imageSplitStatus.textContent =
        "Previewing " + want.length + " image part(s) below.";
    }
  } catch (err) {
    if (els.imageSplitStatus) {
      els.imageSplitStatus.textContent =
        (err && err.message) || "Preview failed.";
    }
  }
}

function renderImageSplitResult(result, opts) {
  const focusSplit = !!(opts && opts.focusSplit);
  if (!els.imageSplitPanel) return;

  const splits = (result && result.splits) || [];
  const concatenated = !!(result && result.concatenated && splits.length >= 2);

  if (!concatenated) {
    clearImageSplitPanel();
    // Still show a quiet note when Split was clicked and nothing glued.
    if (focusSplit && result && result.ok) {
      els.imageSplitPanel.hidden = false;
      if (els.imageSplitStatus) {
        const markerNote = describeSplitMarkers(result.markers);
        els.imageSplitStatus.textContent =
          "No concatenated payload detected" +
          markerNote +
          ". Single container or no second magic after EOI/IEND.";
      }
    }
    return;
  }

  imageSplitSession = {
    url: (result && result.url) || (currentImage && currentImage.url) || "",
    splits,
    markers: result.markers || null,
    concatenated: true,
  };
  clearSplitPreviews();
  els.imageSplitPanel.hidden = false;

  const second = splits[1];
  if (els.imageSplitStatus) {
    els.imageSplitStatus.textContent =
      "Concatenated file detected @" +
      formatHexOffset(second.offset) +
      " (" +
      (second.label || second.type) +
      ")" +
      " · " +
      splits.length +
      " part(s)" +
      describeSplitMarkers(result.markers);
  }

  if (els.imageSplitActions) {
    els.imageSplitActions.replaceChildren();
    const addBtn = (label, title, onClick) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ghost-btn";
      btn.textContent = label;
      if (title) btn.title = title;
      btn.addEventListener("click", onClick);
      els.imageSplitActions.appendChild(btn);
    };
    addBtn("Download part 1", "Save bytes before second magic", () =>
      downloadSplitPart(0)
    );
    addBtn(
      "Download part 2",
      "Save concatenated payload starting @" + formatHexOffset(second.offset),
      () => downloadSplitPart(1)
    );
    const previewableIdx = splits
      .map((p, i) => (p.previewable ? i : -1))
      .filter((i) => i >= 0);
    if (previewableIdx.length) {
      addBtn("Preview both", "Show <img> for image-type parts", () =>
        previewSplitParts(previewableIdx.slice(0, 2))
      );
    }
    if (splits.length > 2) {
      addBtn("Split all", "Download every detected segment", () =>
        downloadAllSplitParts()
      );
    }
  }

  if (els.imageSplitList) {
    els.imageSplitList.replaceChildren();
    splits.forEach((part, i) => {
      const li = document.createElement("li");
      li.className = "asset-item";
      const body = document.createElement("div");
      body.className = "preview mono";
      body.textContent =
        "Part " +
        (i + 1) +
        " · " +
        (part.label || part.type) +
        " @" +
        formatHexOffset(part.offset) +
        " · " +
        formatByteSize(part.size);
      li.appendChild(body);
      const meta = document.createElement("div");
      meta.className = "meta-line";
      const dl = document.createElement("button");
      dl.type = "button";
      dl.className = "ghost-btn";
      dl.textContent = "Download";
      dl.addEventListener("click", () => downloadSplitPart(i));
      meta.appendChild(dl);
      if (part.previewable) {
        const pv = document.createElement("button");
        pv.type = "button";
        pv.className = "ghost-btn";
        pv.textContent = "Preview";
        pv.addEventListener("click", () => previewSplitParts([i]));
        meta.appendChild(pv);
      }
      li.appendChild(meta);
      els.imageSplitList.appendChild(li);
    });
  }

  if (focusSplit) {
    els.imageSplitPanel.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

function renderImageHexResult(result, opts) {
  if (!els.imageHexPanel) return;
  clearHexPreview();
  if (!result || !result.ok) {
    hexEditSession = null;
    clearImageSplitPanel();
    els.imageHexPanel.hidden = false;
    if (els.imageHexMeta) {
      els.imageHexMeta.textContent = (result && result.error) || "Hex analysis failed.";
    }
    if (els.imageHexStrings) els.imageHexStrings.replaceChildren();
    if (els.imageHexHead) els.imageHexHead.textContent = "";
    if (els.imageHexTail) els.imageHexTail.textContent = "";
    if (els.imageHexEdit) els.imageHexEdit.value = "";
    if (els.imageHexEditLabel) els.imageHexEditLabel.textContent = "";
    if (els.imageHexEditStatus) els.imageHexEditStatus.textContent = "";
    return;
  }

  els.imageHexPanel.hidden = false;
  if (els.imageHexMeta) {
    const splitNote =
      result.concatenated && result.splits && result.splits.length >= 2
        ? " · concatenated @" + formatHexOffset(result.splits[1].offset)
        : "";
    els.imageHexMeta.textContent =
      formatByteSize(result.size) +
      (result.contentType ? " · " + result.contentType : "") +
      " · " +
      ((result.strings && result.strings.length) || 0) +
      " string(s)" +
      splitNote;
  }

  renderImageSplitResult(result, opts);

  if (els.imageHexStrings) {
    els.imageHexStrings.replaceChildren();
    const list = result.strings || [];
    if (!list.length) {
      const li = document.createElement("li");
      li.className = "asset-item";
      li.textContent = "No printable strings (≥4 chars) in scan window.";
      els.imageHexStrings.appendChild(li);
    } else {
      for (const s of list) {
        const li = document.createElement("li");
        li.className = "asset-item";
        const body = document.createElement("div");
        body.className = "preview mono";
        body.textContent = s.text.length > 160 ? s.text.slice(0, 160) + "…" : s.text;
        body.title = s.text;
        li.appendChild(body);
        const meta = document.createElement("div");
        meta.className = "meta-line";
        const off = document.createElement("span");
        off.textContent =
          "@0x" + Number(s.offset || 0).toString(16) + " · " + (s.len || s.text.length) + " chars";
        meta.appendChild(off);
        meta.appendChild(copyButton(s.text));
        meta.appendChild(handoffButton("Cipher", () => sendTextToCipher(s.text)));
        meta.appendChild(
          handoffButton("Probe", () => {
            setProbeMode("id");
            els.probeInput.value = s.text.trim().slice(0, 200);
            focusProbePanel();
            startProbe();
          })
        );
        meta.appendChild(
          handoffButton("Notes", () => {
            if (!els.notesInput) return;
            const cur = els.notesInput.value || "";
            els.notesInput.value = cur ? cur + "\n" + s.text : s.text;
            persistNotesSoon();
            focusNotesPanel();
          })
        );
        li.appendChild(meta);
        els.imageHexStrings.appendChild(li);
      }
    }
  }

  if (els.imageHexHead) els.imageHexHead.textContent = result.headHex || "";
  if (els.imageHexTail) els.imageHexTail.textContent = result.tailHex || "";

  hexEditSession = {
    url: result.url || (currentImage && currentImage.url) || "",
    editOffset: Number(result.editOffset) || 0,
    editHex: result.editHex || "",
    editScope: result.editScope || "full",
    editSize: Number(result.editSize) || 0,
  };
  if (els.imageHexEditLabel) {
    els.imageHexEditLabel.textContent = "(" + describeHexEditScope(result) + ")";
  }
  if (els.imageHexEdit) els.imageHexEdit.value = result.editHex || "";
  if (els.imageHexEditStatus) {
    els.imageHexEditStatus.textContent =
      result.editScope === "tail"
        ? "Large file: editing last " +
          formatByteSize(result.editSize) +
          " only. Apply replaces that region through EOF."
        : "Edit hex, then Apply / Patch for preview + download.";
  }

  if (!(opts && opts.focusSplit)) {
    els.imageHexPanel.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

async function applyHexPatch() {
  if (!hexEditSession || !hexEditSession.url) {
    if (els.imageHexEditStatus) {
      els.imageHexEditStatus.textContent = "Run Hex / strings first.";
    }
    return;
  }
  const editHex = els.imageHexEdit ? els.imageHexEdit.value : "";
  if (els.imageHexEditStatus) els.imageHexEditStatus.textContent = "Patching…";
  if (els.btnHexApply) els.btnHexApply.disabled = true;
  clearHexPreview();
  try {
    const result = await browser.runtime.sendMessage({
      type: MSG.IMAGE_HEX_PATCH,
      url: hexEditSession.url,
      editOffset: hexEditSession.editOffset,
      editHex,
    });
    if (!result || !result.ok || !result.base64) {
      if (els.imageHexEditStatus) {
        els.imageHexEditStatus.textContent =
          (result && result.error) || "Patch failed.";
      }
      return;
    }
    const bytes = base64ToUint8Array(result.base64);
    const type = result.contentType || "application/octet-stream";
    hexPatchedBlob = new Blob([bytes], { type });
    hexPreviewObjectUrl = URL.createObjectURL(hexPatchedBlob);
    if (els.imageHexPreview) {
      els.imageHexPreview.src = hexPreviewObjectUrl;
      els.imageHexPreview.alt = "Patched preview (" + formatByteSize(result.size) + ")";
    }
    if (els.imageHexPreviewWrap) els.imageHexPreviewWrap.hidden = false;
    if (els.btnHexDownload) els.btnHexDownload.hidden = false;
    if (els.imageHexEditStatus) {
      els.imageHexEditStatus.textContent =
        "Patched " +
        formatByteSize(result.size) +
        (result.originalSize != null && result.originalSize !== result.size
          ? " (was " + formatByteSize(result.originalSize) + ")"
          : "") +
        ". Preview below — PNG CRC may be invalid if chunks were corrupted.";
    }
  } catch (_err) {
    if (els.imageHexEditStatus) {
      els.imageHexEditStatus.textContent = "Patch request failed.";
    }
  } finally {
    if (els.btnHexApply) els.btnHexApply.disabled = false;
  }
}

function resetHexEdit() {
  if (!hexEditSession) return;
  if (els.imageHexEdit) els.imageHexEdit.value = hexEditSession.editHex || "";
  clearHexPreview();
  if (els.imageHexEditStatus) {
    els.imageHexEditStatus.textContent = "Reset to original edit region.";
  }
}

function downloadPatchedHex() {
  if (!hexPatchedBlob || !hexEditSession) return;
  const a = document.createElement("a");
  const url = hexPreviewObjectUrl || URL.createObjectURL(hexPatchedBlob);
  a.href = url;
  a.download = guessPatchedFilename(
    hexEditSession.url,
    hexPatchedBlob.type
  );
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function runImageHex(imageUrl, opts) {
  if (!imageUrl) return;
  const focusSplit = !!(opts && opts.focusSplit);
  focusImagePanel();
  if (els.imageHexPanel) els.imageHexPanel.hidden = false;
  if (els.imageHexMeta) {
    els.imageHexMeta.textContent = focusSplit
      ? "Scanning for concatenated files…"
      : "Fetching bytes…";
  }
  if (els.imageHexStrings) els.imageHexStrings.replaceChildren();
  if (els.imageHexHead) els.imageHexHead.textContent = "";
  if (els.imageHexTail) els.imageHexTail.textContent = "";
  if (els.imageHexEdit) els.imageHexEdit.value = "";
  if (els.imageHexEditLabel) els.imageHexEditLabel.textContent = "";
  if (els.imageHexEditStatus) els.imageHexEditStatus.textContent = "";
  clearHexPreview();
  clearImageSplitPanel();
  hexEditSession = null;
  if (els.btnImageHex) els.btnImageHex.disabled = true;
  if (els.btnImageSplit) els.btnImageSplit.disabled = true;
  try {
    const result = await browser.runtime.sendMessage({
      type: MSG.IMAGE_HEX,
      url: imageUrl,
    });
    renderImageHexResult(result || { ok: false, error: "No response" }, {
      focusSplit,
    });
    // Light meta peek alongside hex when available
    if (result && result.ok && result.metaFields) {
      renderImageMetaResult({ ok: true, fields: result.metaFields, url: imageUrl });
    }
  } catch (_err) {
    renderImageHexResult({ ok: false, error: "Hex analysis failed." });
  } finally {
    if (els.btnImageHex) els.btnImageHex.disabled = false;
    if (els.btnImageSplit) els.btnImageSplit.disabled = false;
  }
}

function renderImageMetaResult(result) {
  if (!els.imageMetaPanel) return;
  els.imageMetaPanel.hidden = false;
  if (!result || !result.ok) {
    if (els.imageMetaStatus) {
      els.imageMetaStatus.textContent = (result && result.error) || "Meta parse failed.";
    }
    if (els.imageMetaList) els.imageMetaList.replaceChildren();
    return;
  }
  const fields = result.fields || [];
  if (els.imageMetaStatus) {
    els.imageMetaStatus.textContent = fields.length
      ? fields.length + " field(s)"
      : "No EXIF / PNG text chunks found.";
  }
  if (!els.imageMetaList) return;
  els.imageMetaList.replaceChildren();
  for (const f of fields) {
    const label = f.key || f.tag || "field";
    const value = f.value || "";
    const li = assetCard(
      label + ": " + (value.length > 140 ? value.slice(0, 140) + "…" : value),
      f.source || "meta",
      value,
      label,
      { handoff: true }
    );
    els.imageMetaList.appendChild(li);
  }
  els.imageMetaPanel.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

async function runImageMeta(imageUrl) {
  if (!imageUrl) return;
  focusImagePanel();
  if (els.imageMetaPanel) els.imageMetaPanel.hidden = false;
  if (els.imageMetaStatus) els.imageMetaStatus.textContent = "Fetching metadata…";
  if (els.imageMetaList) els.imageMetaList.replaceChildren();
  if (els.btnImageMeta) els.btnImageMeta.disabled = true;
  try {
    const result = await browser.runtime.sendMessage({
      type: MSG.IMAGE_META,
      url: imageUrl,
    });
    renderImageMetaResult(result || { ok: false, error: "No response" });
  } catch (_err) {
    renderImageMetaResult({ ok: false, error: "Meta analysis failed." });
  } finally {
    if (els.btnImageMeta) els.btnImageMeta.disabled = false;
  }
}

function filterReasonLabel(row) {
  const err = String((row && row.error) || "");
  const map = {
    "m-string": "missing-page string",
    "m-code": "missing status code",
    "soft-404": "soft-404 body",
    unconfirmed: "no exists signal",
    "unconfirmed-manual": "open to verify",
    "no-e-string": "no exists rule",
    "no-e-string-manual": "open to verify",
    "redirect-lost-id": "redirect lost id",
    "raw-miss": "empty/error body",
    "status-unconfirmed": "ambiguous redirect",
    "tab-missing": "not found on page",
    "tab-unconfirmed": "page check inconclusive",
    "tab-no-content-script": "page check failed",
    "tab-timeout": "page check timeout",
    "tab-blocked": "blocked / login wall",
    "auth-or-rate-limit": "blocked (auth/rate-limit)",
    "manual-check": "open to verify (no auto-confirm)",
    "fetch-failed": "fetch failed — open to verify",
    "http-401": "HTTP 401 auth",
    "http-403": "HTTP 403 auth/rate-limit",
    "http-429": "HTTP 429 rate-limit",
    "http-502": "HTTP 502 gateway",
    "http-503": "HTTP 503 unavailable",
    "http-504": "HTTP 504 timeout",
  };
  if (map[err]) return map[err];
  if (row && row.kind === "blocked") return "blocked (auth/rate-limit)";
  if (row && row.kind === "error") return err ? "error: " + err : "request error";
  if (row && row.status === 404) return "HTTP 404";
  if (row && row.status === 410) return "HTTP 410";
  if (err) return err;
  return row && row.status != null ? "HTTP " + row.status + " not confirmed" : "not confirmed";
}

function renderFilteredList(probe) {
  if (!els.probeFiltered || !els.probeFilteredBody) return;
  // Soft misses only — blocked/auth/rate-limit belong in the primary list.
  const rows = ((probe && probe.misses) || [])
    .filter((r) => r && r.group !== "likely")
    .slice()
    .sort((a, b) => String(a.label || "").localeCompare(String(b.label || "")));

  if (!rows.length) {
    els.probeFiltered.hidden = true;
    els.probeFilteredBody.replaceChildren();
    if (els.countFiltered) els.countFiltered.textContent = "0";
    return;
  }

  els.probeFiltered.hidden = false;
  if (els.countFiltered) els.countFiltered.textContent = String(rows.length);
  els.probeFilteredBody.replaceChildren();

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>Service</th><th>Why filtered</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    const tdSvc = document.createElement("td");
    tdSvc.className = "svc";
    tdSvc.textContent = row.label || row.group || "Host";
    const tdWhy = document.createElement("td");
    const reason = document.createElement("div");
    reason.className = "reason";
    reason.textContent = filterReasonLabel(row);
    tdWhy.appendChild(reason);
    if (row.url) {
      const a = document.createElement("a");
      a.href = row.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = row.url;
      tdWhy.appendChild(a);
    }
    if (row.status != null && row.status !== 0) {
      const st = document.createElement("div");
      st.className = "decoded";
      st.textContent = "HTTP " + row.status;
      tdWhy.appendChild(st);
    }
    tr.append(tdSvc, tdWhy);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  els.probeFilteredBody.appendChild(table);
}

function renderProbe(probe, options) {
  const shouldFocus = !options || options.focus !== false;
  if (!probe) {
    els.badgeProbe.textContent = "0";
    els.probeStatus.textContent = "";
    els.probeStatus.className = "probe-status";
    els.probeHits.replaceChildren();
    renderFilteredList(null);
    els.btnProbe.disabled = false;
    return;
  }

  if (shouldFocus) focusProbePanel();

  if (probe.mode) setProbeMode(probe.mode);

  if (probe.id && els.probeInput && !els.probeInput.matches(":focus")) {
    if (els.probeInput.value !== probe.id) els.probeInput.value = probe.id;
  }

  const hits = (probe.hits || []).slice().sort((a, b) => {
    const pa = a.priority != null ? a.priority : 9;
    const pb = b.priority != null ? b.priority : 9;
    return pa - pb || String(a.label || "").localeCompare(String(b.label || ""));
  });
  const blocked = (probe.blocked || []).slice().sort((a, b) => {
    const pa = a.priority != null ? a.priority : 9;
    const pb = b.priority != null ? b.priority : 9;
    return pa - pb || String(a.label || "").localeCompare(String(b.label || ""));
  });
  const likely = probe.likely || [];
  const primaryUrls = new Set(
    hits.concat(blocked).map((h) => h.url).filter(Boolean)
  );
  // Shape suggestions only when nothing visible yet (avoid duplicating blocked GitHub etc.)
  const likelyOnly =
    hits.length || blocked.length
      ? []
      : likely.filter((l) => l && l.url && !primaryUrls.has(l.url));
  const rows = hits.concat(blocked).concat(likelyOnly);
  lastBlockedUrls = blocked.map((b) => b.url).filter(Boolean);

  els.badgeProbe.textContent = String(hits.length + blocked.length);
  els.btnProbe.disabled = Boolean(probe.running);
  if (els.probeActions) {
    els.probeActions.hidden = !(lastBlockedUrls.length && !probe.running);
  }

  const modeLabel = probe.mode === "username" ? "username" : "ID";
  const filteredCount = (probe.misses || []).length || 0;
  const blockedNote =
    blocked.length
      ? " · " + blocked.length + " blocked — check manually"
      : "";
  const filteredNote = filteredCount ? " · " + filteredCount + " filtered" : "";
  const siteDirHint =
    probe.siteDirQueued > 0 && probe.pageDir
      ? " · " + probe.siteDirQueued + " under " + probe.pageDir
      : "";
  els.probeStatus.className = "probe-status";
  if (probe.running) {
    els.probeStatus.classList.add("is-run");
    els.probeStatus.textContent =
      "Searching " + modeLabel + " " + (probe.tried || 0) + "/" + (probe.total || "?") +
      "… confirmed " + hits.length +
      (blocked.length ? ", " + blocked.length + " blocked" : "") +
      (filteredCount ? ", " + filteredCount + " filtered" : "") +
      siteDirHint;
  } else if (probe.status === "done") {
    if (hits.length || blocked.length) {
      els.probeStatus.classList.add(hits.length ? "is-hit" : "is-blocked");
      if (hits.length) {
        els.probeStatus.textContent =
          hits.length + " confirmed · " +
          blocked.length + " blocked · " +
          filteredCount + " filtered" +
          siteDirHint +
          " (exists-signal verified)";
      } else {
        els.probeStatus.textContent =
          "0 confirmed · " +
          blocked.length +
          " blocked (auth/rate-limit) — open to verify · " +
          filteredCount +
          " filtered" +
          siteDirHint;
      }
    } else if (likelyOnly.length) {
      els.probeStatus.classList.add("is-hit");
      els.probeStatus.textContent =
        "0 confirmed · 0 blocked · " + filteredCount + " filtered" + siteDirHint + ". " +
        likelyOnly.length +
        " shape-based suggestion" + (likelyOnly.length === 1 ? "" : "s") +
        " — open to verify:";
    } else {
      els.probeStatus.textContent =
        "0 confirmed · 0 blocked · " + filteredCount + " filtered for “" +
        (probe.id || "") +
        "” after " +
        (probe.tried || 0) +
        " hosts" +
        siteDirHint +
        ".";
    }
  } else {
    els.probeStatus.textContent = "";
  }

  els.probeHits.replaceChildren();
  renderFilteredList(probe);
  if (!rows.length) return;

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>Service</th><th>URL</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const hit of rows) {
    const tr = document.createElement("tr");
    if (hit.kind === "blocked") tr.className = "is-blocked";
    const tdSvc = document.createElement("td");
    tdSvc.className = "svc";
    const name = document.createElement("span");
    name.textContent = hit.label || hit.group || "Hit";
    tdSvc.appendChild(name);
    if (hit.kind === "blocked") {
      const badge = document.createElement("span");
      badge.className = "probe-row-badge is-blocked";
      badge.textContent = "blocked — check manually";
      tdSvc.appendChild(badge);
    } else if (!hit.hit && hit.kind === "likely") {
      const badge = document.createElement("span");
      badge.className = "probe-row-badge is-likely";
      badge.textContent = "likely";
      tdSvc.appendChild(badge);
    }
    const tdUrl = document.createElement("td");
    const a = document.createElement("a");
    a.href = hit.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = hit.url;
    tdUrl.appendChild(a);
    if (hit.status != null && hit.status !== 0) {
      const st = document.createElement("div");
      st.className = "decoded";
      st.textContent = "HTTP " + hit.status;
      tdUrl.appendChild(st);
    } else if (hit.kind === "blocked" && hit.error === "fetch-failed") {
      const st = document.createElement("div");
      st.className = "decoded";
      st.textContent = "fetch failed — open to verify";
      tdUrl.appendChild(st);
    }
    tr.append(tdSvc, tdUrl);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  els.probeHits.appendChild(table);
}

async function startProbe() {
  const id = (els.probeInput.value || "").trim();
  if (!id) {
    els.probeStatus.textContent =
      probeMode === "username" ? "Enter a username first." : "Enter a token first.";
    return;
  }
  els.btnProbe.disabled = true;
  els.probeStatus.className = "probe-status is-run";
  els.probeStatus.textContent = "Starting search…";
  try {
    const windowId = await currentWindowId();
    const pageUrl =
      lastKnownPageUrl ||
      (els.host && els.host.title) ||
      "";
    const res = await browser.runtime.sendMessage({
      type: MSG.PROBE_BACKLINK,
      id,
      mode: probeMode,
      windowId,
      pageUrl,
    });
    if (res && !res.ok) {
      els.probeStatus.className = "probe-status";
      els.probeStatus.textContent = res.error || "Probe failed.";
      els.btnProbe.disabled = false;
    } else if (res && res.pageDir) {
      // Immediate hint before progress events arrive
      els.probeStatus.textContent =
        "Starting search… queuing under " + res.pageDir;
    }
  } catch (_err) {
    els.probeStatus.className = "probe-status";
    els.probeStatus.textContent = "Probe failed.";
    els.btnProbe.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

els.reveal.addEventListener("click", async () => {
  const next = !revealEnabled;
  try {
    const windowId = await currentWindowId();
    await browser.runtime.sendMessage({
      type: MSG.TOGGLE_REVEAL,
      enabled: next,
      windowId,
    });
  } catch (_err) {
    els.scanStatus.textContent = "Reveal failed on this page.";
  }
});

els.btnProbe.addEventListener("click", () => startProbe());
els.probeInput.addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    startProbe();
  }
});

if (els.modeId) {
  els.modeId.addEventListener("click", () => setProbeMode("id"));
}
if (els.modeUsername) {
  els.modeUsername.addEventListener("click", () => setProbeMode("username"));
}

function openUrl(url) {
  if (!url) return;
  // Prefer background tabs.create — window.open from sidebar can replace the panel.
  browser.runtime
    .sendMessage({ type: MSG.OPEN_URL, url, active: true })
    .catch(() => {
      browser.tabs.create({ url, active: true }).catch(() => {});
    });
}

async function copyText(text) {
  const value = text == null ? "" : String(text);
  if (!value) return false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch (_err) {
    /* fall through */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return Boolean(ok);
  } catch (_err2) {
    return false;
  }
}

if (els.btnImageOpen) {
  els.btnImageOpen.addEventListener("click", () => {
    if (currentImage) openUrl(currentImage.url);
  });
}
if (els.btnImageCopy) {
  els.btnImageCopy.addEventListener("click", async () => {
    if (!currentImage) return;
    const ok = await copyText(currentImage.url);
    if (els.imageEmpty) {
      /* brief status via badge title */
    }
    els.btnImageCopy.textContent = ok ? "Copied" : "Copy failed";
    setTimeout(() => {
      els.btnImageCopy.textContent = "Copy URL";
    }, 1200);
  });
}
if (els.btnImageLens) {
  els.btnImageLens.addEventListener("click", () => {
    if (currentImage) openUrl(reverseSearchUrls(currentImage.url).lens);
  });
}
if (els.btnImageYandex) {
  els.btnImageYandex.addEventListener("click", () => {
    if (currentImage) openUrl(reverseSearchUrls(currentImage.url).yandex);
  });
}
if (els.btnImageTineye) {
  els.btnImageTineye.addEventListener("click", () => {
    if (currentImage) openUrl(reverseSearchUrls(currentImage.url).tineye);
  });
}
if (els.btnImageForensics) {
  els.btnImageForensics.addEventListener("click", () => {
    if (currentImage) runImageForensics(currentImage.url);
  });
}
if (els.btnImageStegstruck) {
  els.btnImageStegstruck.addEventListener("click", () => {
    if (currentImage) runStegStruckScan(currentImage.url);
  });
}
if (els.btnImageHex) {
  els.btnImageHex.addEventListener("click", () => {
    if (currentImage) runImageHex(currentImage.url);
  });
}
if (els.btnImageSplit) {
  els.btnImageSplit.addEventListener("click", () => {
    if (currentImage) runImageHex(currentImage.url, { focusSplit: true });
  });
}
if (els.btnHexApply) {
  els.btnHexApply.addEventListener("click", () => {
    applyHexPatch();
  });
}
if (els.btnHexReset) {
  els.btnHexReset.addEventListener("click", () => {
    resetHexEdit();
  });
}
if (els.btnHexDownload) {
  els.btnHexDownload.addEventListener("click", () => {
    downloadPatchedHex();
  });
}
if (els.btnImageMeta) {
  els.btnImageMeta.addEventListener("click", () => {
    if (currentImage) runImageMeta(currentImage.url);
  });
}
if (els.btnImageCopyFallback) {
  els.btnImageCopyFallback.addEventListener("click", async () => {
    const url = lastForensicsUrl || (currentImage && currentImage.url) || "";
    if (!url) return;
    const ok = await copyText(url);
    els.btnImageCopyFallback.textContent = ok ? "Copied" : "Still failed — select URL above";
    if (ok) setImageForensicsStatus("URL copied", { showCopyFallback: false });
    setTimeout(() => {
      els.btnImageCopyFallback.textContent = "Copy image URL";
    }, 1400);
  });
}
if (els.btnOpenBlocked) {
  els.btnOpenBlocked.addEventListener("click", () => {
    for (const url of lastBlockedUrls) {
      openUrlInBackground(url);
    }
  });
}
if (els.btnImageProbe) {
  els.btnImageProbe.addEventListener("click", async () => {
    if (!currentImage) return;
    let token = "";
    try {
      const u = new URL(currentImage.url);
      const parts = u.pathname.split("/").filter(Boolean);
      let last = parts[parts.length - 1] || "";
      last = last.replace(/\.(jpe?g|png|gif|webp|bmp|svg|avif|ico)$/i, "");
      token = last;
    } catch (_err) {
      token = "";
    }
    if (!token || token.length < 4) {
      els.probeStatus.textContent = "Image filename does not look like a backlink ID.";
      focusProbePanel();
      return;
    }
    setProbeMode("id");
    els.probeInput.value = token;
    focusProbePanel();
    await startProbe();
  });
}

// ---------------------------------------------------------------------------
// Audio Asset
// ---------------------------------------------------------------------------

if (els.audioPreview) {
  els.audioPreview.addEventListener("error", () => {
    if (!els.audioPreview) return;
    const src = els.audioPreview.currentSrc || els.audioPreview.getAttribute("src") || "";
    if (!src) return;
    setAudioStatus("preview unavailable");
  });
}

if (els.btnAudioOpen) {
  els.btnAudioOpen.addEventListener("click", () => {
    if (currentAudio && currentAudio.url) openUrlInBackground(currentAudio.url);
  });
}

if (els.btnAudioCopy) {
  els.btnAudioCopy.addEventListener("click", async () => {
    const url = (currentAudio && currentAudio.url) || "";
    if (!url) {
      setAudioStatus("No URL to copy.");
      return;
    }
    const ok = await copyText(url);
    els.btnAudioCopy.textContent = ok ? "Copied" : "Copy failed";
    setTimeout(() => {
      els.btnAudioCopy.textContent = "Copy URL";
    }, 1400);
  });
}

if (els.btnAudioAnalyze) {
  els.btnAudioAnalyze.addEventListener("click", () => {
    if (!currentAudio) {
      setAudioStatus("Drop a file or capture an http(s) URL first.");
      return;
    }
    if (audioLocalBuffer) {
      runAudioAnalyze(audioLocalBuffer, audioLocalFilename || currentAudio.filename || "audio");
      return;
    }
    if (!currentAudio.url || !/^https?:\/\//i.test(currentAudio.url)) {
      setAudioStatus("Cannot fetch blob/file URL — drop the file below.");
      return;
    }
    runAudioAnalyze(currentAudio.url);
  });
}

if (els.btnAudioProbe) {
  els.btnAudioProbe.addEventListener("click", async () => {
    if (!currentAudio) return;
    let token = "";
    try {
      const src = currentAudio.url || currentAudio.filename || "";
      const u = new URL(src, "http://local/");
      const parts = u.pathname.split("/").filter(Boolean);
      let last = parts[parts.length - 1] || "";
      last = last.replace(/\.(mp3|wav|ogg|m4a|flac|aac|webm|opus)$/i, "");
      token = last;
    } catch (_err) {
      token = (currentAudio.filename || "").replace(/\.(mp3|wav|ogg|m4a|flac|aac|webm)$/i, "");
    }
    if (!token || token.length < 4) {
      setAudioStatus("Audio filename does not look like a backlink ID.");
      focusProbePanel();
      return;
    }
    setProbeMode("id");
    els.probeInput.value = token;
    focusProbePanel();
    await startProbe();
  });
}

const audioTools = audioDeepToolUrls();
function openAudioDeepTool(url) {
  // Persist before tabs.create → LIVE_ASSETS → pushState can race an empty store.
  if (currentAudio) persistAudioAsset(currentAudio);
  openUrlInBackground(url);
  setAudioStatus("Opens external tool — upload the file there manually");
}
if (els.btnAudioAudacity) {
  els.btnAudioAudacity.addEventListener("click", () => openAudioDeepTool(audioTools.audacity));
}
if (els.btnAudioSpectrum) {
  els.btnAudioSpectrum.addEventListener("click", () => openAudioDeepTool(audioTools.spectrum));
}
if (els.btnAudioMorse) {
  els.btnAudioMorse.addEventListener("click", () => openAudioDeepTool(audioTools.morse));
}
if (els.btnAudioSstv) {
  els.btnAudioSstv.addEventListener("click", () => openAudioDeepTool(audioTools.sstv));
}

if (els.audioFile) {
  els.audioFile.addEventListener("change", () => {
    const file = els.audioFile.files && els.audioFile.files[0];
    if (file) analyzeAudioLocally(file);
    els.audioFile.value = "";
  });
}

if (els.audioDrop) {
  ["dragenter", "dragover"].forEach((evt) => {
    els.audioDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      els.audioDrop.classList.add("is-dragover");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    els.audioDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (evt === "dragleave") els.audioDrop.classList.remove("is-dragover");
    });
  });
  els.audioDrop.addEventListener("drop", (e) => {
    els.audioDrop.classList.remove("is-dragover");
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) analyzeAudioLocally(file);
  });
  els.audioDrop.addEventListener("click", () => {
    if (els.audioFile) els.audioFile.click();
  });
  els.audioDrop.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (els.audioFile) els.audioFile.click();
    }
  });
}

// ---------------------------------------------------------------------------
// Archive / ZIP comment
// ---------------------------------------------------------------------------

function archiveHandOffText() {
  if (!currentArchive) return "";
  const comment = archiveCommentPayload(currentArchive);
  // Prefer hex-decoded password when that's the useful payload
  if (currentArchive.hexHint) return currentArchive.hexHint;
  return comment;
}

if (els.btnArchiveCopy) {
  els.btnArchiveCopy.addEventListener("click", async () => {
    const text = archiveCommentPayload(currentArchive);
    if (!text) {
      setArchiveStatus("No comment to copy.");
      return;
    }
    const ok = await copyText(text);
    setArchiveStatus(ok ? "Comment copied." : "Copy failed.");
  });
}

if (els.btnArchiveCipher) {
  els.btnArchiveCipher.addEventListener("click", () => {
    const text = archiveCommentPayload(currentArchive);
    if (!text) {
      setArchiveStatus("No comment to send.");
      return;
    }
    if (els.cipherInput) {
      els.cipherInput.value = text;
      renderCiphers(text);
    }
    browser.runtime.sendMessage({ type: MSG.CIPHER_INPUT, text }).catch(() => {});
    focusCipherPanel({ focusInput: true });
    setArchiveStatus(
      currentArchive && currentArchive.hexHint
        ? "Sent to Cipher (hex hint: " + currentArchive.hexHint + ")."
        : "Sent to Cipher Clipboard."
    );
  });
}

if (els.btnArchiveNotes) {
  els.btnArchiveNotes.addEventListener("click", () => {
    const text = archiveCommentPayload(currentArchive);
    if (!text) {
      setArchiveStatus("No comment to send.");
      return;
    }
    if (!els.notesInput) return;
    const cur = els.notesInput.value || "";
    const line =
      (currentArchive && currentArchive.filename
        ? "[" + currentArchive.filename + "] "
        : "") + text;
    els.notesInput.value = cur ? cur + "\n" + line : line;
    browser.storage.local.set({ [NOTES_KEY]: els.notesInput.value }).catch(() => {});
    focusPanel("panel-notes");
    setArchiveStatus("Appended to Notes.");
  });
}

if (els.btnArchiveProbe) {
  els.btnArchiveProbe.addEventListener("click", async () => {
    const text = archiveHandOffText() || archiveCommentPayload(currentArchive);
    if (!text) {
      setArchiveStatus("No comment to probe.");
      return;
    }
    const token = text.trim().slice(0, 200);
    setProbeMode("id");
    if (els.probeInput) els.probeInput.value = token;
    focusProbePanel();
    setArchiveStatus("Probing: " + token.slice(0, 48));
    await startProbe();
  });
}

async function onArchiveFileChosen(file) {
  if (!file) return;
  setArchiveStatus("Reading " + file.name + "…");
  try {
    const buffer = await file.arrayBuffer();
    await analyzeArchiveLocally(buffer, file.name || "archive.zip");
  } catch (err) {
    setArchiveStatus((err && err.message) || "Failed to read file");
  }
}

if (els.archiveFile) {
  els.archiveFile.addEventListener("change", () => {
    const file = els.archiveFile.files && els.archiveFile.files[0];
    onArchiveFileChosen(file);
    try {
      els.archiveFile.value = "";
    } catch (_err) {
      /* ignore */
    }
  });
}

if (els.archiveDrop) {
  ["dragenter", "dragover"].forEach((evt) => {
    els.archiveDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      els.archiveDrop.classList.add("is-dragover");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    els.archiveDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (evt === "dragleave") els.archiveDrop.classList.remove("is-dragover");
    });
  });
  els.archiveDrop.addEventListener("drop", (e) => {
    els.archiveDrop.classList.remove("is-dragover");
    const file =
      e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]
        ? e.dataTransfer.files[0]
        : null;
    onArchiveFileChosen(file);
  });
}

if (els.btnPinHunt) {
  els.btnPinHunt.addEventListener("click", async () => {
    try {
      const windowId = await currentWindowId();
      const res = await browser.runtime.sendMessage({
        type: MSG.PIN_HUNT_BASE,
        windowId,
      });
      if (res && res.ok) renderHuntBase(res.huntBase);
      else if (els.huntBaseLabel) {
        els.huntBaseLabel.textContent = (res && res.error) || "Pin failed";
        els.huntBaseLabel.classList.remove("is-pinned");
      }
    } catch (_err) {
      if (els.huntBaseLabel) {
        els.huntBaseLabel.textContent = "Pin failed";
        els.huntBaseLabel.classList.remove("is-pinned");
      }
    }
  });
}

if (els.btnClearHunt) {
  els.btnClearHunt.addEventListener("click", async () => {
    try {
      await browser.runtime.sendMessage({ type: MSG.CLEAR_HUNT_BASE });
      renderHuntBase(null);
    } catch (_err) {
      /* ignore */
    }
  });
}

els.rescan.addEventListener("click", async () => {
  els.scanStatus.textContent = "Scanning…";
  try {
    const windowId = await currentWindowId();
    const res = await browser.runtime.sendMessage({
      type: MSG.RESCAN,
      windowId,
    });
    els.scanStatus.textContent = res && res.ok ? "Scan requested." : (res && res.error) || "Scan failed.";
  } catch (_err) {
    els.scanStatus.textContent = "Cannot scan this page.";
  }
});

if (els.btnRobots) {
  els.btnRobots.addEventListener("click", () => {
    fetchSiteDiscovery().catch(() => {});
  });
}

els.cipherInput.addEventListener("input", () => {
  const text = els.cipherInput.value;
  renderCiphers(text);
  if (cipherTimer) clearTimeout(cipherTimer);
  cipherTimer = setTimeout(() => {
    browser.runtime.sendMessage({ type: MSG.CIPHER_INPUT, text }).catch(() => {});
  }, 300);
});

async function loadCipherAutoDecode() {
  if (!els.cipherAutoDecode) return;
  try {
    const bag = await browser.storage.local.get(CIPHER_AUTO_DECODE_KEY);
    const on =
      typeof bag[CIPHER_AUTO_DECODE_KEY] === "boolean"
        ? bag[CIPHER_AUTO_DECODE_KEY]
        : true;
    els.cipherAutoDecode.checked = on;
  } catch (_err) {
    els.cipherAutoDecode.checked = true;
  }
}

async function loadCipherRotN() {
  let n = 13;
  try {
    const bag = await browser.storage.local.get(CIPHER_ROT_N_KEY);
    if (typeof bag[CIPHER_ROT_N_KEY] === "number") {
      n = clampCipherRotN(bag[CIPHER_ROT_N_KEY]);
    } else if (typeof bag[CIPHER_ROT_N_KEY] === "string") {
      n = clampCipherRotN(bag[CIPHER_ROT_N_KEY]);
    }
  } catch (_err) {
    n = 13;
  }
  setCipherRotN(n, { persist: false });
}

function onCipherRotNChange(raw) {
  setCipherRotN(raw);
  if (els.cipherInput) renderCiphers(els.cipherInput.value);
}

function onCipherKeyChange() {
  if (els.cipherKey) setCipherSessionKey(els.cipherKey.value);
  if (els.cipherInput) renderCiphers(els.cipherInput.value);
}

if (els.cipherAutoDecode) {
  els.cipherAutoDecode.addEventListener("change", () => {
    const on = Boolean(els.cipherAutoDecode.checked);
    browser.storage.local.set({ [CIPHER_AUTO_DECODE_KEY]: on }).catch(() => {});
  });
}

if (els.cipherRotSlider) {
  els.cipherRotSlider.addEventListener("input", () => {
    onCipherRotNChange(els.cipherRotSlider.value);
  });
}
if (els.cipherRotN) {
  els.cipherRotN.addEventListener("input", () => {
    onCipherRotNChange(els.cipherRotN.value);
  });
  els.cipherRotN.addEventListener("change", () => {
    onCipherRotNChange(els.cipherRotN.value);
  });
}
if (els.cipherKey) {
  els.cipherKey.addEventListener("input", onCipherKeyChange);
}

// ---------------------------------------------------------------------------
// Notes — cryptic-hunt extraction + optional format; persists to storage.local
// ---------------------------------------------------------------------------

function notesSetStatus(text) {
  if (els.notesStatus) els.notesStatus.textContent = text || "";
}

function notesGetTarget() {
  const el = els.notesInput;
  if (!el) return { text: "", start: 0, end: 0, full: true };
  const value = el.value;
  const start = el.selectionStart;
  const end = el.selectionEnd;
  if (typeof start === "number" && typeof end === "number" && start !== end) {
    return { text: value.slice(start, end), start, end, full: false };
  }
  return { text: value, start: 0, end: value.length, full: true };
}

function notesApplyTransform(fn) {
  const el = els.notesInput;
  if (!el) return;
  const target = notesGetTarget();
  const next = fn(target.text);
  if (next === target.text) return;
  const before = el.value.slice(0, target.start);
  const after = el.value.slice(target.end);
  el.value = before + next + after;
  const caret = target.start + next.length;
  try {
    if (target.full) {
      el.setSelectionRange(0, el.value.length);
    } else {
      el.setSelectionRange(target.start, caret);
    }
  } catch (_err) {
    /* ignore */
  }
  el.focus({ preventScroll: true });
  scheduleNotesSave();
}

function notesTitleCase(text) {
  return text.replace(/\S+/g, (word) => {
    const letters = word.match(/[A-Za-zÀ-ÖØ-öø-ÿ]/);
    if (!letters) return word;
    let done = false;
    return word.replace(/[A-Za-zÀ-ÖØ-öø-ÿ]/g, (ch) => {
      if (done) return ch.toLowerCase();
      done = true;
      return ch.toUpperCase();
    });
  });
}

const NOTES_XFORMS = {
  upper: (t) => t.toUpperCase(),
  lower: (t) => t.toLowerCase(),
  title: notesTitleCase,
  trim: (t) => t.trim(),
  collapse: (t) => t.replace(/\s+/g, " ").trim(),
  reverse: (t) => Array.from(t).reverse().join(""),
  nospace: (t) => t.replace(/\s+/g, ""),
};

function notesCount(text) {
  const chars = text.length;
  const trimmed = text.trim();
  const words = trimmed ? trimmed.split(/\s+/).length : 0;
  const lines = text.length ? text.split(/\r\n|\r|\n/).length : 0;
  return { chars, words, lines };
}

/** Whitespace-delimited tokens for first/last letter puzzles. */
function notesWordTokens(text) {
  return text.match(/\S+/g) || [];
}

function notesFirstLetter(word) {
  const m = String(word).match(/[A-Za-z]/);
  return m ? m[0] : "";
}

function notesLastLetter(word) {
  const matches = String(word).match(/[A-Za-z]/g);
  return matches ? matches[matches.length - 1] : "";
}

/**
 * First integer at the start of each non-empty line → A1Z26 letters.
 * @param {string[]} lines
 * @returns {string}
 */
function notesA1Z26FromLineStarts(lines) {
  let out = "";
  for (const line of lines) {
    if (!String(line).trim()) continue;
    const m = String(line).match(/^\s*(\d+)/);
    if (!m) continue;
    const letter = a1z26LetterFromNumber(Number(m[1]));
    if (letter) out += letter;
  }
  return out;
}

/**
 * All integers in reading order; map 1–26 → letters, skip others.
 * @param {string} text
 * @returns {string}
 */
function notesA1Z26FromAllNumbers(text) {
  let out = "";
  for (const m of String(text).matchAll(/\d+/g)) {
    const letter = a1z26LetterFromNumber(Number(m[0]));
    if (letter) out += letter;
  }
  return out;
}

/**
 * Integer runs in reading order, joined with spaces — for decimal ASCII hunts
 * where noise, words, or line breaks sit between codes (#67#65#80, 32@21, etc.).
 * @param {string} text
 * @returns {string}
 */
function notesSpacedNumbers(text) {
  const source = String(text || "");
  if (/[#*]/.test(source)) {
    const codes = parseDecimalAsciiCodes(source);
    return codes ? codes.join(" ") : "";
  }
  const codes = [];
  for (const m of source.matchAll(/\d+/g)) {
    codes.push(...expandDecimalAsciiToken(m[0]));
  }
  return codes.join(" ");
}

/**
 * Cryptic-hunt style extractions. Returns candidates worth showing.
 * @param {string} text
 * @returns {{ id: string, label: string, value: string }[]}
 */
function notesAnalyzeHidden(text) {
  const source = String(text || "");
  if (!source.trim()) return [];

  const words = notesWordTokens(source);
  const lines = source.split(/\r\n|\r|\n/);

  const a1z26LineStarts = notesA1Z26FromLineStarts(lines);
  const a1z26AllNumbers = notesA1Z26FromAllNumbers(source);
  const spacedNumbers = notesSpacedNumbers(source);
  const capitals = (source.match(/[A-Z]/g) || []).join("");
  const firstLetters = words.map(notesFirstLetter).filter(Boolean).join("");
  const lastLetters = words.map(notesLastLetter).filter(Boolean).join("");
  const acrostic = lines
    .filter((line) => line.trim().length)
    .map((line) => {
      const trimmed = line.replace(/^\s+/, "");
      return trimmed.charAt(0) || "";
    })
    .join("");
  const lowercase = (source.match(/[a-z]/g) || []).join("");
  const digits = (source.match(/[0-9]/g) || []).join("");
  const inParens = Array.from(source.matchAll(/\(([^)]*)\)/g))
    .map((m) => (m[1].match(/[A-Za-z]/g) || []).join(""))
    .join("");

  /** @type {{ id: string, label: string, value: string }[]} */
  const raw = [
    // A1Z26 first so classic “numbers at line starts” clues surface prominently
    { id: "a1z26-lines", label: "A1Z26 (line starts)", value: a1z26LineStarts },
    { id: "a1z26-all", label: "A1Z26 (all numbers)", value: a1z26AllNumbers },
    { id: "spaced-numbers", label: "Spaced numbers", value: spacedNumbers },
    { id: "capitals", label: "Capitals", value: capitals },
    { id: "first", label: "First letters", value: firstLetters },
    { id: "last", label: "Last letters", value: lastLetters },
    { id: "acrostic", label: "Acrostic", value: acrostic },
    { id: "lowercase", label: "Lowercase", value: lowercase },
    { id: "digits", label: "Digits", value: digits },
    { id: "parens", label: "In parentheses", value: inParens },
  ];

  const seen = new Set();
  const out = [];
  for (const row of raw) {
    const value = row.value;
    if (!notesCandidateInteresting(row.id, value, source, words.length, lines.length)) {
      continue;
    }
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

function notesCandidateInteresting(id, value, source, wordCount, lineCount) {
  if (!value || value.length < 2) return false;

  const compact = source.replace(/\s+/g, "");
  // Identical to the whole blob (or compact blob) is not a "hidden" message.
  if (value === source.trim() || value === compact) return false;

  if (id === "capitals") {
    // Need mixed case to be meaningful as a hidden capitals message.
    return /[a-z]/.test(source) && /[A-Z]/.test(source);
  }
  if (id === "lowercase") {
    return /[A-Z]/.test(source) && /[a-z]/.test(source) && value.length >= 3;
  }
  if (id === "first" || id === "last") {
    return wordCount >= 2;
  }
  if (id === "acrostic") {
    return lineCount >= 2 && value.length >= 2;
  }
  if (id === "a1z26-lines") {
    return lineCount >= 2 && value.length >= 2;
  }
  if (id === "a1z26-all") {
    return value.length >= 2;
  }
  if (id === "spaced-numbers") {
    return value.trim().split(/\s+/).length >= 2;
  }
  if (id === "digits" || id === "parens") {
    return value.length >= 2;
  }
  return true;
}

function renderNotesResults(candidates) {
  if (!els.notesResults) return;
  els.notesResults.replaceChildren();
  notesAnalyzedCandidates = [];

  if (!candidates.length) {
    const empty = document.createElement("p");
    empty.className = "notes-results-empty";
    empty.textContent =
      "No hidden messages found — try text with mixed case, multiple words, or several lines.";
    els.notesResults.appendChild(empty);
    els.notesResults.hidden = false;
    return;
  }

  els.notesResults.hidden = false;
  notesAnalyzedCandidates = candidates.map((c) => c.value);

  for (const row of candidates) {
    const card = document.createElement("div");
    card.className = "notes-result";
    card.title = row.value;

    const head = document.createElement("div");
    head.className = "notes-result-head";

    const kind = document.createElement("span");
    kind.className = "notes-result-kind";
    kind.textContent = row.label;

    const acts = document.createElement("div");
    acts.className = "notes-result-acts";

    const toCipher = document.createElement("button");
    toCipher.type = "button";
    toCipher.className = "notes-result-act";
    toCipher.textContent = "Cipher";
    toCipher.title = "Send to Cipher Clipboard";
    toCipher.addEventListener("click", () => {
      sendNotesPayloadToCipher(row.value);
    });

    const toProbe = document.createElement("button");
    toProbe.type = "button";
    toProbe.className = "notes-result-act";
    toProbe.textContent = "Probe";
    toProbe.title = "Probe as Backlink ID";
    toProbe.addEventListener("click", () => {
      probeNotesToken(row.value);
    });

    acts.append(toCipher, toProbe);
    head.append(kind, acts);

    const label = document.createElement("button");
    label.type = "button";
    label.className = "notes-result-value";
    label.textContent = row.value;
    label.title = "Copy " + row.value;
    label.addEventListener("click", async () => {
      const ok = await copyText(row.value);
      notesSetStatus(ok ? "Copied: " + row.value.slice(0, 48) : "Copy failed.");
    });

    card.append(head, label);
    els.notesResults.appendChild(card);
  }
}

function scheduleNotesSave() {
  if (notesTimer) clearTimeout(notesTimer);
  notesTimer = setTimeout(() => {
    const text = els.notesInput ? els.notesInput.value : "";
    browser.storage.local.set({ [NOTES_KEY]: text }).catch(() => {});
  }, 300);
}

async function loadNotes() {
  if (!els.notesInput) return;
  try {
    const bag = await browser.storage.local.get(NOTES_KEY);
    if (typeof bag[NOTES_KEY] === "string") {
      els.notesInput.value = bag[NOTES_KEY];
    }
  } catch (_err) {
    /* ignore */
  }
}

function notesActivePayload() {
  const target = notesGetTarget();
  const selected = (target.full ? "" : target.text).trim();
  if (selected) return selected;
  if (notesAnalyzedCandidates.length) return notesAnalyzedCandidates[0];
  return (els.notesInput && els.notesInput.value.trim()) || "";
}

function sendNotesPayloadToCipher(text) {
  const payload = (text || "").trim();
  if (!payload) {
    notesSetStatus("Nothing to send — select text or Analyze first.");
    return;
  }
  if (els.cipherInput) {
    els.cipherInput.value = payload;
    renderCiphers(payload);
    browser.runtime.sendMessage({ type: MSG.CIPHER_INPUT, text: payload }).catch(() => {});
  }
  focusCipherPanel();
  notesSetStatus("Sent to Cipher Clipboard.");
}

async function probeNotesToken(text) {
  const token = (text || "").trim();
  if (!token) {
    notesSetStatus("Nothing to probe — select text or Analyze first.");
    return;
  }
  setProbeMode("id");
  if (els.probeInput) els.probeInput.value = token;
  focusProbePanel();
  notesSetStatus("Probing: " + token.slice(0, 48));
  await startProbe();
}

if (els.notesInput) {
  els.notesInput.addEventListener("input", () => {
    scheduleNotesSave();
  });
}

document.querySelectorAll(".notes-xform").forEach((btn) => {
  btn.addEventListener("click", () => {
    const id = btn.getAttribute("data-notes-xform");
    const fn = id && NOTES_XFORMS[id];
    if (!fn) return;
    notesApplyTransform(fn);
    notesSetStatus("Applied " + (btn.getAttribute("title") || id) + ".");
  });
});

if (els.btnNotesCount) {
  els.btnNotesCount.addEventListener("click", () => {
    const target = notesGetTarget();
    const c = notesCount(target.text);
    const scope = target.full ? "notes" : "selection";
    notesSetStatus(
      scope + ": " + c.chars + " chars · " + c.words + " words · " + c.lines + " lines"
    );
  });
}

if (els.btnNotesAnalyze) {
  els.btnNotesAnalyze.addEventListener("click", () => {
    const target = notesGetTarget();
    const candidates = notesAnalyzeHidden(target.text);
    renderNotesResults(candidates);
    const scope = target.full ? "notes" : "selection";
    notesSetStatus(
      candidates.length
        ? "Found " + candidates.length + " candidate(s) in " + scope + "."
        : "No hidden messages in " + scope + "."
    );
  });
}

if (els.btnNotesToCipher) {
  els.btnNotesToCipher.addEventListener("click", () => {
    sendNotesPayloadToCipher(notesActivePayload());
  });
}

if (els.btnNotesToProbe) {
  els.btnNotesToProbe.addEventListener("click", () => {
    probeNotesToken(notesActivePayload());
  });
}

browser.runtime.onMessage.addListener((message) => {
  if (!message || !message.type) return;

  if (message.type === MSG.CIPHER_INPUT) {
    if (typeof message.text === "string") {
      if (els.cipherInput && els.cipherInput.value !== message.text) {
        els.cipherInput.value = message.text;
        renderCiphers(message.text);
      }
    }
    if (message.focus !== false) {
      focusCipherPanel({ focusInput: !message.auto });
    }
    if (message.ingestToast) showIngestToast(message.ingestToast);
    if (message.appendNote) appendNoteLine(message.appendNote);
    return;
  }

  if (message.type === MSG.PROBE_PROGRESS || message.type === MSG.PROBE_RESULT) {
    if (message.probe) renderProbe(message.probe, { focus: true });
    return;
  }

  if (message.type === MSG.IMAGE_ASSET && message.imageAsset) {
    const pending = takePendingIngest(message.imageAsset.pendingIngest);
    renderImageAsset(message.imageAsset, { focus: message.focus !== false });
    if (message.ingestToast) showIngestToast(message.ingestToast);
    else if (pending && pending.toast) showIngestToast(pending.toast);
    const url = message.imageAsset.url || "";
    if (message.analyzeHex && /^https?:\/\//i.test(url)) {
      runImageHex(url);
    }
    if (message.imageAsset.pendingIngest) clearPendingIngest("image");
    return;
  }

  if (message.type === MSG.ARCHIVE_INFO && message.archiveInfo) {
    const pending = takePendingIngest(message.archiveInfo.pendingIngest);
    renderArchiveInfo(message.archiveInfo, { focus: message.focus !== false });
    if (message.ingestToast) showIngestToast(message.ingestToast);
    else if (pending && pending.toast) showIngestToast(pending.toast);
    if (message.archiveInfo.pendingIngest) clearPendingIngest("archive");
    return;
  }

  if (message.type === MSG.AUDIO_ASSET && message.audioAsset) {
    const pending = takePendingIngest(message.audioAsset.pendingIngest);
    renderAudioAsset(message.audioAsset, { focus: message.focus !== false });
    if (message.ingestToast) showIngestToast(message.ingestToast);
    else if (pending && pending.toast) showIngestToast(pending.toast);
    const url = message.audioAsset.url || "";
    if (message.analyze && /^https?:\/\//i.test(url)) {
      runAudioAnalyze(url);
    } else if (pending && pending.analyze && /^https?:\/\//i.test(url)) {
      runAudioAnalyze(url);
    }
    if (message.audioAsset.pendingIngest) clearPendingIngest("audio");
    return;
  }

  if (message.type === MSG.IMAGE_FORENSICS) {
    if (message.imageAsset) {
      renderImageAsset(message.imageAsset, { focus: true });
    }
    if (message.stegstruck) {
      const s = message.stegstruck;
      setImageForensicsStatus(
        s.ok
          ? "StegStruck opened · job " + (s.jobId || "")
          : s.error || "StegStruck failed",
        { showCopyFallback: false }
      );
      return;
    }
    const url = message.copyUrl || (message.imageAsset && message.imageAsset.url) || "";
    lastForensicsUrl = url;
    const n = typeof message.toolCount === "number" ? message.toolCount : 3;
    if (url) {
      copyText(url).then((copied) => {
        setImageForensicsStatus(
          copied
            ? "Opened " + n + " tools · URL copied"
            : "Opened " + n + " tools · copy failed — use Copy image URL",
          { showCopyFallback: !copied }
        );
      });
    } else {
      setImageForensicsStatus("Opened " + n + " tools");
    }
    return;
  }

  if (message.type === MSG.DNS_INPUT && message.domain) {
    if (els.dnsInput) els.dnsInput.value = message.domain;
    focusDnsPanel();
    return;
  }

  if (message.type === MSG.DNS_RESULT) {
    renderDnsResult(message);
    return;
  }

  if (message.type === MSG.GEOHASH_INPUT && message.text) {
    if (els.geohashInput) els.geohashInput.value = String(message.text).trim();
    focusGeohashPanel();
    resolveGeohashInput();
    return;
  }

  if (message.type === MSG.STATE) {
    applyState(message);
  }
});

// ---------------------------------------------------------------------------
// DNS Inspector
// ---------------------------------------------------------------------------

async function runDnsLookup() {
  if (!els.dnsInput) return;
  const domain = (els.dnsInput.value || "").trim();
  if (!domain) {
    if (els.dnsStatus) els.dnsStatus.textContent = "Enter a domain first.";
    return;
  }
  if (els.dnsStatus) els.dnsStatus.textContent = "Looking up…";
  if (els.btnDns) els.btnDns.disabled = true;
  try {
    const res = await browser.runtime.sendMessage({
      type: MSG.DNS_LOOKUP,
      domain,
    });
    if (res && !res.ok && res.error) {
      if (els.dnsStatus) els.dnsStatus.textContent = res.error;
    }
  } catch (_err) {
    if (els.dnsStatus) els.dnsStatus.textContent = "DNS lookup failed.";
  } finally {
    if (els.btnDns) els.btnDns.disabled = false;
  }
}

function renderDnsResult(msg) {
  focusDnsPanel();
  if (!els.dnsResults) return;
  els.dnsResults.replaceChildren();
  if (msg.domain && els.dnsInput && !els.dnsInput.matches(":focus")) {
    els.dnsInput.value = msg.domain;
  }
  if (!msg.ok) {
    if (els.dnsStatus) els.dnsStatus.textContent = msg.error || "Lookup failed.";
    if (els.badgeDns) els.badgeDns.textContent = "0";
    return;
  }
  const order = ["TXT", "A", "AAAA", "MX", "CNAME", "NS"];
  const records = msg.records || {};
  let count = 0;
  for (const type of order) {
    const rows = records[type] || [];
    if (!rows.length) continue;
    count += rows.length;
    const section = document.createElement("section");
    section.className = "group dns-group";
    const h = document.createElement("h2");
    h.textContent = type + " ";
    const c = document.createElement("span");
    c.className = "count";
    c.textContent = String(rows.length);
    h.appendChild(c);
    section.appendChild(h);
    const ul = document.createElement("ul");
    ul.className = "asset-list";
    for (const row of rows) {
      const li = document.createElement("li");
      li.className = "asset-item";
      const body = document.createElement("div");
      body.className = "preview mono";
      body.textContent = row.data;
      li.appendChild(body);
      const meta = document.createElement("div");
      meta.className = "meta-line";
      if (row.ttl != null) {
        const ttl = document.createElement("span");
        ttl.textContent = "TTL " + row.ttl;
        meta.appendChild(ttl);
      }
      meta.appendChild(copyButton(row.data));
      meta.appendChild(handoffButton("Cipher", () => sendTextToCipher(row.data)));
      meta.appendChild(
        handoffButton("Probe", () => {
          setProbeMode("id");
          els.probeInput.value = row.data.trim().slice(0, 200);
          focusProbePanel();
          startProbe();
        })
      );
      meta.appendChild(
        handoffButton("Notes", () => {
          if (!els.notesInput) return;
          const cur = els.notesInput.value || "";
          els.notesInput.value = cur ? cur + "\n" + row.data : row.data;
          persistNotesSoon();
          focusNotesPanel();
        })
      );
      li.appendChild(meta);
      ul.appendChild(li);
    }
    section.appendChild(ul);
    els.dnsResults.appendChild(section);
  }
  if (els.badgeDns) els.badgeDns.textContent = String(count);
  if (els.dnsStatus) {
    els.dnsStatus.textContent =
      count
        ? msg.domain + " — " + count + " record" + (count === 1 ? "" : "s") +
          (msg.error ? " (" + msg.error + ")" : "")
        : msg.domain + " — no records" + (msg.error ? " (" + msg.error + ")" : "");
  }
}

if (els.btnDns) {
  els.btnDns.addEventListener("click", () => runDnsLookup());
}
if (els.dnsInput) {
  els.dnsInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      runDnsLookup();
    }
  });
}

// ---------------------------------------------------------------------------
// Geohash / coordinates
// ---------------------------------------------------------------------------

const GEOHASH_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz";

function decodeGeohash(hash) {
  const s = String(hash || "")
    .trim()
    .toLowerCase();
  if (!s || !/^[0-9bcdefghjkmnpqrstuvwxyz]+$/i.test(s)) {
    return null;
  }
  let even = true;
  const latRange = [-90, 90];
  const lonRange = [-180, 180];
  for (let i = 0; i < s.length; i++) {
    const idx = GEOHASH_BASE32.indexOf(s[i]);
    if (idx < 0) return null;
    for (let bit = 4; bit >= 0; bit--) {
      const set = (idx >> bit) & 1;
      if (even) {
        const mid = (lonRange[0] + lonRange[1]) / 2;
        if (set) lonRange[0] = mid;
        else lonRange[1] = mid;
      } else {
        const mid = (latRange[0] + latRange[1]) / 2;
        if (set) latRange[0] = mid;
        else latRange[1] = mid;
      }
      even = !even;
    }
  }
  const lat = (latRange[0] + latRange[1]) / 2;
  const lon = (lonRange[0] + lonRange[1]) / 2;
  return {
    lat,
    lon,
    latErr: (latRange[1] - latRange[0]) / 2,
    lonErr: (lonRange[1] - lonRange[0]) / 2,
    hash: s,
  };
}

function parseLatLon(raw) {
  const m = String(raw || "")
    .trim()
    .match(/^(-?\d+(?:\.\d+)?)\s*[,;\s]\s*(-?\d+(?:\.\d+)?)$/);
  if (!m) return null;
  const lat = Number(m[1]);
  const lon = Number(m[2]);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null;
  return { lat, lon, latErr: 0, lonErr: 0, hash: "" };
}

function resolveGeohashInput() {
  if (!els.geohashInput || !els.geohashResults) return;
  const raw = (els.geohashInput.value || "").trim();
  els.geohashResults.replaceChildren();
  if (!raw) {
    if (els.geohashStatus) els.geohashStatus.textContent = "Paste a geohash or lat, lon.";
    return;
  }
  let resolved = parseLatLon(raw);
  if (!resolved) resolved = decodeGeohash(raw);
  if (!resolved) {
    if (els.geohashStatus) {
      els.geohashStatus.textContent = "Not a geohash or lat, lon pair.";
    }
    return;
  }
  const lat = resolved.lat;
  const lon = resolved.lon;
  if (els.geohashStatus) {
    els.geohashStatus.textContent = resolved.hash
      ? "Geohash " + resolved.hash
      : "Coordinates";
  }
  const coords = lat.toFixed(6) + ", " + lon.toFixed(6);
  const card = document.createElement("div");
  card.className = "geohash-card";
  const line = document.createElement("p");
  line.className = "mono";
  line.textContent = coords;
  card.appendChild(line);
  if (resolved.hash) {
    const err = document.createElement("p");
    err.className = "status-hint";
    err.textContent =
      "±" + resolved.latErr.toFixed(5) + " lat · ±" + resolved.lonErr.toFixed(5) + " lon";
    card.appendChild(err);
  }
  const actions = document.createElement("div");
  actions.className = "image-actions";
  const osm =
    "https://www.openstreetmap.org/?mlat=" +
    encodeURIComponent(String(lat)) +
    "&mlon=" +
    encodeURIComponent(String(lon)) +
    "#map=14/" +
    encodeURIComponent(String(lat)) +
    "/" +
    encodeURIComponent(String(lon));
  const gmaps =
    "https://www.google.com/maps?q=" +
    encodeURIComponent(String(lat) + "," + String(lon));
  const btnOsm = document.createElement("button");
  btnOsm.type = "button";
  btnOsm.className = "ghost-btn";
  btnOsm.textContent = "OpenStreetMap";
  btnOsm.addEventListener("click", () => openUrl(osm));
  const btnG = document.createElement("button");
  btnG.type = "button";
  btnG.className = "ghost-btn";
  btnG.textContent = "Google Maps";
  btnG.addEventListener("click", () => openUrl(gmaps));
  const btnCopy = document.createElement("button");
  btnCopy.type = "button";
  btnCopy.className = "ghost-btn";
  btnCopy.textContent = "Copy coords";
  btnCopy.addEventListener("click", async () => {
    const ok = await copyText(coords);
    btnCopy.textContent = ok ? "Copied" : "Fail";
    setTimeout(() => {
      btnCopy.textContent = "Copy coords";
    }, 1000);
  });
  const btnCipher = document.createElement("button");
  btnCipher.type = "button";
  btnCipher.className = "ghost-btn";
  btnCipher.textContent = "To Cipher";
  btnCipher.addEventListener("click", () => sendTextToCipher(coords));
  const btnNotes = document.createElement("button");
  btnNotes.type = "button";
  btnNotes.className = "ghost-btn";
  btnNotes.textContent = "To Notes";
  btnNotes.addEventListener("click", () => {
    if (!els.notesInput) return;
    const cur = els.notesInput.value || "";
    els.notesInput.value = cur ? cur + "\n" + coords : coords;
    persistNotesSoon();
    focusNotesPanel();
  });
  actions.append(btnOsm, btnG, btnCopy, btnCipher, btnNotes);
  card.appendChild(actions);
  els.geohashResults.appendChild(card);
}

if (els.btnGeohash) {
  els.btnGeohash.addEventListener("click", () => resolveGeohashInput());
}
if (els.geohashInput) {
  els.geohashInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      resolveGeohashInput();
    }
  });
}

setProbeMode("id");
initHelpTips();
initPanelReorder();
initPanelOpenPersistence();
loadPanelOrder();
loadPanelOpenState();
loadNotes();
loadAutoIngestToggle();
loadCipherAutoDecode();
loadCipherRotN().then(() => {
  if (els.cipherInput) renderCiphers(els.cipherInput.value);
});
requestState();
renderCiphers(els.cipherInput.value);
