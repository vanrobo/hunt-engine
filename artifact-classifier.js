/**
 * The Hunt Engine — artifact classifier (shared).
 * Pattern-based mechanic tags for cryptic / OSINT hunts. No hunt-specific spoilers.
 */
"use strict";

(function artifactClassifierFactory(root) {
  const ZERO_WIDTH_RE =
    /[\u200B\u200C\u200D\u2060\uFEFF\u180E\u200E\u200F\u2061\u2062\u2063\u2064]/;

  const HTML_COMMENT_RE = /^\s*<!--[\s\S]*?-->\s*$/;
  const HEX_BLOB_RE = /^(?:[0-9a-fA-F]{2}\s*){8,}$|^(?:0x)?[0-9a-fA-F]{16,}$/;
  const BASE64_RE = /[A-Za-z0-9+/]{16,}={0,2}/;
  const HUNT_SLUG_RE = /^[A-Za-z0-9_-]{2,64}$/;
  const DOMAIN_RE =
    /^(?:https?:\/\/)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?:\/|$|\s)/i;
  const MORSE_LIKE_RE = /^[\s.\-·−_\/\\0-1]{6,}$/;
  const HODOR_RE = /\b[hH][oO][dD][oO][rR]/;
  const PASTEBIN_ID_RE = /^[a-zA-Z0-9]{8}$/;
  const ISBN_RE =
    /^(?:ISBN[- ]*)?(?:97[89][- ]?)?(?:\d[- ]?){9}[\dXx]$/i;

  const STOPWORDS = new Set([
    "the",
    "and",
    "for",
    "are",
    "but",
    "not",
    "you",
    "all",
    "can",
    "had",
    "her",
    "was",
    "one",
    "our",
    "out",
    "has",
    "have",
    "this",
    "that",
    "with",
    "from",
    "they",
    "been",
    "have",
    "will",
    "your",
    "what",
    "when",
    "where",
    "which",
    "who",
    "how",
  ]);

  const TAG_LABELS = {
    html_comment: "HTML comment",
    zero_width: "Zero-width",
    base64: "Base64",
    hex_blob: "Hex blob",
    hunt_slug: "Hunt slug",
    paste_id: "Paste ID",
    paste_url: "Paste URL",
    geohash: "Geohash",
    coordinates: "Coordinates",
    domain: "Domain",
    morse: "Morse-like",
    hodor_cipher: "HODOR cipher",
    uuid: "UUID",
    snowflake: "Discord snowflake",
    youtube_id: "YouTube ID",
    isbn: "ISBN",
    video_url: "Video URL",
    archive_url: "Archive.org",
    flag_shape: "Flag-shaped",
    id_pattern: "ID pattern",
    confirmed_hunt_hit: "Hunt hit",
  };

  const ACTION_LABELS = {
    cipher: "Cipher",
    notes: "Notes",
    probe: "Probe",
    probe_hunt: "Probe hunt site",
    dns: "DNS",
    geohash: "Geohash",
    paste: "Paste panel",
    id_router: "ID router",
    video: "Video lane",
    archive: "Archive helper",
    source_scan: "Scan source",
    hodor: "Open in dCode",
    zw_decode: "Strip ZW",
  };

  function isLikelyBase64(text) {
    const t = String(text || "").trim();
    if (t.length < 16) return false;
    if (!/^[A-Za-z0-9+/=\s]+$/.test(t)) return false;
    const compact = t.replace(/\s/g, "");
    if (compact.length % 4 === 1) return false;
    return /={0,2}$/.test(compact) || compact.length >= 20;
  }

  function looksLikeGeohash(text) {
    const s = String(text || "")
      .trim()
      .toLowerCase();
    return /^[0-9bcdefghjkmnpqrstuvwxyz]{4,12}$/.test(s);
  }

  function looksLikeLatLon(text) {
    return /^-?\d+(?:\.\d+)?\s*[,;\s]\s*-?\d+(?:\.\d+)?$/.test(String(text || "").trim());
  }

  function looksLikeHodor(text) {
    const t = String(text || "");
    if (!HODOR_RE.test(t)) return false;
    const words = t.split(/\s+/).filter(Boolean);
    if (words.length < 2) return false;
    let hodorish = 0;
    for (const w of words) {
      if (/[hH][oO][dD][oO][rR]/.test(w)) hodorish++;
    }
    return hodorish / words.length >= 0.4;
  }

  function looksLikeMorse(text) {
    const t = String(text || "").trim();
    if (!MORSE_LIKE_RE.test(t)) return false;
    return /[.\-·−]/.test(t);
  }

  function extractDomain(text) {
    const m = String(text || "").trim().match(DOMAIN_RE);
    return m ? m[1].toLowerCase() : null;
  }

  function isPasteHost(urlOrHost) {
    const s = String(urlOrHost || "").toLowerCase();
    return (
      s.includes("pastebin.com") ||
      s.includes("controlc.com") ||
      s.includes("rentry.co") ||
      s.includes("rentry.org") ||
      s.includes("hastebin.com") ||
      s.includes("paste.ee") ||
      s.includes("telegra.ph") ||
      s.includes("gist.github.com") ||
      s.includes("write.as") ||
      s.includes("dpaste.com") ||
      s.includes("justpaste.it")
    );
  }

  function pushTag(out, type, confidence, actions, meta) {
    if (out.some((t) => t.type === type)) return;
    out.push({
      type,
      label: TAG_LABELS[type] || type,
      confidence,
      actions: actions.slice(),
      meta: meta || null,
    });
  }

  /**
   * @param {string} raw
   * @param {{ source?: string, hasHuntBase?: boolean, confirmedHit?: boolean, idMatches?: Array<object> }} ctx
   */
  function classifyArtifact(raw, ctx) {
    const context = ctx || {};
    const text = String(raw || "").trim();
    const out = [];
    if (!text) return out;

    if (context.confirmedHit) {
      pushTag(out, "confirmed_hunt_hit", "sure", ["probe_hunt", "notes"]);
    }

    if (HTML_COMMENT_RE.test(text) || context.source === "comment") {
      pushTag(out, "html_comment", "sure", ["notes", "probe_hunt", "source_scan"]);
    }

    if (ZERO_WIDTH_RE.test(text)) {
      pushTag(out, "zero_width", "sure", ["zw_decode", "cipher", "notes"]);
    }

    if (isLikelyBase64(text)) {
      pushTag(out, "base64", text.endsWith("=") ? "sure" : "maybe", ["cipher"]);
    }

    if (HEX_BLOB_RE.test(text.replace(/\s/g, ""))) {
      pushTag(out, "hex_blob", "maybe", ["cipher"]);
    }

    if (looksLikeLatLon(text)) {
      pushTag(out, "coordinates", "sure", ["geohash", "notes"]);
    } else if (looksLikeGeohash(text)) {
      pushTag(out, "geohash", "sure", ["geohash", "notes"]);
    }

    if (looksLikeHodor(text)) {
      pushTag(out, "hodor_cipher", "sure", ["dcode", "cipher", "notes"]);
    }

    if (looksLikeMorse(text)) {
      pushTag(out, "morse", "maybe", ["cipher"]);
    }

    if (/^https?:\/\//i.test(text)) {
      const lower = text.toLowerCase();
      if (
        lower.includes("youtube.com") ||
        lower.includes("youtu.be") ||
        lower.includes("vimeo.com") ||
        lower.includes("dailymotion.com")
      ) {
        pushTag(out, "video_url", "sure", ["video", "probe"]);
      }
      if (lower.includes("archive.org/details/")) {
        pushTag(out, "archive_url", "sure", ["archive", "notes"]);
      }
      if (isPasteHost(text)) {
        pushTag(out, "paste_url", "sure", ["paste", "probe"]);
      }
    } else if (isPasteHost(text)) {
      pushTag(out, "paste_url", "maybe", ["paste", "probe"]);
    }

    const domainOnly = extractDomain(text);
    if (domainOnly && !/\//.test(text.replace(/^https?:\/\//i, ""))) {
      pushTag(out, "domain", "sure", ["dns"]);
    }

    if (PASTEBIN_ID_RE.test(text) && !STOPWORDS.has(text.toLowerCase())) {
      pushTag(out, "paste_id", "maybe", ["paste", "probe"]);
    }

    if (ISBN_RE.test(text.replace(/\s/g, ""))) {
      pushTag(out, "isbn", "sure", ["id_router", "archive", "notes"]);
    }

    if (/^CTF\{|\bFLAG\{|picoCTF\{/i.test(text)) {
      pushTag(out, "flag_shape", "sure", ["cipher", "notes"]);
    }

    if (HUNT_SLUG_RE.test(text) && !/\s/.test(text)) {
      const lower = text.toLowerCase();
      const conf =
        context.hasHuntBase && !STOPWORDS.has(lower) && /\d|[A-Z_-]/.test(text)
          ? "sure"
          : STOPWORDS.has(lower)
            ? "maybe"
            : "maybe";
      pushTag(out, "hunt_slug", conf, ["probe_hunt", "probe"]);
    }

    if (context.idMatches && context.idMatches.length) {
      pushTag(out, "id_pattern", "sure", ["id_router", "probe"]);
    }

    return out.sort((a, b) => {
      const rank = { sure: 0, maybe: 1 };
      return (rank[a.confidence] || 2) - (rank[b.confidence] || 2);
    });
  }

  function stripZeroWidth(text) {
    return String(text || "").replace(
      /[\u200B\u200C\u200D\u2060\uFEFF\u180E\u200E\u200F\u2061\u2062\u2063\u2064]/g,
      ""
    );
  }

  const api = {
    classifyArtifact,
    stripZeroWidth,
    TAG_LABELS,
    ACTION_LABELS,
    isLikelyBase64,
    looksLikeGeohash,
    looksLikeHodor,
    looksLikeMorse,
    isPasteHost,
    STOPWORDS,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ArtifactClassifier = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : this);
