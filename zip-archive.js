/**
 * Lightweight ZIP (and friends) inspection for Hunt Engine.
 * Shared by background.js and sidebar.js — no external library.
 */

"use strict";

const ZIP_ARCHIVE = (() => {
  const EOCD_SIG = [0x50, 0x4b, 0x05, 0x06];
  const CD_SIG = [0x50, 0x4b, 0x01, 0x02];
  const LOCAL_SIG = [0x50, 0x4b, 0x03, 0x04];
  const MAX_COMMENT = 0xffff;

  function readU16(bytes, off) {
    return bytes[off] | (bytes[off + 1] << 8);
  }

  function readU32(bytes, off) {
    return (
      (bytes[off] |
        (bytes[off + 1] << 8) |
        (bytes[off + 2] << 16) |
        (bytes[off + 3] << 24)) >>>
      0
    );
  }

  function matchSig(bytes, off, sig) {
    if (off + sig.length > bytes.length) return false;
    for (let i = 0; i < sig.length; i++) {
      if (bytes[off + i] !== sig[i]) return false;
    }
    return true;
  }

  function decodeUtf8(bytes, start, end) {
    try {
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(start, end));
    } catch (_err) {
      let s = "";
      for (let i = start; i < end; i++) s += String.fromCharCode(bytes[i]);
      return s;
    }
  }

  /**
   * Detect container format from magic / extension hint.
   * @param {Uint8Array} bytes
   * @param {string} [filename]
   */
  function detectFormat(bytes, filename) {
    const name = String(filename || "").toLowerCase();
    if (bytes.length >= 4 && matchSig(bytes, 0, LOCAL_SIG)) return "zip";
    if (bytes.length >= 4 && matchSig(bytes, 0, [0x50, 0x4b, 0x05, 0x06])) return "zip";
    if (bytes.length >= 4 && matchSig(bytes, 0, [0x50, 0x4b, 0x07, 0x08])) return "zip";
    if (bytes.length >= 4 && matchSig(bytes, 0, [0x52, 0x61, 0x72, 0x21])) return "rar";
    if (
      bytes.length >= 6 &&
      bytes[0] === 0x37 &&
      bytes[1] === 0x7a &&
      bytes[2] === 0xbc &&
      bytes[3] === 0xaf &&
      bytes[4] === 0x27 &&
      bytes[5] === 0x1c
    ) {
      return "7z";
    }
    if (/\.(zip|jar|apk|war|ear)$/i.test(name)) return "zip";
    if (/\.rar$/i.test(name)) return "rar";
    if (/\.7z$/i.test(name)) return "7z";
    return "unknown";
  }

  /**
   * Find End of Central Directory record offset, or -1.
   * @param {Uint8Array} bytes
   */
  function findEocd(bytes) {
    if (bytes.length < 22) return -1;
    const start = Math.max(0, bytes.length - (MAX_COMMENT + 22));
    for (let i = bytes.length - 22; i >= start; i--) {
      if (matchSig(bytes, i, EOCD_SIG)) {
        const commentLen = readU16(bytes, i + 20);
        if (i + 22 + commentLen <= bytes.length) return i;
      }
    }
    return -1;
  }

  /**
   * Walk central directory for encryption bit (GP bit 0).
   * Falls back to first local file header if CD walk fails.
   * @param {Uint8Array} bytes
   * @param {number} eocd
   */
  function detectEncryption(bytes, eocd) {
    const totalRecords = readU16(bytes, eocd + 10);
    const cdOffset = readU32(bytes, eocd + 16);
    let off = cdOffset;
    let sawEntry = false;

    for (let n = 0; n < totalRecords && off + 46 <= bytes.length; n++) {
      if (!matchSig(bytes, off, CD_SIG)) break;
      sawEntry = true;
      const flags = readU16(bytes, off + 8);
      if (flags & 0x0001) return true;
      const nameLen = readU16(bytes, off + 28);
      const extraLen = readU16(bytes, off + 30);
      const cmtLen = readU16(bytes, off + 32);
      off += 46 + nameLen + extraLen + cmtLen;
    }

    if (!sawEntry && matchSig(bytes, 0, LOCAL_SIG) && bytes.length >= 30) {
      const flags = readU16(bytes, 6);
      return Boolean(flags & 0x0001);
    }
    return false;
  }

  /**
   * @param {ArrayBuffer|Uint8Array} buffer
   * @param {{ filename?: string }} [opts]
   * @returns {{
   *   ok: boolean,
   *   format: string,
   *   supported: boolean,
   *   comment: string,
   *   encrypted: boolean|null,
   *   error: string|null
   * }}
   */
  function inspect(buffer, opts) {
    const bytes =
      buffer instanceof Uint8Array
        ? buffer
        : buffer instanceof ArrayBuffer
          ? new Uint8Array(buffer)
          : null;
    const filename = (opts && opts.filename) || "";

    if (!bytes || bytes.length === 0) {
      return {
        ok: false,
        format: "unknown",
        supported: false,
        comment: "",
        encrypted: null,
        error: "Empty file",
      };
    }

    const format = detectFormat(bytes, filename);

    if (format === "rar" || format === "7z") {
      return {
        ok: false,
        format,
        supported: false,
        comment: "",
        encrypted: null,
        error:
          format.toUpperCase() +
          " comments are not supported yet — ZIP / JAR / APK only",
      };
    }

    if (format !== "zip" && !matchSig(bytes, 0, LOCAL_SIG) && findEocd(bytes) < 0) {
      return {
        ok: false,
        format: format || "unknown",
        supported: false,
        comment: "",
        encrypted: null,
        error: "Not a ZIP archive (unsupported or corrupt)",
      };
    }

    const eocd = findEocd(bytes);
    if (eocd < 0) {
      return {
        ok: false,
        format: "zip",
        supported: true,
        comment: "",
        encrypted: null,
        error: "ZIP End of Central Directory not found",
      };
    }

    const commentLen = readU16(bytes, eocd + 20);
    const comment =
      commentLen > 0
        ? decodeUtf8(bytes, eocd + 22, eocd + 22 + commentLen)
        : "";

    let encrypted = false;
    try {
      encrypted = detectEncryption(bytes, eocd);
    } catch (_err) {
      encrypted = false;
    }

    return {
      ok: true,
      format: "zip",
      supported: true,
      comment,
      encrypted,
      error: null,
    };
  }

  /**
   * True when filename / mime looks like a ZIP-family download.
   * @param {string} filename
   * @param {string} [mime]
   */
  function isZipFamily(filename, mime) {
    const name = String(filename || "").toLowerCase();
    const m = String(mime || "").toLowerCase();
    if (/\.(zip|jar|apk|war|ear)$/i.test(name)) return true;
    if (
      m === "application/zip" ||
      m === "application/java-archive" ||
      m === "application/x-zip-compressed" ||
      m === "application/vnd.android.package-archive"
    ) {
      return true;
    }
    return false;
  }

  /**
   * True when we should attempt inspect (ZIP family or RAR/7z stub).
   * @param {string} filename
   * @param {string} [mime]
   */
  function isArchiveCandidate(filename, mime) {
    if (isZipFamily(filename, mime)) return true;
    const name = String(filename || "").toLowerCase();
    return /\.(rar|7z)$/i.test(name);
  }

  /**
   * If comment looks like hex, return decoded UTF-8 preview (or null).
   * @param {string} comment
   */
  function hexDecodeHint(comment) {
    const raw = String(comment || "").trim();
    if (!raw) return null;
    const hex = raw.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
    if (hex.length < 2 || hex.length % 2 !== 0) return null;
    // Prefer mostly-hex comments (avoid decoding random text with a few hex digits)
    const compact = raw.replace(/\s+/g, "");
    if (hex.length < compact.length * 0.85) return null;
    if (hex.length > 512) return null;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    const text = decodeUtf8(bytes, 0, bytes.length);
    // Printable-ish
    if (!/^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/.test(text) || !text.trim()) {
      return null;
    }
    return text;
  }

  return {
    inspect,
    isZipFamily,
    isArchiveCandidate,
    hexDecodeHint,
    detectFormat,
  };
})();

// Export for Node-less shared script load (background + sidebar).
if (typeof globalThis !== "undefined") {
  globalThis.ZIP_ARCHIVE = ZIP_ARCHIVE;
}
