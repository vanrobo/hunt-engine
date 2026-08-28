/**
 * The Hunt Engine — local image forensics (sidebar).
 * ELA, LSB bit planes, RGB channel split.
 */
"use strict";

(function imageLocalFactory(root) {
  let elaCache = null;

  function loadImageFromBlob(blob) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(url);
        resolve(img);
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Image decode failed"));
      };
      img.src = url;
    });
  }

  async function fetchImageBlob(url) {
    const res = await fetch(url, { credentials: "omit", cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.blob();
  }

  async function loadImageSource(urlOrBlob) {
    if (urlOrBlob instanceof Blob) return loadImageFromBlob(urlOrBlob);
    const blob = await fetchImageBlob(String(urlOrBlob));
    return loadImageFromBlob(blob);
  }

  function sourceKey(urlOrBlob) {
    if (urlOrBlob instanceof Blob) {
      return "blob:" + urlOrBlob.size + ":" + (urlOrBlob.type || "");
    }
    return "url:" + String(urlOrBlob);
  }

  function copyImageData(data) {
    return new Uint8ClampedArray(data.data);
  }

  async function buildResavedData(drawCanvas, tw, th, quality) {
    const jpegBlob = await new Promise((resolve, reject) => {
      drawCanvas.toBlob(
        (b) => (b ? resolve(b) : reject(new Error("JPEG export failed"))),
        "image/jpeg",
        quality
      );
    });
    const reImg = await loadImageFromBlob(jpegBlob);
    const c2 = document.createElement("canvas");
    c2.width = tw;
    c2.height = th;
    const x2 = c2.getContext("2d");
    x2.drawImage(reImg, 0, 0, tw, th);
    return copyImageData(x2.getImageData(0, 0, tw, th));
  }

  function paintElaDiff(canvas, srcData, resavedData, amplify) {
    const tw = canvas.width;
    const th = canvas.height;
    const ctx = canvas.getContext("2d");
    const out = ctx.createImageData(tw, th);
    const amp = amplify == null ? 8 : amplify;
    for (let i = 0; i < srcData.length; i += 4) {
      const dr = Math.abs(srcData[i] - resavedData[i]);
      const dg = Math.abs(srcData[i + 1] - resavedData[i + 1]);
      const db = Math.abs(srcData[i + 2] - resavedData[i + 2]);
      const d = Math.max(dr, dg, db) * amp;
      const v = d > 255 ? 255 : d;
      out.data[i] = v;
      out.data[i + 1] = v;
      out.data[i + 2] = v;
      out.data[i + 3] = 255;
    }
    ctx.putImageData(out, 0, 0);
  }

  async function ensureElaCache(urlOrBlob, options) {
    const opts = options || {};
    const quality = opts.quality == null ? 0.92 : opts.quality;
    const key = sourceKey(urlOrBlob);
    const needSource = !elaCache || elaCache.key !== key;

    if (needSource) {
      const img = await loadImageSource(urlOrBlob);
      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      const maxDim = opts.maxDim || 800;
      const scale = Math.min(1, maxDim / Math.max(w, h));
      const tw = Math.max(1, Math.floor(w * scale));
      const th = Math.max(1, Math.floor(h * scale));

      const c1 = document.createElement("canvas");
      c1.width = tw;
      c1.height = th;
      const x1 = c1.getContext("2d");
      x1.drawImage(img, 0, 0, tw, th);

      let srcData;
      try {
        srcData = copyImageData(x1.getImageData(0, 0, tw, th));
      } catch (_err) {
        throw new Error("Canvas tainted — drop file or use CORS-friendly URL");
      }

      elaCache = {
        key,
        tw,
        th,
        drawCanvas: c1,
        srcData,
        quality,
        resavedData: await buildResavedData(c1, tw, th, quality),
      };
    } else if (elaCache.quality !== quality) {
      elaCache.quality = quality;
      elaCache.resavedData = await buildResavedData(
        elaCache.drawCanvas,
        elaCache.tw,
        elaCache.th,
        quality
      );
    }
    return elaCache;
  }

  /**
   * Error Level Analysis — re-save JPEG at chosen quality and diff (with sliders).
   */
  async function renderEla(urlOrBlob, canvas, options) {
    const opts = options || {};
    const quality = opts.quality == null ? 0.92 : opts.quality;
    const amplify = opts.amplify == null ? 8 : opts.amplify;
    if (!canvas) return { ok: false, error: "No canvas" };
    try {
      const cache = await ensureElaCache(urlOrBlob, opts);
      canvas.width = cache.tw;
      canvas.height = cache.th;
      paintElaDiff(canvas, cache.srcData, cache.resavedData, amplify);
      return {
        ok: true,
        width: cache.tw,
        height: cache.th,
        quality: Math.round(quality * 100),
        amplify,
        note: "Tune JPEG quality + error scale like Forensically. Best on JPEG sources.",
      };
    } catch (err) {
      return { ok: false, error: (err && err.message) || "ELA failed" };
    }
  }

  /** Re-paint from cache when only the error-scale slider moves. */
  async function repaintEla(canvas, options) {
    const opts = options || {};
    if (!elaCache || !canvas) {
      return { ok: false, error: "Run ELA first" };
    }
    const quality = opts.quality == null ? elaCache.quality : opts.quality;
    const amplify = opts.amplify == null ? 8 : opts.amplify;
    try {
      if (elaCache.quality !== quality) {
        elaCache.quality = quality;
        elaCache.resavedData = await buildResavedData(
          elaCache.drawCanvas,
          elaCache.tw,
          elaCache.th,
          quality
        );
      }
      canvas.width = elaCache.tw;
      canvas.height = elaCache.th;
      paintElaDiff(canvas, elaCache.srcData, elaCache.resavedData, amplify);
      return { ok: true, width: elaCache.tw, height: elaCache.th, quality, amplify };
    } catch (err) {
      return { ok: false, error: (err && err.message) || "ELA repaint failed" };
    }
  }

  function clearElaCache() {
    elaCache = null;
  }

  function renderBitPlane(img, canvas, channel, bit) {
    const w = img.naturalWidth || img.width;
    const h = img.naturalHeight || img.height;
    const maxDim = 480;
    const scale = Math.min(1, maxDim / Math.max(w, h));
    const tw = Math.max(1, Math.floor(w * scale));
    const th = Math.max(1, Math.floor(h * scale));
    const c = document.createElement("canvas");
    c.width = tw;
    c.height = th;
    const x = c.getContext("2d");
    x.drawImage(img, 0, 0, tw, th);
    const data = x.getImageData(0, 0, tw, th);
    const chMap = { r: 0, g: 1, b: 2 };
    const ci = chMap[channel] != null ? chMap[channel] : 0;
    const mask = 1 << bit;
    canvas.width = tw;
    canvas.height = th;
    const ctx = canvas.getContext("2d");
    const out = ctx.createImageData(tw, th);
    for (let i = 0; i < data.data.length; i += 4) {
      const on = data.data[i + ci] & mask ? 255 : 0;
      out.data[i] = on;
      out.data[i + 1] = on;
      out.data[i + 2] = on;
      out.data[i + 3] = 255;
    }
    ctx.putImageData(out, 0, 0);
    return { width: tw, height: th };
  }

  async function renderLsb(urlOrBlob, container) {
    if (!container) return { ok: false, error: "No container" };
    try {
      const img = await loadImageSource(urlOrBlob);
      container.replaceChildren();
      const channels = ["r", "g", "b"];
      for (const ch of channels) {
        for (let bit = 0; bit < 2; bit++) {
          const wrap = document.createElement("div");
          wrap.className = "local-img-tile";
          const label = document.createElement("p");
          label.className = "status-hint";
          label.textContent = ch.toUpperCase() + " bit " + bit;
          const cv = document.createElement("canvas");
          cv.className = "local-tool-canvas";
          renderBitPlane(img, cv, ch, bit);
          wrap.append(label, cv);
          container.appendChild(wrap);
        }
      }
      return { ok: true };
    } catch (err) {
      return { ok: false, error: (err && err.message) || "LSB failed" };
    }
  }

  async function renderChannelSplit(urlOrBlob, container) {
    if (!container) return { ok: false, error: "No container" };
    try {
      const img = await loadImageSource(urlOrBlob);
      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      const maxDim = 360;
      const scale = Math.min(1, maxDim / Math.max(w, h));
      const tw = Math.max(1, Math.floor(w * scale));
      const th = Math.max(1, Math.floor(h * scale));
      container.replaceChildren();
      const names = [
        { label: "Red", fn: (d, o, i) => { o[i]=d[i]; o[i+1]=0; o[i+2]=0; } },
        { label: "Green", fn: (d, o, i) => { o[i]=0; o[i+1]=d[i+1]; o[i+2]=0; } },
        { label: "Blue", fn: (d, o, i) => { o[i]=0; o[i+1]=0; o[i+2]=d[i+2]; } },
      ];
      const c = document.createElement("canvas");
      c.width = tw;
      c.height = th;
      const x = c.getContext("2d");
      x.drawImage(img, 0, 0, tw, th);
      const data = x.getImageData(0, 0, tw, th);
      for (const spec of names) {
        const wrap = document.createElement("div");
        wrap.className = "local-img-tile";
        const label = document.createElement("p");
        label.className = "status-hint";
        label.textContent = spec.label;
        const cv = document.createElement("canvas");
        cv.className = "local-tool-canvas";
        cv.width = tw;
        cv.height = th;
        const ctx = cv.getContext("2d");
        const out = ctx.createImageData(tw, th);
        for (let i = 0; i < data.data.length; i += 4) {
          spec.fn(data.data, out.data, i);
          out.data[i + 3] = 255;
        }
        ctx.putImageData(out, 0, 0);
        wrap.append(label, cv);
        container.appendChild(wrap);
      }
      return { ok: true };
    } catch (err) {
      return { ok: false, error: (err && err.message) || "Channel split failed" };
    }
  }

  const api = {
    renderEla,
    repaintEla,
    clearElaCache,
    renderLsb,
    renderChannelSplit,
    loadImageSource,
    fetchImageBlob,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ImageLocal = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : this);
