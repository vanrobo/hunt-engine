/**
 * The Hunt Engine — local audio analysis (sidebar).
 * Spectrogram, Morse-from-audio, experimental SSTV (Scottie S1).
 */
"use strict";

(function mediaLocalFactory(root) {
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
  };

  function clamp(v, lo, hi) {
    return Math.max(lo, Math.min(hi, v));
  }

  function nextPow2(n) {
    let p = 1;
    while (p < n) p <<= 1;
    return p;
  }

  /** In-place radix-2 FFT magnitude bins (real input). */
  function fftMagnitudes(real, fftSize) {
    const n = fftSize;
    const re = new Float32Array(n);
    const im = new Float32Array(n);
    for (let i = 0; i < Math.min(real.length, n); i++) re[i] = real[i];
    // bit-reverse
    let j = 0;
    for (let i = 1; i < n; i++) {
      let bit = n >> 1;
      for (; j & bit; bit >>= 1) j ^= bit;
      j ^= bit;
      if (i < j) {
        const tr = re[i];
        re[i] = re[j];
        re[j] = tr;
      }
    }
    for (let len = 2; len <= n; len <<= 1) {
      const ang = (-2 * Math.PI) / len;
      const wlenRe = Math.cos(ang);
      const wlenIm = Math.sin(ang);
      for (let i = 0; i < n; i += len) {
        let wRe = 1;
        let wIm = 0;
        for (let k = 0; k < len / 2; k++) {
          const uRe = re[i + k];
          const uIm = im[i + k];
          const vRe = re[i + k + len / 2] * wRe - im[i + k + len / 2] * wIm;
          const vIm = re[i + k + len / 2] * wIm + im[i + k + len / 2] * wRe;
          re[i + k] = uRe + vRe;
          im[i + k] = uIm + vIm;
          re[i + k + len / 2] = uRe - vRe;
          im[i + k + len / 2] = uIm - vIm;
          const nwRe = wRe * wlenRe - wIm * wlenIm;
          wIm = wRe * wlenIm + wIm * wlenRe;
          wRe = nwRe;
        }
      }
    }
    const mags = new Float32Array(n / 2);
    for (let i = 0; i < n / 2; i++) {
      mags[i] = Math.sqrt(re[i] * re[i] + im[i] * im[i]);
    }
    return mags;
  }

  function hannWindow(n, i) {
    return 0.5 * (1 - Math.cos((2 * Math.PI * i) / Math.max(n - 1, 1)));
  }

  async function decodeToAudioBuffer(arrayBuffer) {
    const ctx = new (root.AudioContext || root.webkitAudioContext)();
    const copy = arrayBuffer.slice(0);
    const buf = await ctx.decodeAudioData(copy);
    ctx.close().catch(() => {});
    return buf;
  }

  /**
   * Draw spectrogram heatmap onto canvas.
   * @returns {{ ok: boolean, error?: string, duration?: number, sampleRate?: number }}
   */
  async function renderSpectrogram(arrayBuffer, canvas, options) {
    const opts = options || {};
    if (!canvas || !arrayBuffer) return { ok: false, error: "No audio or canvas" };
    try {
      const audioBuffer = await decodeToAudioBuffer(arrayBuffer);
      const channel = audioBuffer.getChannelData(0);
      const sampleRate = audioBuffer.sampleRate;
      const fftSize = opts.fftSize || 1024;
      const hop = opts.hop || 256;
      const maxSeconds = opts.maxSeconds || 120;
      const maxSamples = Math.min(channel.length, Math.floor(maxSeconds * sampleRate));
      const cols = Math.max(1, Math.floor((maxSamples - fftSize) / hop));
      const rows = fftSize / 2;

      const w = canvas.width;
      const h = canvas.height;
      const ctx = canvas.getContext("2d");
      if (!ctx) return { ok: false, error: "Canvas 2d unavailable" };

      const img = ctx.createImageData(w, h);
      const data = img.data;

      let maxMag = 1e-9;
      const grid = new Float32Array(cols * rows);

      for (let c = 0; c < cols; c++) {
        const start = c * hop;
        const slice = new Float32Array(fftSize);
        for (let i = 0; i < fftSize; i++) {
          const idx = start + i;
          slice[i] = idx < maxSamples ? channel[idx] * hannWindow(fftSize, i) : 0;
        }
        const mags = fftMagnitudes(slice, fftSize);
        for (let r = 0; r < rows; r++) {
          const v = mags[r];
          grid[c * rows + (rows - 1 - r)] = v;
          if (v > maxMag) maxMag = v;
        }
      }

      const colStep = cols / w;
      const rowStep = rows / h;
      for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
          const gc = Math.min(cols - 1, Math.floor(x * colStep));
          const gr = Math.min(rows - 1, Math.floor(y * rowStep));
          const v = grid[gc * rows + gr] / maxMag;
          const t = clamp(Math.log10(1 + v * 999) / 3, 0, 1);
          const idx = (y * w + x) * 4;
          // green-on-black hunt palette
          data[idx] = Math.floor(t * 40);
          data[idx + 1] = Math.floor(60 + t * 195);
          data[idx + 2] = Math.floor(t * 80);
          data[idx + 3] = 255;
        }
      }
      ctx.putImageData(img, 0, 0);
      return {
        ok: true,
        duration: audioBuffer.duration,
        sampleRate,
        columns: cols,
      };
    } catch (err) {
      return { ok: false, error: (err && err.message) || "Spectrogram failed" };
    }
  }

  function goertzelPower(samples, sampleRate, freq) {
    const n = samples.length;
    const k = Math.round((n * freq) / sampleRate);
    const w = (2 * Math.PI * k) / n;
    const coeff = 2 * Math.cos(w);
    let s0 = 0;
    let s1 = 0;
    let s2 = 0;
    for (let i = 0; i < n; i++) {
      s0 = samples[i] + coeff * s1 - s2;
      s2 = s1;
      s1 = s0;
    }
    return s1 * s1 + s2 * s2 - coeff * s1 * s2;
  }

  function bandpassEnvelope(channel, sampleRate, loHz, hiHz) {
    const win = Math.max(32, Math.floor(sampleRate / 200));
    const hop = Math.floor(win / 2);
    const out = [];
    for (let i = 0; i < channel.length - win; i += hop) {
      const slice = channel.subarray(i, i + win);
      let e = 0;
      for (let f = loHz; f <= hiHz; f += 50) {
        e += goertzelPower(slice, sampleRate, f);
      }
      out.push({ t: i / sampleRate, e: Math.sqrt(e) });
    }
    return out;
  }

  function decodeMorseFromEnvelope(env, sampleRate) {
    if (!env.length) return { ok: false, text: "", error: "Empty envelope" };
    const energies = env.map((p) => p.e);
    const maxE = Math.max.apply(null, energies);
    const thresh = maxE * 0.35;
    const states = energies.map((e) => (e >= thresh ? 1 : 0));

    const runs = [];
    let cur = states[0];
    let len = 1;
    for (let i = 1; i < states.length; i++) {
      if (states[i] === cur) len++;
      else {
        runs.push({ on: cur, len });
        cur = states[i];
        len = 1;
      }
    }
    runs.push({ on: cur, len });

    const onRuns = runs.filter((r) => r.on).map((r) => r.len);
    if (!onRuns.length) return { ok: false, text: "", error: "No tone bursts detected" };
    onRuns.sort((a, b) => a - b);
    const unit = onRuns[Math.floor(onRuns.length * 0.25)] || onRuns[0];

    let morse = "";
    let i = 0;
    while (i < runs.length) {
      const r = runs[i];
      if (!r.on) {
        if (r.len >= unit * 5) morse += " / ";
        else if (r.len >= unit * 2.5) morse += " ";
        i++;
        continue;
      }
      if (r.len < unit * 1.8) morse += ".";
      else morse += "-";
      i++;
    }

    const words = morse.split(" / ");
    const decoded = [];
    for (const word of words) {
      const letters = word.trim().split(/\s+/).filter(Boolean);
      const chars = letters.map((tok) => MORSE_TABLE[tok] || "?").join("");
      decoded.push(chars);
    }
    const text = decoded.join(" ").replace(/\?+/g, "?").trim();
    return {
      ok: text.length > 0 && !/^\?+$/.test(text),
      text,
      raw: morse.trim(),
      unitMs: Math.round((unit * (env[1] ? env[1].t - env[0].t : 0.01)) * 1000),
    };
  }

  async function decodeMorseFromAudio(arrayBuffer) {
    try {
      const audioBuffer = await decodeToAudioBuffer(arrayBuffer);
      const channel = audioBuffer.getChannelData(0);
      const env = bandpassEnvelope(channel, audioBuffer.sampleRate, 400, 1400);
      return decodeMorseFromEnvelope(env, audioBuffer.sampleRate);
    } catch (err) {
      return { ok: false, text: "", error: (err && err.message) || "Morse decode failed" };
    }
  }

  /** Experimental Scottie S1 SSTV — frequency → pixel (1500–2300 Hz). */
  async function decodeSstvScottieS1(arrayBuffer, canvas) {
    if (!canvas || !arrayBuffer) return { ok: false, error: "No audio or canvas" };
    try {
      const audioBuffer = await decodeToAudioBuffer(arrayBuffer);
      const channel = audioBuffer.getChannelData(0);
      const sr = audioBuffer.sampleRate;
      const width = 320;
      const height = 256;
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) return { ok: false, error: "Canvas 2d unavailable" };

      const img = ctx.createImageData(width, height);
      const px = img.data;
      const spb = Math.floor(sr / 9000);
      const win = Math.max(64, spb * 4);
      let pos = Math.floor(sr * 0.4);

      function freqAt(p) {
        if (p + win >= channel.length) return 0;
        const slice = channel.subarray(p, p + win);
        const f0 = goertzelPower(slice, sr, 1200);
        const f1 = goertzelPower(slice, sr, 1500);
        const f2 = goertzelPower(slice, sr, 1900);
        const f3 = goertzelPower(slice, sr, 2300);
        const max = Math.max(f0, f1, f2, f3);
        if (max === f0) return 1200;
        if (max === f1) return 1500;
        if (max === f2) return 1900;
        return 2300;
      }

      for (let y = 0; y < height; y++) {
        while (pos + win < channel.length && freqAt(pos) < 1300) pos += spb;
        pos += spb * 8;
        for (let x = 0; x < width; x++) {
          const f = freqAt(pos);
          let lum = 0;
          if (f >= 1500) lum = clamp(((f - 1500) / 800) * 255, 0, 255);
          const i = (y * width + x) * 4;
          px[i] = lum;
          px[i + 1] = lum;
          px[i + 2] = lum;
          px[i + 3] = 255;
          pos += spb;
        }
        pos += spb * 16;
      }
      ctx.putImageData(img, 0, 0);
      return { ok: true, mode: "Scottie S1 (experimental)", width, height };
    } catch (err) {
      return { ok: false, error: (err && err.message) || "SSTV decode failed" };
    }
  }

  const api = {
    renderSpectrogram,
    decodeMorseFromAudio,
    decodeSstvScottieS1,
    decodeToAudioBuffer,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.MediaLocal = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : this);
