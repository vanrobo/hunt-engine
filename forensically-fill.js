/**
 * Hunt Engine — load captured images into Forensically (29a.ch) automatically.
 */
"use strict";

const FILL_KEY = "huntForensicsPending";
const MAX_AGE_MS = 120000;

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function loadImageFile(file, tool) {
  const inputs = document.querySelectorAll('input[type="file"][accept*="image"]');
  const input = inputs[0] || document.querySelector('input[type="file"]');
  if (!input) return false;
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  if (tool) {
    const hash = tool.startsWith("#") ? tool : "#forensic-" + tool;
    if (location.hash !== hash) location.hash = hash;
  }
  return true;
}

function tryConsumePending() {
  browser.storage.session.get(FILL_KEY).then((bag) => {
    const p = bag[FILL_KEY];
    if (!p || !p.base64) return;
    if (Date.now() - (p.ts || 0) > MAX_AGE_MS) return;
    const bytes = b64ToBytes(p.base64);
    const file = new File([bytes], p.filename || "hunt-image.jpg", {
      type: p.mime || "image/jpeg",
    });
    if (loadImageFile(file, p.tool)) {
      browser.storage.session.remove(FILL_KEY).catch(() => {});
    }
  });
}

browser.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== "HUNT_FORENSICALLY_LOAD") return;
  try {
    const bytes = msg.base64 ? b64ToBytes(msg.base64) : null;
    if (!bytes || !bytes.length) return Promise.resolve({ ok: false, error: "empty image" });
    const file = new File([bytes], msg.filename || "hunt-image.jpg", {
      type: msg.mime || "image/jpeg",
    });
    return Promise.resolve({ ok: loadImageFile(file, msg.tool) });
  } catch (err) {
    return Promise.resolve({ ok: false, error: (err && err.message) || "load failed" });
  }
});

function boot() {
  tryConsumePending();
  [300, 800, 1500, 3000].forEach((ms) => setTimeout(tryConsumePending, ms));
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
