/**
 * Hunt Engine — fill dCode.fr tool inputs when opened from the sidebar.
 */
"use strict";

const FILL_KEY = "huntDcodePending";
const MAX_AGE_MS = 120000;

const Logic = typeof HuntDcodeFillLogic !== "undefined" ? HuntDcodeFillLogic : null;

function pathMatchesPending(pendingUrl) {
  if (!pendingUrl) return true;
  try {
    const want = new URL(pendingUrl, location.origin).pathname.replace(/\/$/, "");
    const here = location.pathname.replace(/\/$/, "");
    return here === want || here.endsWith(want) || want.endsWith(here);
  } catch (_err) {
    return true;
  }
}

function onHost() {
  return /(^|\.)dcode\.fr$/i.test(location.hostname);
}

async function runFill(text) {
  if (!Logic || !text) return false;
  return Logic.fillWhenReady(String(text || ""));
}

let pendingTimer = null;

function schedulePendingFill() {
  if (pendingTimer) clearTimeout(pendingTimer);
  pendingTimer = setTimeout(() => {
    pendingTimer = null;
    tryConsumePending();
  }, 60);
}

function tryConsumePending() {
  if (!Logic || !onHost()) return;
  browser.storage.session.get(FILL_KEY).then(async (bag) => {
    const p = bag[FILL_KEY];
    if (!p || !p.text) return;
    if (Date.now() - (p.ts || 0) > MAX_AGE_MS) return;
    if (!pathMatchesPending(p.url)) return;
    const ok = await runFill(p.text);
    if (ok) browser.storage.session.remove(FILL_KEY).catch(() => {});
    else schedulePendingFill();
  });
}

browser.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== "HUNT_DCODE_FILL") return;
  const text = msg.text || "";
  return runFill(text).then((ok) => {
    if (ok) browser.storage.session.remove(FILL_KEY).catch(() => {});
    return { ok: Boolean(ok) };
  });
});

function boot() {
  tryConsumePending();
  const delays = [300, 700, 1200, 2000, 3500, 5500, 8000, 12000, 16000];
  for (const ms of delays) setTimeout(tryConsumePending, ms);

  const obs = new MutationObserver(() => schedulePendingFill());
  obs.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => obs.disconnect(), 25000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
