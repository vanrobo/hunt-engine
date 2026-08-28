/**
 * Hunt Engine — dCode.fr autofill logic (DOM only; injectable via executeScript).
 */
"use strict";

(function dcodeFillLogicFactory(root) {
  const PAGE_SELECTORS = [
    {
      match: /\/cipher-identifier/i,
      formId: "cipher_identifier",
      selectors: ["#cipher_identifier_ciphertext"],
    },
    {
      match: /\/morse-code/i,
      formId: "decipher_morse",
      selectors: ["#decipher_morse_ciphertext", "#decipher_morse"],
    },
    {
      match: /\/hodor-language/i,
      formId: "decipher_hodor",
      selectors: ["#decipher_hodor_ciphertext", "#decipher_hodor"],
    },
  ];

  function storageOk() {
    try {
      localStorage.setItem("__hunt_dcode_test", "1");
      localStorage.removeItem("__hunt_dcode_test");
      return true;
    } catch (_err) {
      return false;
    }
  }

  function syncLocalStorage(formId, fieldName, value) {
    if (!formId || !storageOk()) return;
    try {
      let data = {};
      const raw = localStorage.getItem(formId);
      if (raw) {
        try {
          data = JSON.parse(raw) || {};
        } catch (_err) {
          data = {};
        }
      }
      data[fieldName || "ciphertext"] = value;
      localStorage.setItem(formId, JSON.stringify(data));
    } catch (_err) {
      /* ignore */
    }
  }

  function isFormField(el) {
    if (!el || el.id === "contact_message") return false;
    if (el.disabled || el.readOnly) return false;
    if (!el.closest("#forms")) return false;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    return true;
  }

  function findTargetField() {
    const path = location.pathname || "";
    for (const page of PAGE_SELECTORS) {
      if (!page.match.test(path)) continue;
      for (const sel of page.selectors) {
        const el = document.querySelector(sel);
        if (el && isFormField(el)) {
          return { el, formId: page.formId || formIdFrom(el) };
        }
      }
    }

    const forms = document.querySelectorAll("#forms form");
    for (const form of forms) {
      const ta = form.querySelector('textarea[name="ciphertext"]');
      if (ta && isFormField(ta)) {
        return { el: ta, formId: form.getAttribute("id") || "" };
      }
    }

    const named = document.querySelector('#forms textarea[name="ciphertext"]');
    if (named && isFormField(named)) {
      return { el: named, formId: formIdFrom(named) };
    }
    return null;
  }

  function formIdFrom(el) {
    const form = el && el.closest ? el.closest("form") : null;
    return (form && form.getAttribute("id")) || "";
  }

  function fireInputEvents(el, payload) {
    try {
      el.dispatchEvent(
        new InputEvent("input", {
          bubbles: true,
          cancelable: true,
          inputType: "insertText",
          data: payload,
        })
      );
    } catch (_err) {
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function setFieldValue(el, text, formId) {
    const payload = String(text || "");
    if (!el || !payload) return false;
    const fieldName = el.getAttribute("name") || "ciphertext";

    if (root.jQuery) {
      try {
        const $el = root.jQuery(el);
        $el.val(payload).trigger("keyup").trigger("change");
        if ($el.val() === payload) {
          syncLocalStorage(formId, fieldName, payload);
          return true;
        }
      } catch (_err) {
        /* fall through */
      }
    }

    el.focus();
    try {
      el.select();
      document.execCommand("selectAll", false, null);
      if (document.execCommand("insertText", false, payload) && el.value === payload) {
        fireInputEvents(el, payload);
        syncLocalStorage(formId, fieldName, payload);
        return true;
      }
    } catch (_err) {
      /* fall through */
    }

    try {
      const proto =
        el.tagName === "TEXTAREA"
          ? HTMLTextAreaElement.prototype
          : HTMLInputElement.prototype;
      const desc = Object.getOwnPropertyDescriptor(proto, "value");
      if (desc && desc.set) desc.set.call(el, payload);
      else el.value = payload;
      fireInputEvents(el, payload);
      if (el.value === payload) {
        syncLocalStorage(formId, fieldName, payload);
        return true;
      }
    } catch (_err2) {
      el.value = payload;
      fireInputEvents(el, payload);
    }

    const ok = el.value === payload;
    if (ok) syncLocalStorage(formId, fieldName, payload);
    return ok;
  }

  function dcodeReady() {
    return Boolean(root.jQuery && document.querySelector("#forms form textarea"));
  }

  function fillNow(text) {
    const target = findTargetField();
    if (!target) return false;
    return setFieldValue(target.el, text, target.formId);
  }

  function fillWhenReady(text, options) {
    const opts = options || {};
    const payload = String(text || "");
    const timeoutMs = opts.timeoutMs == null ? 20000 : opts.timeoutMs;
    const delayAfterReadyMs = opts.delayAfterReadyMs == null ? 180 : opts.delayAfterReadyMs;
    if (!payload) return Promise.resolve(false);

    const started = Date.now();
    return new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        resolve(Boolean(ok));
      };

      const attemptFill = () => {
        if (settled) return;
        const ok = fillNow(payload);
        if (ok) {
          finish(true);
          return;
        }
        if (Date.now() - started >= timeoutMs) {
          finish(false);
          return;
        }
        setTimeout(attemptFill, 220);
      };

      const waitReady = () => {
        if (settled) return;
        if (!dcodeReady()) {
          if (Date.now() - started >= timeoutMs) {
            attemptFill();
            return;
          }
          setTimeout(waitReady, 80);
          return;
        }
        setTimeout(attemptFill, delayAfterReadyMs);
      };

      waitReady();
    });
  }

  const api = {
    fillNow,
    fillWhenReady,
    findTargetField,
    dcodeReady,
  };

  root.HuntDcodeFillLogic = api;
})(typeof globalThis !== "undefined" ? globalThis : window);
