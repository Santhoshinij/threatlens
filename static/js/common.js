/* Shared helpers used by more than one page. Exposes window.TL. */
(() => {
  "use strict";
  const RESULT_KEY = "threatlens.result.v1";
  const RECENT_KEY = "threatlens.recent.v1";

  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* non-JSON error page */ }
    if (!res.ok) throw new Error(data.error || "Something went wrong on the server. Try again.");
    return data;
  }

  /* Run a check, remember the answer for the Result page, then go there. */
  async function analyseAndGo(kind, value) {
    try { sessionStorage.removeItem(RESULT_KEY); } catch (_) { /* ignore */ }   // never show an older answer
    const data = kind === "message"
      ? await post("/api/analyze/message", { text: value })
      : await post("/api/analyze/url", { url: value });
    try {
      sessionStorage.setItem(RESULT_KEY, JSON.stringify({ kind, input: value, data, at: Date.now() }));
    } catch (_) {
      throw new Error("Your browser blocked temporary storage, so the result page cannot open. Try a normal (non-private) window.");
    }
    saveRecent({ kind, value, level: data.verdict.level });
    window.location.href = "/result";
  }

  function loadResult() {
    try { return JSON.parse(sessionStorage.getItem(RESULT_KEY)); } catch (_) { return null; }
  }

  function loadRecent() {
    try { return JSON.parse(localStorage.getItem(RECENT_KEY)) || []; } catch (_) { return []; }
  }
  function saveRecent(item) {
    const list = loadRecent().filter((r) => !(r.kind === item.kind && r.value === item.value));
    list.unshift(item);
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 6))); } catch (_) { /* storage unavailable */ }
  }
  function clearRecent() {
    try { localStorage.removeItem(RECENT_KEY); } catch (_) { /* ignore */ }
  }

  window.TL = { post, analyseAndGo, loadResult, loadRecent, clearRecent };
})();
