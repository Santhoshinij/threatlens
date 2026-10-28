/* Check page: collect input, call the backend, hand over to the Result page. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const tabs = { message: $("tab-message"), url: $("tab-url") };
  const panes = { message: $("pane-message"), url: $("pane-url") };
  const msgInput = $("msg-input");
  const urlInput = $("url-input");
  const errorBox = $("error");

  function selectTab(kind, focus) {
    for (const k of Object.keys(tabs)) {
      const on = k === kind;
      tabs[k].setAttribute("aria-selected", on);
      tabs[k].tabIndex = on ? 0 : -1;
      panes[k].hidden = !on;
    }
    errorBox.hidden = true;
    if (focus) tabs[kind].focus();
  }
  for (const k of Object.keys(tabs)) {
    tabs[k].addEventListener("click", () => selectTab(k));
    tabs[k].addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") selectTab(k === "message" ? "url" : "message", true);
    });
  }
  if (new URLSearchParams(location.search).get("tab") === "url") selectTab("url");

  msgInput.addEventListener("input", () => {
    $("msg-count").textContent = msgInput.value.length + " / 5000";
  });

  async function run(kind, value) {
    const btn = panes[kind].querySelector("button[type=submit]");
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Reading…";
    errorBox.hidden = true;
    try {
      await TL.analyseAndGo(kind, value);          // navigates to /result on success
    } catch (err) {
      errorBox.textContent = err.message;
      errorBox.hidden = false;
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  panes.message.addEventListener("submit", (e) => { e.preventDefault(); run("message", msgInput.value.trim()); });
  panes.url.addEventListener("submit", (e) => { e.preventDefault(); run("url", urlInput.value.trim()); });

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const kind = chip.dataset.kind, val = chip.dataset.sample;
      if (kind === "message") { msgInput.value = val; msgInput.dispatchEvent(new Event("input")); }
      else urlInput.value = val;
      run(kind, val);
    });
  });

  /* recent checks (browser only) */
  function drawRecent() {
    const list = TL.loadRecent();
    $("recent").hidden = list.length === 0;
    const ul = $("recent-list");
    ul.textContent = "";
    for (const r of list) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.innerHTML = '<span class="dot"></span><span class="txt"></span>';
      b.querySelector(".dot").classList.add(r.level);
      b.querySelector(".txt").textContent = r.value.replace(/\s+/g, " ");
      b.addEventListener("click", () => {
        selectTab(r.kind);
        if (r.kind === "message") { msgInput.value = r.value; msgInput.dispatchEvent(new Event("input")); }
        else urlInput.value = r.value;
        run(r.kind, r.value);
      });
      li.append(b);
      ul.append(li);
    }
  }
  $("clear-recent").addEventListener("click", () => { TL.clearRecent(); drawRecent(); });
  drawRecent();
})();
