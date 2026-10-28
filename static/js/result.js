/* Result page: draw the answer the Check page stored for this tab. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const saved = TL.loadResult();

  if (!saved || !saved.data) {
    $("empty").hidden = false;
    return;
  }
  const { kind, input, data, at } = saved;
  $("result").hidden = false;

  $("verdict").classList.add(data.verdict.level);
  const when = at ? new Date(at).toLocaleTimeString() : "";
  $("verdict-kind").textContent = (kind === "message" ? "Message check" : "Web address check") + (when ? " · checked at " + when : "");
  $("verdict-label").textContent = data.verdict.label;
  $("score-pct").textContent = Math.round(data.score * 100) + "%";
  document.title = data.verdict.label + " · ThreatLens";

  // meter marker slides in from the left
  const marker = $("marker");
  marker.style.left = "0%";
  requestAnimationFrame(() => requestAnimationFrame(() => {
    marker.style.left = Math.min(Math.max(data.score, 0.01), 0.99) * 100 + "%";
  }));

  if (kind === "message") {
    $("annotated-wrap").hidden = false;
    renderAnnotated(input, data.highlights || []);
    renderLinks(data.links || []);
  } else {
    $("url-shown").hidden = false;
    $("url-line").textContent = data.url;
  }
  renderSignals(data.signals || []);
  for (const a of data.verdict.advice) {
    const li = document.createElement("li");
    li.textContent = a;
    $("advice").append(li);
  }

  function renderAnnotated(text, highlights) {
    // Server offsets are Unicode code points; JS strings are UTF-16, so slice by code point.
    const chars = Array.from(text);
    const out = $("annotated");
    out.textContent = "";
    let pos = 0;
    for (const h of highlights) {
      if (h.start > pos) out.append(chars.slice(pos, h.start).join(""));
      const m = document.createElement("mark");
      m.className = h.severity;
      m.textContent = chars.slice(h.start, h.end).join("");
      out.append(m);
      pos = h.end;
    }
    if (pos < chars.length) out.append(chars.slice(pos).join(""));
  }

  function renderLinks(links) {
    if (!links.length) return;
    $("links-wrap").hidden = false;
    const ul = $("links");
    for (const l of links) {
      const li = document.createElement("li");
      const u = document.createElement("span"); u.className = "u"; u.textContent = l.url;
      const s = document.createElement("span"); s.className = "s";
      s.textContent = Math.round(l.score * 100) + "% risk";
      li.append(u, s);
      ul.append(li);
    }
  }

  function renderSignals(list) {
    const ul = $("signals");
    if (!list.length) {
      const li = document.createElement("li");
      li.className = "none";
      const t = document.createElement("span"); t.className = "t"; t.textContent = "No specific warning signs found";
      const d = document.createElement("span"); d.className = "d";
      d.textContent = "The wording and links look ordinary. That is reassuring, not a guarantee.";
      li.append(t, d);
      ul.append(li);
      return;
    }
    for (const s of list) {
      const li = document.createElement("li");
      li.className = s.severity;
      const t = document.createElement("span"); t.className = "t"; t.textContent = s.title;
      const d = document.createElement("span"); d.className = "d"; d.textContent = s.detail;
      li.append(t, d);
      ul.append(li);
    }
  }
})();
