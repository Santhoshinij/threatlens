/* Home page: fill in the model accuracy table inside "How ThreatLens decides". */
(() => {
  "use strict";
  const box = document.getElementById("metrics");
  if (!box) return;
  fetch("/api/metrics").then((r) => (r.ok ? r.json() : null)).then((m) => {
    if (!m || !m.messages) return;
    const pct = (x) => (x * 100).toFixed(1) + "%";
    box.innerHTML = "<p>Accuracy on held-out sample data:</p><table><tr><th>Messages</th><td></td><td></td></tr><tr><th>Links</th><td></td><td></td></tr></table>";
    const rows = box.querySelectorAll("tr");
    rows[0].children[1].textContent = pct(m.messages.accuracy);
    rows[0].children[2].textContent = m.messages.test_size + " test items";
    rows[1].children[1].textContent = pct(m.urls.accuracy);
    rows[1].children[2].textContent = m.urls.test_size + " test items";
    const note = document.createElement("p");
    note.textContent = "These figures come from generated demo data, so real-world accuracy will be lower. Retraining on real scam datasets is the main way to improve it.";
    box.append(note);
    box.hidden = false;
  }).catch(() => {});
})();
