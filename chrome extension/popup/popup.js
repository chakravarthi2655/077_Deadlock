// popup/popup.js
(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const host = new URL(tab.url).hostname;
  const key = `phishcache:${host}`;
  const stored = await chrome.storage.local.get(key);
  const entry = stored[key];
  const scoreEl = document.getElementById("score");
  const reasonsEl = document.getElementById("reasons");

  if (!entry) {
    scoreEl.textContent = "No data yet";
    return;
  }
  scoreEl.textContent = `${entry.score}/100`;
  scoreEl.style.color = entry.score >= 70 ? "#c0152f" : entry.score >= 20 ? "#c98a00" : "#1a7f37";
  reasonsEl.innerHTML = entry.reasons.map(r => `<li>${r}</li>`).join("");
})();