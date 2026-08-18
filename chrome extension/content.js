// content.js
const AMBIGUOUS_LOW = 20;
const AMBIGUOUS_HIGH = 60;
const BLOCK_THRESHOLD = 70;

let alreadyEscalated = false;
let overlayShown = false;

function getCacheKey(host) {
  return `phishcache:${host}`;
}

async function getCached(host) {
  const key = getCacheKey(host);
  const stored = await chrome.storage.local.get(key);
  const entry = stored[key];
  if (!entry) return null;
  const ttlMs = 24 * 60 * 60 * 1000; // 24h TTL — recheck periodically even if "clean"
  if (Date.now() - entry.timestamp > ttlMs) return null;
  return entry;
}

async function setCached(host, result) {
  const key = getCacheKey(host);
  await chrome.storage.local.set({ [key]: { ...result, timestamp: Date.now() } });
}

function showBlockOverlay(score, reasons) {
  if (overlayShown) return;
  overlayShown = true;

  const overlay = document.createElement("div");
  overlay.id = "phishing-shield-overlay";
  overlay.innerHTML = `
    <div class="ps-box">
      <h1>⚠ This site looks like phishing</h1>
      <p class="ps-score">Risk score: ${score}/100</p>
      <ul class="ps-reasons">${reasons.map(r => `<li>${r}</li>`).join("")}</ul>
      <div class="ps-actions">
        <button id="ps-leave">Leave this site</button>
        <button id="ps-proceed">Proceed anyway (not recommended)</button>
      </div>
    </div>
  `;
  document.documentElement.appendChild(overlay);

  document.getElementById("ps-leave").addEventListener("click", () => {
    window.location.href = "about:blank";
  });
  document.getElementById("ps-proceed").addEventListener("click", () => {
    overlay.remove();
    overlayShown = false;
  });
}

async function runCheck() {
  const host = location.hostname;
  const cached = await getCached(host);
  if (cached) {
    if (cached.score >= BLOCK_THRESHOLD) showBlockOverlay(cached.score, cached.reasons);
    return;
  }

  const domResult = scoreDom(document, host);
  const urlResult = await chrome.runtime.sendMessage({ type: "SCORE_URL", url: location.href });

  let combinedScore = Math.round((domResult.score + (urlResult?.score || 0)) / 2);
  let reasons = [...domResult.reasons, ...(urlResult?.reasons || [])];

  // Escalate to AI only when the local heuristic verdict is ambiguous
  if (combinedScore >= AMBIGUOUS_LOW && combinedScore <= AMBIGUOUS_HIGH && !alreadyEscalated) {
    alreadyEscalated = true;
    const signals = extractDomSignalsForAI(document, host);
    const aiResult = await chrome.runtime.sendMessage({ type: "AI_ANALYZE", url: location.href, signals });
    if (aiResult && typeof aiResult.score === "number") {
      combinedScore = Math.round((combinedScore + aiResult.score) / 2);
      reasons = [...reasons, ...(aiResult.reasons || [])];
    }
  }

  await setCached(host, { score: combinedScore, reasons });

  if (combinedScore >= BLOCK_THRESHOLD) {
    showBlockOverlay(combinedScore, reasons);
  }
}

// Initial check once DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runCheck);
} else {
  runCheck();
}

// Watch for late-injected login forms (common phishing evasion trick)
const observer = new MutationObserver(mutations => {
  const addedForm = mutations.some(m =>
    [...m.addedNodes].some(n => n.nodeType === 1 && (n.tagName === "FORM" || n.querySelector?.("form input[type=password]")))
  );
  if (addedForm) {
    // Content changed meaningfully — re-run the check, ignoring cache this once
    chrome.storage.local.remove(getCacheKey(location.hostname)).then(runCheck);
  }
});
observer.observe(document.documentElement, { childList: true, subtree: true });