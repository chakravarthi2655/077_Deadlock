// heuristics.js
// Pure functions, no chrome.* calls here — usable in both background and content contexts.

const BRAND_KEYWORDS = [
  "paypal", "microsoft", "apple", "google", "amazon", "netflix",
  "bankofamerica", "chase", "wellsfargo", "facebook", "instagram", "irs"
];

const SUSPICIOUS_TLDS = [".zip", ".mov", ".xyz", ".top", ".club", ".gq", ".tk", ".ml"];

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

// --- URL-level heuristics ---
function scoreUrl(urlStr) {
  let score = 0;
  const reasons = [];
  let host;
  try {
    host = new URL(urlStr).hostname.toLowerCase();
  } catch {
    return { score: 0, reasons: [] };
  }

  // IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score += 40;
    reasons.push("URL uses a raw IP address instead of a domain name");
  }

  // Excessive subdomains
  const subCount = host.split(".").length - 2;
  if (subCount >= 3) {
    score += 35;
    reasons.push("Unusually many subdomains");
  }

  // Suspicious TLD
  if (SUSPICIOUS_TLDS.some(tld => host.endsWith(tld))) {
    score += 35;
    reasons.push("Domain uses a TLD commonly abused for phishing");
  }

  // Typosquat distance to known brands
  const domainRoot = host.split(".").slice(-2, -1)[0] || "";
  for (const brand of BRAND_KEYWORDS) {
    if (domainRoot === brand) continue; // exact legit match, skip
    const dist = levenshtein(domainRoot, brand);
    if (dist > 0 && dist <= 2 && domainRoot.length >= brand.length - 2) {
      score += 45;
      reasons.push(`Domain closely resembles "${brand}" (possible typosquat)`);
      break;
    }
  }

  // Brand name appears but not as the actual domain (e.g. paypal-secure-login.com)
  for (const brand of BRAND_KEYWORDS) {
    if (host.includes(brand) && domainRoot !== brand) {
      score += 40;
      reasons.push(`Brand name "${brand}" appears in domain that isn't the real brand site`);
      break;
    }
  }

  // @ symbol trick (user@evil.com style redirects)
  if (urlStr.includes("@")) {
    score += 35;
    reasons.push("URL contains an '@' symbol, often used to obscure the real destination");
  }

  return { score: Math.min(score, 100), reasons };
}

// --- DOM-level heuristics (run inside the page) ---
function scoreDom(doc, pageHost) {
  let score = 0;
  const reasons = [];

  const passwordInputs = doc.querySelectorAll('input[type="password"]');
  if (passwordInputs.length > 0) {
    passwordInputs.forEach(input => {
      const form = input.closest("form");
      if (form && form.action) {
        try {
          const actionHost = new URL(form.action, doc.baseURI).hostname;
          if (actionHost && actionHost !== pageHost) {
            score += 50;
            reasons.push(`Login form submits to a different domain (${actionHost})`);
          }
        } catch {}
      }
    });
  }

  // Brand text present but domain doesn't match
  const bodyText = doc.body ? doc.body.innerText.toLowerCase() : "";
  for (const brand of BRAND_KEYWORDS) {
    if (bodyText.includes(brand) && !pageHost.includes(brand)) {
      score += 30;
      reasons.push(`Page mentions "${brand}" but domain doesn't match`);
      break;
    }
  }

  // Hidden/invisible text (possible prompt-injection against the AI reviewer)
  doc.querySelectorAll("[style]").forEach(el => {
    const style = el.getAttribute("style") || "";
    if (/display:\s*none|visibility:\s*hidden|opacity:\s*0/i.test(style) && el.innerText?.length > 20) {
      score += 25;
      reasons.push("Hidden text detected on page (possible evasion attempt)");
    }
  });

  // Obfuscated inline scripts (very rough heuristic: long unbroken strings, eval/unescape use)
  doc.querySelectorAll("script:not([src])").forEach(script => {
    const code = script.textContent || "";
    if (code.length > 500 && (code.includes("eval(") || code.includes("unescape(") || /[a-zA-Z0-9+/]{200,}/.test(code))) {
      score += 25;
      reasons.push("Obfuscated inline script detected");
    }
  });

  return { score: Math.min(score, 100), reasons };
}

// --- Extract compact signals to send to AI (only called when escalating) ---
function extractDomSignalsForAI(doc, pageHost) {
  const forms = [...doc.querySelectorAll("form")].map(f => ({
    action: f.action || null,
    hasPasswordField: !!f.querySelector('input[type="password"]'),
    inputCount: f.querySelectorAll("input").length
  }));

  return {
    host: pageHost,
    title: doc.title,
    formCount: forms.length,
    forms,
    visibleBrandMentions: BRAND_KEYWORDS.filter(b => (doc.body?.innerText || "").toLowerCase().includes(b)),
    hasFavicon: !!doc.querySelector('link[rel*="icon"]')
  };
}