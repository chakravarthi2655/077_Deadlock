import os
import io
from typing import Optional

import httpx
import uvicorn
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import pytesseract
from PIL import Image
VT_API_KEY="2fa3b1fe8a4238d5f7004a35737d06e5d28e4c5e05ea39f4e8da70cf1993b8d8"

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
# On Linux (cloud host): requires `apt-get install tesseract-ocr`

VT_API_KEY = os.environ.get("VT_API_KEY")  # set this in your environment — never hardcode it
VT_BASE_URL = "https://www.virustotal.com/api/v3/domains"

app = FastAPI(title="PhishGuard Intelligence")

# ------------------------------------------------------------------
# Data Models
# ------------------------------------------------------------------
class DomainScanRequest(BaseModel):
    domain: str

# ------------------------------------------------------------------
# Local heuristics
# ------------------------------------------------------------------
TRUSTED_BRANDS = [
    "paypal", "google", "amazon", "microsoft", "apple", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "wellsfargo"
]
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "confirm", "account", "signin", "support"]
HIGH_ABUSE_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"]


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur_row = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur_row.append(min(
                prev_row[j] + 1,
                cur_row[j - 1] + 1,
                prev_row[j - 1] + cost
            ))
        prev_row = cur_row
    return prev_row[-1]


def clean_domain(raw_domain: str) -> str:
    domain = raw_domain.lower().strip()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    return domain


def score_domain_heuristics(domain: str) -> dict:
    root = domain.split(".")[0]
    tld = domain.split(".")[-1] if "." in domain else ""

    score = 0
    reasons = []

    closest_brand, closest_dist = None, None
    for brand in TRUSTED_BRANDS:
        dist = levenshtein(root, brand)
        if closest_dist is None or dist < closest_dist:
            closest_brand, closest_dist = brand, dist

    if closest_dist is not None and 0 < closest_dist <= 3 and len(root) > 3:
        weight = max(10, 50 - (closest_dist * 10))
        score += weight
        reasons.append(f"High similarity to '{closest_brand}' (edit distance {closest_dist})")

    for brand in TRUSTED_BRANDS:
        if brand in domain and domain != brand:
            score += 30
            reasons.append(f"Contains brand name '{brand}' embedded in a longer domain")
            break

    hit_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in domain]
    if hit_keywords:
        score += min(20, 5 * len(hit_keywords))
        reasons.append(f"Contains suspicious keyword(s): {', '.join(hit_keywords)}")

    if "xn--" in domain:
        score += 25
        reasons.append("Uses punycode encoding (possible homoglyph attack)")

    if domain.count("-") >= 2:
        score += 10
        reasons.append("Contains multiple hyphens, a common typosquatting pattern")

    if tld in HIGH_ABUSE_TLDS:
        score += 15
        reasons.append(f"Uses a high-abuse TLD ('.{tld}')")

    score = max(0, min(score, 100))
    return {"score": score, "reasons": reasons}


# ------------------------------------------------------------------
# VirusTotal lookup
# ------------------------------------------------------------------
async def check_virustotal(domain: str) -> dict:
    """
    Queries VirusTotal's domain report endpoint.
    Returns available=False (never raises) if the key is missing,
    the request fails, or the domain has no report on file.
    """
    if not VT_API_KEY:
        return {"available": False, "reason": "VT_API_KEY not set"}

    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}/{domain}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        return {"available": False, "reason": f"VT request failed: {e}"}

    if resp.status_code == 404:
        return {"available": True, "found": False, "malicious": 0, "suspicious": 0, "harmless": 0}

    if resp.status_code == 429:
        return {"available": False, "reason": "VT rate limit hit (free tier: 4 req/min)"}

    if resp.status_code != 200:
        return {"available": False, "reason": f"VT lookup failed (HTTP {resp.status_code})"}

    try:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError):
        return {"available": False, "reason": "VT returned an unexpected response shape"}

    return {
        "available": True,
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
    }


def combine_scores(heuristic: dict, vt: dict) -> dict:
    """Merges local heuristic score with VirusTotal signal into one final score."""
    score = heuristic["score"]
    reasons = list(heuristic["reasons"])

    if vt.get("available") and vt.get("found"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        if malicious > 0:
            vt_boost = min(60, malicious * 10)
            score += vt_boost
            reasons.append(f"VirusTotal: flagged malicious by {malicious} security vendor(s)")
        if suspicious > 0:
            vt_boost = min(20, suspicious * 5)
            score += vt_boost
            reasons.append(f"VirusTotal: flagged suspicious by {suspicious} vendor(s)")
        if malicious == 0 and suspicious == 0:
            # Clean VT report pulls a purely-heuristic score down a bit —
            # a domain flagged only for lexical similarity but clean on VT
            # is lower confidence than one with no corroboration at all.
            score = max(0, int(score * 0.7))
            reasons.append("VirusTotal: no vendors flagged this domain as malicious/suspicious")
    elif vt.get("available") and not vt.get("found"):
        reasons.append("VirusTotal: no report on file for this domain (not necessarily safe)")
    else:
        reasons.append(f"VirusTotal: unavailable ({vt.get('reason', 'unknown error')})")

    score = max(0, min(score, 100))
    return {"score": score, "reasons": reasons}


# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------
@app.post("/api/scan-domain")
async def scan_domain(req: DomainScanRequest):
    if not req.domain.strip():
        return JSONResponse(status_code=400, content={"error": "Domain cannot be empty"})

    domain = clean_domain(req.domain)
    heuristic = score_domain_heuristics(domain)
    vt = await check_virustotal(domain)
    combined = combine_scores(heuristic, vt)

    explanation = "; ".join(combined["reasons"]) if combined["reasons"] else f"No indicators found for '{domain}'."

    return {
        "risk_score": combined["score"],
        "explanation": explanation,
        "virustotal": vt,
        "permutations": [],
    }


@app.post("/api/scan-sms")
async def scan_sms(
    sms_text: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None)
):
    extracted_text = (sms_text or "").strip()
    ocr_error = None

    if image is not None:
        try:
            image_bytes = await image.read()
            if not image_bytes:
                ocr_error = "Uploaded file was empty."
            else:
                img = Image.open(io.BytesIO(image_bytes))
                ocr_result = pytesseract.image_to_string(img).strip()
                if ocr_result:
                    extracted_text = f"{extracted_text}\n[OCR Extracted Text]: {ocr_result}".strip()
                else:
                    ocr_error = "No readable text found in the image."
        except pytesseract.TesseractNotFoundError:
            ocr_error = (
                "Tesseract binary not found on this host. "
                "Install it with `apt-get install tesseract-ocr` (Linux) "
                "or set pytesseract.pytesseract.tesseract_cmd to the correct path (Windows)."
            )
        except Exception as e:
            ocr_error = f"Failed to process image: {e}"

    if not extracted_text and ocr_error:
        return JSONResponse(status_code=422, content={"error": ocr_error})
    if not extracted_text:
        return JSONResponse(status_code=400, content={"error": "No text or image provided."})

    lowered = extracted_text.lower()
    risk_score = 92 if ("http" in lowered or "urgent" in lowered) else 30

    summary = f"Analyzed Content: '{extracted_text}'\n\n"
    summary += (
        "High risk detected: contains a suspicious link or urgent call to action."
        if risk_score >= 60
        else "No strong phishing indicators detected in this message."
    )
    if ocr_error:
        summary += f"\n\n(Note: {ocr_error})"

    return {
        "risk_score": risk_score,
        "extracted_text": extracted_text,
        "summary": summary,
    }


# ------------------------------------------------------------------
# UI Served at http://localhost:8000/
# ------------------------------------------------------------------
HTML_LAYOUT = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PhishGuard Intelligence</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-12 font-sans">
  <div class="max-w-4xl mx-auto space-y-8">

    <div class="flex items-center gap-3 border-b border-slate-800 pb-6">
      <div class="p-3 bg-cyan-500/10 rounded-xl border border-cyan-500/20 text-cyan-400">
        <i data-lucide="shield" class="w-8 h-8"></i>
      </div>
      <div>
        <h1 class="text-2xl font-bold tracking-tight">PhishGuard Intelligence</h1>
        <p class="text-sm text-slate-400">Typosquatting, VirusTotal & AI Smishing OCR Inspector</p>
      </div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-2 flex gap-2">
      <button id="tab-domain" onclick="switchTab('domain')" class="flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 bg-cyan-600 text-white shadow-lg">
        <i data-lucide="globe" class="w-4 h-4"></i> Domain Scanner
      </button>
      <button id="tab-sms" onclick="switchTab('sms')" class="flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 text-slate-400 hover:bg-slate-800/50">
        <i data-lucide="smartphone" class="w-4 h-4"></i> SMS / Screenshot OCR
      </button>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
      <label id="input-label" class="text-xs font-semibold uppercase tracking-wider text-slate-400">Target Domain / URL</label>

      <input id="domain-input" type="text" placeholder="e.g. paypal-login-verify.com" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-cyan-500 text-white">

      <div id="sms-container" class="hidden space-y-3">
        <textarea id="sms-input" rows="3" placeholder="Paste SMS text here..." class="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-sm focus:outline-none focus:border-cyan-500 text-white"></textarea>

        <div class="text-xs text-slate-500 text-center font-medium">--- OR UPLOAD SCREENSHOT ---</div>

        <div class="flex items-center justify-center w-full">
          <label class="flex flex-col items-center justify-center w-full h-32 border-2 border-slate-800 border-dashed rounded-xl cursor-pointer bg-slate-950 hover:bg-slate-900 transition-all">
            <div class="flex flex-col items-center justify-center pt-5 pb-6">
              <i data-lucide="image" class="w-6 h-6 text-slate-400 mb-2"></i>
              <p class="text-xs text-slate-400"><span class="font-semibold text-cyan-400">Click to upload screenshot</span> or drag and drop</p>
              <p id="file-name" class="text-xs text-cyan-300 mt-1 font-mono"></p>
            </div>
            <input id="image-input" type="file" accept="image/*" class="hidden" onchange="showFileName()" />
          </label>
        </div>
      </div>

      <button id="scan-btn" onclick="executeScan()" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold py-3 rounded-xl transition-all">
        Execute Threat Scan
      </button>
    </div>

    <div id="loading-state" class="hidden text-center py-8 text-cyan-400 space-y-2">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
      <p class="text-sm">Processing OCR & Analyzing Content...</p>
    </div>

    <div id="error-card" class="hidden bg-red-500/10 border border-red-500/30 rounded-2xl p-4 text-sm text-red-300"></div>

    <div id="results-card" class="hidden bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <span class="text-xs text-slate-400">Calculated Risk Score</span>
          <div id="risk-score" class="text-3xl font-extrabold text-white">0 / 100</div>
        </div>
        <div id="risk-badge" class="px-4 py-2 rounded-full text-xs font-bold">SAFE</div>
      </div>

      <div class="space-y-2">
        <h3 class="text-sm font-semibold text-cyan-400">Threat Analysis</h3>
        <div id="ai-summary" class="bg-slate-950 border border-slate-800/80 rounded-xl p-4 text-sm text-slate-300 leading-relaxed whitespace-pre-line"></div>
      </div>
    </div>

  </div>

  <script>
    lucide.createIcons();
    let currentTab = 'domain';

    function switchTab(tab) {
      currentTab = tab;
      const domainBtn = document.getElementById('tab-domain');
      const smsBtn = document.getElementById('tab-sms');
      const domainInput = document.getElementById('domain-input');
      const smsContainer = document.getElementById('sms-container');
      const label = document.getElementById('input-label');

      if (tab === 'domain') {
        domainBtn.className = 'flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 bg-cyan-600 text-white shadow-lg';
        smsBtn.className = 'flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 text-slate-400 hover:bg-slate-800/50';
        domainInput.classList.remove('hidden');
        smsContainer.classList.add('hidden');
        label.innerText = 'Target Domain / URL';
      } else {
        smsBtn.className = 'flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 bg-cyan-600 text-white shadow-lg';
        domainBtn.className = 'flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 text-slate-400 hover:bg-slate-800/50';
        smsContainer.classList.remove('hidden');
        domainInput.classList.add('hidden');
        label.innerText = 'Raw SMS or Screenshot OCR';
      }
      document.getElementById('results-card').classList.add('hidden');
      document.getElementById('error-card').classList.add('hidden');
    }

    function showFileName() {
      const input = document.getElementById('image-input');
      const fileNameEl = document.getElementById('file-name');
      if (input.files.length > 0) {
        fileNameEl.innerText = `Selected: ${input.files[0].name}`;
      }
    }

    function showError(message) {
      const errorCard = document.getElementById('error-card');
      errorCard.innerText = message;
      errorCard.classList.remove('hidden');
      document.getElementById('results-card').classList.add('hidden');
    }

    async function executeScan() {
      document.getElementById('loading-state').classList.remove('hidden');
      document.getElementById('results-card').classList.add('hidden');
      document.getElementById('error-card').classList.add('hidden');

      try {
        let res;
        if (currentTab === 'domain') {
          const value = document.getElementById('domain-input').value;
          if (!value.trim()) { showError('Please enter a domain to scan.'); return; }
          res = await fetch('/api/scan-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: value })
          });
        } else {
          const formData = new FormData();
          const textVal = document.getElementById('sms-input').value;
          const fileInput = document.getElementById('image-input');
          if (!textVal && !fileInput.files[0]) { showError('Please paste SMS text or upload a screenshot.'); return; }
          if (textVal) formData.append('sms_text', textVal);
          if (fileInput.files[0]) formData.append('image', fileInput.files[0]);
          res = await fetch('/api/scan-sms', { method: 'POST', body: formData });
        }

        const data = await res.json();
        if (!res.ok) { showError(data.error || data.detail || 'Something went wrong during the scan.'); return; }
        renderResults(data);
      } catch (err) {
        console.error("Scan error:", err);
        showError('Network or server error: ' + err.message);
      } finally {
        document.getElementById('loading-state').classList.add('hidden');
      }
    }

    function renderResults(data) {
      const resultsCard = document.getElementById('results-card');
      const riskScore = document.getElementById('risk-score');
      const riskBadge = document.getElementById('risk-badge');
      const aiSummary = document.getElementById('ai-summary');

      riskScore.innerText = `${data.risk_score} / 100`;

      if (data.risk_score > 60) {
        riskBadge.innerText = 'HIGH THREAT / SCAM';
        riskBadge.className = 'px-4 py-2 rounded-full text-xs font-bold bg-red-500/10 text-red-400 border border-red-500/20';
      } else {
        riskBadge.innerText = 'LOW RISK / SAFE';
        riskBadge.className = 'px-4 py-2 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
      }

      aiSummary.innerText = data.explanation || data.summary;
      resultsCard.classList.remove('hidden');
    }
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_LAYOUT


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
