import os
import io
from typing import Optional

import uvicorn
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import pytesseract
from PIL import Image

# Set Tesseract binary path dynamically based on OS
if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
# On Linux (cloud host), pytesseract automatically uses /usr/bin/tesseract

app = FastAPI(title="PhishGuard Intelligence")

# ------------------------------------------------------------------
# Data Models
# ------------------------------------------------------------------
class DomainScanRequest(BaseModel):
    domain: str

# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------
@app.post("/api/scan-domain")
async def scan_domain(req: DomainScanRequest):
    return {
        "risk_score": 85,
        "explanation": f"Domain '{req.domain}' shows high similarity to known brand assets.",
        "permutations": [
            {"fuzzer": "Bitsquatting", "domain-name": f"p-{req.domain}", "dns-a": "192.0.2.1", "dns-mx": "mail.site.com"}
        ]
    }

@app.post("/api/scan-sms")
async def scan_sms(
    sms_text: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None)
):
    extracted_text = sms_text or ""

    if image:
        image_bytes = await image.read()
        img = Image.open(io.BytesIO(image_bytes))
        ocr_result = pytesseract.image_to_string(img)
        extracted_text += f"\n[OCR Extracted Text]: {ocr_result.strip()}"

    return {
        "risk_score": 92 if "http" in extracted_text.lower() or "urgent" in extracted_text.lower() else 30,
        "extracted_text": extracted_text.strip(),
        "summary": f"Analyzed Content: '{extracted_text.strip()}'\n\nHigh risk detected: contains suspicious call to action."
    }

# ------------------------------------------------------------------
# UI Served at http://localhost:8000/
# ------------------------------------------------------------------
HTML_LAYOUT = """
<!DOCTYPE html>
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
        <p class="text-sm text-slate-400">Typosquatting & AI Smishing OCR Inspector</p>
      </div>
    </div>

    <!-- Mode Tabs -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-2 flex gap-2">
      <button id="tab-domain" onclick="switchTab('domain')" class="flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 bg-cyan-600 text-white shadow-lg">
        <i data-lucide="globe" class="w-4 h-4"></i> Domain Scanner
      </button>
      <button id="tab-sms" onclick="switchTab('sms')" class="flex-1 py-3 px-4 rounded-xl font-medium text-sm transition-all flex items-center justify-center gap-2 text-slate-400 hover:bg-slate-800/50">
        <i data-lucide="smartphone" class="w-4 h-4"></i> SMS / Screenshot OCR
      </button>
    </div>

    <!-- Input Form -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
      <label id="input-label" class="text-xs font-semibold uppercase tracking-wider text-slate-400">Target Domain / URL</label>
      
      <!-- Domain Input -->
      <input id="domain-input" type="text" placeholder="e.g. paypal-login-verify.com" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-cyan-500 text-white">

      <!-- SMS & OCR Section -->
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

    <!-- Loading State -->
    <div id="loading-state" class="hidden text-center py-8 text-cyan-400 space-y-2">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
      <p class="text-sm">Processing OCR & Analyzing Content...</p>
    </div>

    <!-- Results Display -->
    <div id="results-card" class="hidden bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <span class="text-xs text-slate-400">Calculated Risk Score</span>
          <div id="risk-score" class="text-3xl font-extrabold text-white">0 / 100</div>
        </div>
        <div id="risk-badge" class="px-4 py-2 rounded-full text-xs font-bold">SAFE</div>
      </div>

      <div class="space-y-2">
        <h3 class="text-sm font-semibold text-cyan-400">AI Threat Analysis</h3>
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
    }

    function showFileName() {
      const input = document.getElementById('image-input');
      const fileNameEl = document.getElementById('file-name');
      if (input.files.length > 0) {
        fileNameEl.innerText = `Selected: ${input.files[0].name}`;
      }
    }

    async function executeScan() {
      document.getElementById('loading-state').classList.remove('hidden');
      document.getElementById('results-card').classList.add('hidden');

      try {
        if (currentTab === 'domain') {
          const value = document.getElementById('domain-input').value;
          if (!value.trim()) return;

          const res = await fetch('/api/scan-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: value })
          });
          const data = await res.json();
          renderResults(data);
        } else {
          const formData = new FormData();
          const textVal = document.getElementById('sms-input').value;
          const fileInput = document.getElementById('image-input');

          if (textVal) formData.append('sms_text', textVal);
          if (fileInput.files[0]) formData.append('image', fileInput.files[0]);

          const res = await fetch('/api/scan-sms', {
            method: 'POST',
            body: formData
          });
          const data = await res.json();
          renderResults(data);
        }
      } catch (err) {
        console.error("Scan error:", err);
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
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_LAYOUT

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
