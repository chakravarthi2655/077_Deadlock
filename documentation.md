# Architecture & Scoring Logic

## Extension scoring

### URL heuristics (heuristics.js → scoreUrl)
- Raw IP as hostname: +40
- 3+ subdomains: +35
- Suspicious TLD (.zip, .xyz, .top, etc.): +35
- Typosquat distance ≤2 from known brand: +45
- Brand name in domain but not the real domain: +40
- '@' symbol in URL: +35

### DOM heuristics (heuristics.js → scoreDom)
- Password form submitting cross-domain: +50
- Brand text present but domain mismatch: +30
- Hidden/invisible text blocks: +25
- Obfuscated inline scripts: +25

### Combination & escalation
1. `combinedScore = average(domScore, urlScore)`
2. If `20 ≤ combinedScore ≤ 60` (ambiguous), escalate to Groq AI with page signals
3. AI score is averaged back in
4. Google Safe Browsing hit forces score to 100 regardless of other signals
5. Score ≥ 70 → block overlay shown

### Caching
Results are cached per-hostname for 24 hours; cache is invalidated early if a new form/password field is injected into the page (evasion detection).

## Backend endpoints
- `/api/scan-domain` — placeholder domain-permutation/typosquat scan (currently returns static demo data — replace with real DNS-twist style scanning)
- `/api/scan-sms` — OCR (via Tesseract) + keyword-based smishing risk scoring (currently returns static demo data — replace with real classification)