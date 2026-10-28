# ScamShield-AI: Backend Service

FastAPI-based detection service integrating the trained scikit-learn scam classifier.

## 1. Features
- **Health Check (`GET /health`):** Verifies application status and confirms that the trained ML model (`ml/models/model.joblib`) is active in memory.
- **Text Scan Endpoint (`POST /api/v1/scans/text`):** Validates input, evaluates message text using the trained TF-IDF + Logistic Regression pipeline, and returns predicted label, scam probability, confidence, and keyword evidence.
- **URL Scan Endpoint (`POST /api/v1/scans/url`):** Offline, static structural heuristic analysis for IP hostnames, excessive subdomains, brand spoofing, and punycode. Operates strictly offline without fetching submitted URLs.
- **Image / Screenshot Scan Endpoint (`POST /api/v1/scans/image`):** Secure screenshot and image scanning for fraud and phishing. Validates true format (JPEG, PNG, WebP) and dimensions in memory, extracts visible text using local OCR (Tesseract), classifies text with the ML scam model, extracts embedded URLs for heuristic & reputation analysis, and computes a unified combined verdict.
- **Data Protection & Hygiene:** Clean input validation (1–5000 characters for text, max 2048 for URLs, max 5 MB and 10,000x10,000 px for images), defensive error envelopes without exposing server stack traces. Images are processed strictly in-memory and are never persisted to disk.

---

## 2. Setup & Execution

### Prerequisites
Activate the project-local virtual environment:
```powershell
# Windows PowerShell
.\.venv\Scripts\activate
```

Dependencies are documented in `backend/requirements.txt` (`fastapi`, `uvicorn`, `pydantic`, `httpx`, `pillow`, `pytesseract`, `python-multipart`).

### Local OCR Engine Setup (Tesseract)

ScamShield-AI uses **local OCR only** to protect user privacy and avoid uploading screenshots or sensitive documents to third-party cloud services.

1. **Windows Installation:**
   - Download the official installer from [UB-Mannheim Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) or install via winget:
     ```powershell
     winget install UB-Mannheim.TesseractOCR
     ```
   - Default install location is `C:\Program Files\Tesseract-OCR\tesseract.exe`.
   - If installed in a custom path, configure the `TESSERACT_CMD` environment variable:
     ```powershell
     $env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
     ```

2. **Linux (Ubuntu/Debian):**
   ```bash
   sudo apt-get update && sudo apt-get install -y tesseract-ocr
   ```

3. **macOS:**
   ```bash
   brew install tesseract
   ```

> **Note on OCR Availability:** If Tesseract is not installed on the system, the endpoint will safely return `ocr_status: "ocr_unavailable"` and `combined_verdict: "inconclusive"` along with a clear diagnostic warning. It will **never** claim the image is safe or upload data to external servers. Unit tests include mock OCR providers allowing complete verification without requiring host binaries.

### Running the Server

#### Option A: Quick Start (Default Host `127.0.0.1` and Port `8000`)
From the `ShieldAI` project root in PowerShell:
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Or activate the virtualenv first:
```powershell
.\.venv\Scripts\activate
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Option B: Configurable Host, Port, and Frontend CORS
The backend supports environment variables so host, port, and CORS origins do not need to be hardcoded:
```powershell
# Set custom frontend dev origin(s) and port
$env:SCAMSHIELD_HOST = "127.0.0.1"
$env:SCAMSHIELD_PORT = "8000"
$env:CORS_ALLOWED_ORIGINS = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

# Run server
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

### Inspecting Interactive API Documentation (/docs)
FastAPI provides live interactive documentation and schema inspection out-of-the-box:
- **Swagger UI (Interactive Testing):** `http://127.0.0.1:8000/docs`
  - Allows your frontend teammate to test request payloads, execute scans, and inspect exact JSON schemas directly in their browser.
- **ReDoc (Human-Readable Spec):** `http://127.0.0.1:8000/redoc`
- **Raw OpenAPI Schema (JSON):** `http://127.0.0.1:8000/openapi.json`

---

## 3. Frontend Integration Guide

This guide is designed for the frontend teammate integrating UI components with this backend detection service.

### Environment & Base URL Configuration
Configure the frontend API client (e.g., via `.env.development` or Vite/Next.js environment variables):
```env
# Vite example:
VITE_API_BASE_URL=http://127.0.0.1:8000

# Next.js example:
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000
```

### CORS Configuration
- By default, common frontend development ports are pre-approved:
  - `http://localhost:3000` & `http://127.0.0.1:3000` (React / Next.js)
  - `http://localhost:5173` & `http://127.0.0.1:5173` (Vite)
  - `http://localhost:8080` & `http://127.0.0.1:8080` (Vue / Webpack)
  - `http://localhost:4173` & `http://127.0.0.1:4173` (Vite Preview)
- To specify additional origins, set the `CORS_ALLOWED_ORIGINS` environment variable as a comma-separated list before launching the server.
- Wildcard `*` origins are deliberately restricted when credentials are enabled to adhere to browser CORS standards.

### Endpoint Matrix Summary

| Method | Endpoint | Request Content-Type | Request Body / Form | Success Status | Key Response Fields |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `GET` | `/health` | None | None | `200 OK` | `status`, `model_loaded`, `model_version`, `api_version` |
| `POST` | `/api/v1/scans/text` | `application/json` | `{"text": string}` | `200 OK` | `label`, `is_scam`, `scam_probability`, `confidence`, `evidence`, `explanation` |
| `POST` | `/api/v1/scans/url` | `application/json` | `{"url": string}` | `200 OK` | `verdict`, `label`, `risk_score`, `risk_level`, `evidence`, `reputation_check` |
| `POST` | `/api/v1/scans/image` | `multipart/form-data` | `file`: binary (JPEG, PNG, WebP) | `200 OK` | `combined_verdict`, `verdict`, `risk_score`, `risk_level`, `ocr_status`, `ocr_info`, `extracted_text`, `evidence`, `warnings` |

### Critical Frontend Verdict & Safety Rules

1. **Inconclusive Image Scans (Do NOT Mark Safe):**
   - If an uploaded image contains no readable text (`ocr_status: "no_text_detected"`) or the host server lacks an active OCR engine (`ocr_status: "ocr_unavailable"`), the endpoint returns `status 200` with `combined_verdict: "inconclusive"`, `risk_score: 0.0`, `risk_level: "inconclusive"`, and `is_confirmed_safe: false`.
   - **Frontend UI Requirement:** The frontend must render an "Inconclusive / Manual Review Required" status badge (amber/gray) rather than a green "Safe / Clean" checkmark.
2. **Image Upload Restrictions:**
   - Content-Type must be `multipart/form-data` with form field name `file`.
   - Max file size: **5 MB** (`5,242,880 bytes`).
   - Allowed file formats: **JPEG (`.jpg`, `.jpeg`), PNG (`.png`), and WebP (`.webp`)**.
   - Spoofed MIME extensions or corrupted images trigger HTTP `422 Unprocessable Content`.
3. **Text Scan Input Limits:**
   - JSON body: `{"text": "..."}`
   - Length: **1 to 5,000 characters**. Whitespace-only strings trigger HTTP `422`.
4. **URL Scan Input Limits:**
   - JSON body: `{"url": "..."}`
   - Length: **1 to 2,048 characters**. Must use `http://` or `https://` scheme. Schemes like `javascript:`, `ftp:`, or URLs with embedded credentials (`user:pass@host`) trigger HTTP `422`.
5. **Standard Error Envelopes:**
   - Any validation error (`422`), unavailable model (`503`), or internal error (`500`) consistently returns a clean JSON structure without leaking internal server paths or stack traces:
     ```json
     {
       "error": "Validation Error",
       "detail": "Descriptive reason for failure"
     }
     ```

---

## 4. Example Requests


### Health Check

#### PowerShell:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method GET | ConvertTo-Json
```

#### cURL:
```bash
curl -X GET "http://127.0.0.1:8000/health"
```

#### Sample Response:
```json
{
  "status": "ok",
  "model_loaded": true,
  "model_version": "v1.0.0-baseline-tfidf-lr",
  "api_version": "1.0.0"
}
```

---

### Scan Text for Scams

#### PowerShell (Scam Example):
```powershell
$body = @{ text = "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim." } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scans/text" -Method POST -ContentType "application/json" -Body $body | ConvertTo-Json
```

#### cURL (Scam Example):
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans/text" \
     -H "Content-Type: application/json" \
     -d '{"text": "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim."}'
```

#### Sample Response:
```json
{
  "text": "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim.",
  "label": "scam",
  "is_scam": true,
  "scam_probability": 0.9635,
  "probabilities": {
    "legitimate": 0.0365,
    "scam": 0.9635
  },
  "confidence": 0.9635,
  "model_version": "v1.0.0-baseline-tfidf-lr",
  "calibrated": false,
  "evidence": [
    {
      "token": "claim",
      "weight": 3.5058,
      "signal": "scam_indicator"
    },
    {
      "token": "urgent",
      "weight": 2.7481,
      "signal": "scam_indicator"
    },
    {
      "token": "prize",
      "weight": 2.5113,
      "signal": "scam_indicator"
    }
  ],
  "explanation": "Detected high-risk scam indicators: 'claim', 'urgent', 'prize'."
}
```

---

### Scan URL for Phishing & Scams (Milestone 2 & 3A)

Combines offline structural heuristics with a local verified threat intelligence snapshot (URLhaus & OpenPhish) without contacting external networks or fetching the submitted URL.

#### Verdict Semantics:
- **`malicious` (Critical Risk):** Confirmed match in verified threat intelligence feed (`reputation_check.matched = true`).
- **`suspicious` (High / Medium Risk):** Elevated heuristic risk signals (e.g., brand spoofing, raw IP host, punycode), without a feed match.
- **`benign` (Low Risk):** Minimal/zero heuristic risk.
- **UNKNOWN Threat Status Rule:** Non-matching URLs report `status: "unknown"` and `is_confirmed_safe: false`. A lack of threat reputation is **NOT** proof of safety.

#### PowerShell (Confirmed Threat Match Example):
```powershell
$body = @{ url = "http://malware-drop.example.com/payload.exe" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scans/url" -Method POST -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 5
```

#### Sample Response (Confirmed Threat Match):
```json
{
  "url": "http://malware-drop.example.com/payload.exe",
  "normalized_url": "http://malware-drop.example.com/payload.exe",
  "verdict": "malicious",
  "label": "malicious",
  "risk_score": 1.0,
  "risk_level": "critical",
  "heuristic_verdict": "suspicious",
  "evidence": [
    {
      "signal": "executable_download_path",
      "description": "URL path targets a direct executable file download.",
      "severity": "high",
      "weight": 0.45
    }
  ],
  "reputation_evidence": [
    {
      "signal": "reputation_threat_match",
      "source": "URLhaus",
      "match_type": "exact_url",
      "threat_type": "malware_distribution",
      "reference_id": "UH-2026-1025-01",
      "matched_pattern": "http://malware-drop.example.com/payload.exe",
      "description": "Verified match in threat intelligence feed from URLhaus.",
      "severity": "critical",
      "weight": 1.0
    }
  ],
  "analysis_method": "offline_static_heuristic_and_threat_intel_v1",
  "limitations": [
    "Analysis is strictly offline and based on static structural heuristics and local feed snapshots.",
    "No live network requests, active crawling, or dynamic DNS lookups were executed.",
    "Absence of a reputation match indicates UNKNOWN threat status, NOT confirmed safety.",
    "Heuristic risk scores represent structural suspicion, not calibrated mathematical probabilities.",
    "Legitimate newly registered domains or enterprise infrastructure may lack reputation history."
  ],
  "reputation_check": {
    "feed_available": true,
    "matched": true,
    "status": "matched",
    "match_type": "exact_url",
    "threat_type": "malware_distribution",
    "feed_source": "URLhaus",
    "reference_id": "UH-2026-1025-01",
    "confidence": 1.0,
    "feed_retrieved_at": "2026-10-26T10:00:00Z",
    "feed_age_days": 1.5,
    "is_stale": false,
    "notes": "CONFIRMED THREAT MATCH: Found in threat intelligence feed (URLhaus) as malware_distribution via exact_url match on 'http://malware-drop.example.com/payload.exe'.",
    "is_confirmed_safe": false
  }
}
```

---

### Scan Screenshot / Image for Scams (Milestone 4)

Analyzes an uploaded screenshot or image file using local OCR, ML scam prediction, and URL threat scanning.

#### Supported Image Formats:
- `JPEG` (`.jpg`, `.jpeg`)
- `PNG` (`.png`)
- `WebP` (`.webp`)
- Validation verifies actual file header magic bytes and image integrity (Pillow `verify()` and `load()`), rejecting spoofed MIME types, renamed executables, and corrupted streams.

#### Limits & Constraints:
- Maximum upload size: **5 MB**
- Maximum dimensions: **10,000 x 10,000 pixels** (25 MP total pixel limit)
- Strictly in-memory: images and OCR text are not saved to disk.

#### Combined Verdict Rules:
- **`malicious` (Critical):** Any URL extracted from the image matches verified threat intelligence.
- **`suspicious` (High / Medium):** The visible text is classified as scam OR an extracted URL exhibits suspicious heuristic signals.
- **`inconclusive`:** No readable text detected in the image, or the local OCR engine is unavailable/encountered an error. The image is **NEVER** marked safe merely because no scam was detected.
- **`benign` (Low):** Visible text was extracted, ML classified it legitimate, and all extracted URLs are benign. `is_confirmed_safe` remains `false`.

#### PowerShell (Multipart Upload Example):
```powershell
$form = @{
    file = Get-Item -Path ".\screenshot.png"
}
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scans/image" -Method POST -Form $form | ConvertTo-Json -Depth 5
```

#### cURL (Multipart Upload Example):
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans/image" \
     -F "file=@screenshot.png;type=image/png"
```

#### Sample Response (Suspicious Scam Screenshot):
```json
{
  "filename": "screenshot.png",
  "image_format": "PNG",
  "dimensions": { "width": 800, "height": 600 },
  "file_size_bytes": 142800,
  "ocr_status": "success",
  "ocr_info": {
    "status": "success",
    "engine": "tesseract",
    "characters_extracted": 112,
    "confidence": null,
    "notes": null
  },
  "extracted_text": "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim before it expires.",
  "text_analysis": {
    "text": "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim before it expires.",
    "label": "scam",
    "is_scam": true,
    "scam_probability": 0.9635,
    "probabilities": { "legitimate": 0.0365, "scam": 0.9635 },
    "confidence": 0.9635,
    "model_version": "v1.0.0-baseline-tfidf-lr",
    "calibrated": false,
    "evidence": [
      { "token": "claim", "weight": 3.5058, "signal": "scam_indicator" },
      { "token": "urgent", "weight": 2.7481, "signal": "scam_indicator" }
    ],
    "explanation": "Detected high-risk scam indicators: 'claim', 'urgent'."
  },
  "extracted_urls": [],
  "url_analyses": [],
  "combined_verdict": "suspicious",
  "verdict": "suspicious",
  "risk_score": 0.9635,
  "risk_level": "high",
  "is_confirmed_safe": false,
  "evidence": [
    {
      "source": "text",
      "signal": "text_scam_indicator",
      "description": "Model keyword indicator 'claim' (weight: 3.5058)",
      "severity": "high",
      "weight": 3.5058
    }
  ],
  "warnings": [
    "Suspicious: Visible text in the image exhibits recognized scam characteristics."
  ],
  "limitations": [
    "Visual elements, logos, watermarks, seals, and visual identity were NOT verified.",
    "Screenshot authenticity was not verified; visual images can be forged, cropped, or simulated.",
    "Analysis is limited strictly to optical character recognition (OCR) of visible text and extracted URLs.",
    "Absence of detected threat does NOT guarantee the image or sender is safe or legitimate."
  ]
}
```

---

## 5. Limitations & Scope Boundary
1. **Visual Brand & Logo Verification:** The scanner relies on optical character recognition of visible text and static heuristic analysis of extracted URLs. It does **not** verify graphical brand logos, seals, digital watermarks, or cryptographic signatures.
2. **Offline Local Processing:** No uploaded screenshots or extracted personal data are sent to external cloud APIs or persisted to local disk storage.
3. **Inconclusive Verdicts:** If an image is unreadable, blurry, contains only graphics without text, or if OCR is unavailable, the system returns `combined_verdict: "inconclusive"`. It never marks unreadable images as "safe".
4. **Threat Reputation Status:** Extracted URLs not matching the verified local snapshot are treated as `unknown`, not confirmed safe.

---

## 6. Troubleshooting
- **`Unsupported image format` (HTTP 422):** Upload only real JPEG, PNG, or WebP files. Files renamed with incorrect extensions (e.g., text or PDF files named `.png`) are identified and rejected.
- **`Image file size exceeds maximum allowed limit of 5 MB` (HTTP 422):** Compress or crop images larger than 5 MB before submitting.
- **`ocr_status: "ocr_unavailable"` in response:** Ensure Tesseract-OCR is installed on the host and located in PATH or designated via the `TESSERACT_CMD` environment variable.
- **`Image dimensions exceed maximum allowed limit` (HTTP 422):** Ensure screenshot width and height are each under 10,000 pixels.

---

## 7. Running Automated Tests
From the `ShieldAI` project root:
```powershell
# Run lightweight backend tests (API, URL heuristics, Threat Reputation, Image Scanning)
.venv\Scripts\python.exe -m unittest discover -s backend/tests -p "test_*.py" -v

# Run lightweight ML unit tests
.venv\Scripts\python.exe -m unittest discover -s ml/tests -p "test_*.py" -v
```



