"""Real OCR verification script for ScamShield-AI Milestone 4.

Verifies:
1. Host Tesseract OCR binary availability & fallback behavior.
2. RapidOCR ONNX local provider availability (real, unmocked OCR).
3. Real, unmocked text extraction through POST /api/v1/scans/image:
   - Harmless sample -> real text extracted -> ML legitimate -> benign verdict.
   - Suspicious sample -> real text & malicious URL extracted -> threat reputation match -> malicious verdict.
4. Blank / unreadable image -> no_text_detected -> inconclusive verdict guarantee.
5. Regression check of existing text, URL, and health endpoints.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure OpenBLAS thread count is safely clamped
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

from backend.app.image_scanner import (
    RapidOCRProvider,
    TesseractOCRProvider,
    find_tesseract_binary,
    get_ocr_provider,
    set_ocr_provider,
)
from backend.app.main import app


def render_image_with_text(lines: list[str], size=(800, 220), font_size=24) -> bytes:
    """Generate a clean image with visible rendered text using Pillow scalable font."""
    img = Image.new("RGB", size, color="white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default(size=font_size)
    except Exception:
        font = ImageFont.load_default()

    y = 30
    for line in lines:
        draw.text((30, y), line, fill="black", font=font)
        y += font_size + 15

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def run_verification():
    print("=" * 75)
    print("ScamShield-AI Milestone 4: Real Local OCR Verification")
    print("=" * 75)

    # -------------------------------------------------------------------
    # Step 1: Check Tesseract binary in Windows environment
    # -------------------------------------------------------------------
    print("\n[Step 1] Checking Tesseract OCR binary in Windows environment...")
    tess_in_path = shutil.which("tesseract")
    env_tess_cmd = os.environ.get("TESSERACT_CMD")
    discovered_tess = find_tesseract_binary()

    print(f"  - shutil.which('tesseract'):       {tess_in_path}")
    print(f"  - env['TESSERACT_CMD']:            {env_tess_cmd}")
    print(f"  - find_tesseract_binary():         {discovered_tess}")

    tess_provider = TesseractOCRProvider()
    print(f"  - TesseractOCRProvider.is_available(): {tess_provider.is_available()}")
    if not tess_provider.is_available():
        print("  -> Tesseract binary is NOT installed on this Windows host.")

    # -------------------------------------------------------------------
    # Step 2: Check RapidOCR local ONNX provider
    # -------------------------------------------------------------------
    print("\n[Step 2] Checking RapidOCR local ONNX provider...")
    rapid_provider = RapidOCRProvider()
    print(f"  - RapidOCRProvider.is_available():     {rapid_provider.is_available()}")
    if rapid_provider.is_available():
        print("  -> STATUS: RapidOCR local ONNX engine is INSTALLED and operational.")
    else:
        print("  -> STATUS: RapidOCR engine is NOT available.")

    # Active default provider
    active_provider = get_ocr_provider()
    print(f"  - Active Default Provider:             {active_provider.__class__.__name__}")

    # -------------------------------------------------------------------
    # Step 3: Test Real OCR Provider Directly (NO MOCKS)
    # -------------------------------------------------------------------
    print("\n[Step 3] Direct Real OCR Extraction Test (NO MOCKS)...")
    sample_lines = [
        "Urgent Notice: Account security verification required.",
        "Please visit http://malware-drop.example.com/payload.exe to confirm."
    ]
    test_img_bytes = render_image_with_text(sample_lines)
    pil_test_img = Image.open(io.BytesIO(test_img_bytes))

    extracted_text, ocr_info = active_provider.extract_text(pil_test_img)
    print(f"  - OCR Engine:            {ocr_info.engine}")
    print(f"  - OCR Status:            {ocr_info.status}")
    print(f"  - Characters Extracted:  {ocr_info.characters_extracted}")
    print(f"  - Average Confidence:    {ocr_info.confidence}")
    print(f"  - Extracted Text:        {repr(extracted_text)}")
    assert ocr_info.status == "success", f"Direct extraction failed: {ocr_info.status}"
    assert ocr_info.characters_extracted > 0, "No characters extracted!"
    print("  -> Direct real OCR extraction SUCCEEDED.")

    # -------------------------------------------------------------------
    # Step 4: Real End-to-End API Scans via POST /api/v1/scans/image (NO MOCKS)
    # -------------------------------------------------------------------
    print("\n[Step 4] End-to-End API Testing via POST /api/v1/scans/image (NO MOCKS)...")
    set_ocr_provider(None)  # Use active local provider
    client = TestClient(app)

    # 4A. Harmless Synthetic Sample
    print("\n  [Sample A: Harmless Message]")
    harmless_lines = [
        "Hey Alex, are we still meeting in the computer lab at 3pm today?",
        "Let me know if the schedule changes."
    ]
    harmless_bytes = render_image_with_text(harmless_lines)
    resp_a = client.post(
        "/api/v1/scans/image",
        files={"file": ("harmless_notice.png", harmless_bytes, "image/png")},
    )
    print(f"  - HTTP Status Code:  {resp_a.status_code}")
    data_a = resp_a.json()
    print(f"  - OCR Engine Used:   {data_a['ocr_info']['engine']}")
    print(f"  - OCR Status:        {data_a['ocr_status']}")
    print(f"  - Extracted Text:    {repr(data_a['extracted_text'])}")
    print(f"  - Text ML Label:     {data_a['text_analysis']['label'] if data_a['text_analysis'] else None}")
    print(f"  - Combined Verdict:  {data_a['combined_verdict']}")
    print(f"  - Risk Score:        {data_a['risk_score']}")
    print(f"  - Risk Level:        {data_a['risk_level']}")
    print(f"  - is_confirmed_safe: {data_a['is_confirmed_safe']}")
    assert data_a["ocr_status"] == "success"
    assert data_a["combined_verdict"] == "benign"
    assert data_a["is_confirmed_safe"] is False
    print("  -> Sample A verification PASSED (Real OCR extracted legitimate text -> Benign).")

    # 4B. Clearly Suspicious Synthetic Sample (Scam text + Malicious Threat Feed URL)
    print("\n  [Sample B: Clearly Suspicious Message]")
    suspicious_lines = [
        "URGENT! You have won a 1000 cash prize! Call right now.",
        "Claim reward immediately: http://malware-drop.example.com/payload.exe"
    ]
    suspicious_bytes = render_image_with_text(suspicious_lines)
    resp_b = client.post(
        "/api/v1/scans/image",
        files={"file": ("suspicious_alert.png", suspicious_bytes, "image/png")},
    )
    print(f"  - HTTP Status Code:  {resp_b.status_code}")
    data_b = resp_b.json()
    print(f"  - OCR Engine Used:   {data_b['ocr_info']['engine']}")
    print(f"  - OCR Status:        {data_b['ocr_status']}")
    print(f"  - Extracted Text:    {repr(data_b['extracted_text'])}")
    print(f"  - Extracted URLs:    {data_b['extracted_urls']}")
    print(f"  - Text ML Label:     {data_b['text_analysis']['label'] if data_b['text_analysis'] else None}")
    print(f"  - Combined Verdict:  {data_b['combined_verdict']}")
    print(f"  - Risk Score:        {data_b['risk_score']}")
    print(f"  - Risk Level:        {data_b['risk_level']}")
    print(f"  - is_confirmed_safe: {data_b['is_confirmed_safe']}")
    assert data_b["ocr_status"] == "success"
    assert "http://malware-drop.example.com/payload.exe" in data_b["extracted_urls"]
    assert data_b["combined_verdict"] == "malicious"
    assert data_b["risk_score"] == 1.0
    assert data_b["risk_level"] == "critical"
    print("  -> Sample B verification PASSED (Real OCR extracted scam text & threat URL -> Malicious).")

    # -------------------------------------------------------------------
    # Step 5: Blank Image Inconclusive Guarantee
    # -------------------------------------------------------------------
    print("\n[Step 5] Blank Image Test (NO MOCKS)...")
    blank_img = Image.new("RGB", (200, 200), color="white")
    blank_buf = io.BytesIO()
    blank_img.save(blank_buf, format="PNG")
    resp_blank = client.post(
        "/api/v1/scans/image",
        files={"file": ("blank.png", blank_buf.getvalue(), "image/png")},
    )
    data_blank = resp_blank.json()
    print(f"  - OCR Status:        {data_blank['ocr_status']}")
    print(f"  - Combined Verdict:  {data_blank['combined_verdict']}")
    print(f"  - Risk Level:        {data_blank['risk_level']}")
    print(f"  - is_confirmed_safe: {data_blank['is_confirmed_safe']}")
    assert data_blank["ocr_status"] == "no_text_detected"
    assert data_blank["combined_verdict"] == "inconclusive"
    assert data_blank["is_confirmed_safe"] is False
    print("  -> Blank image returned INCONCLUSIVE (never marked safe).")

    # -------------------------------------------------------------------
    # Step 6: Tesseract Fallback Verification
    # -------------------------------------------------------------------
    print("\n[Step 6] Tesseract Fallback Verification (when selected via config)...")
    # Simulate Tesseract provider execution
    tess_test = TesseractOCRProvider(tesseract_cmd="C:\\nonexistent_tesseract.exe")
    tess_text, tess_info = tess_test.extract_text(pil_test_img)
    print(f"  - Tesseract Status:  {tess_info.status}")
    print(f"  - Tesseract Notes:   {tess_info.notes}")
    assert tess_info.status == "ocr_unavailable"
    print("  -> Tesseract graceful fallback confirmed.")

    # -------------------------------------------------------------------
    # Step 7: Existing Endpoints Regression Check
    # -------------------------------------------------------------------
    print("\n[Step 7] Checking regression compatibility on existing endpoints...")
    h_resp = client.get("/health")
    print(f"  - GET /health:             HTTP {h_resp.status_code}, status={h_resp.json().get('status')}")
    assert h_resp.status_code == 200

    t_resp = client.post("/api/v1/scans/text", json={"text": "URGENT! You won cash! Call now."})
    print(f"  - POST /scans/text:        HTTP {t_resp.status_code}, label={t_resp.json().get('label')}")
    assert t_resp.status_code == 200

    u_resp = client.post("/api/v1/scans/url", json={"url": "http://malware-drop.example.com/payload.exe"})
    print(f"  - POST /scans/url:         HTTP {u_resp.status_code}, verdict={u_resp.json().get('verdict')}")
    assert u_resp.status_code == 200

    print("\n" + "=" * 75)
    print("REAL OCR VERIFICATION SUCCESSFULLY COMPLETED!")
    print("=" * 75)


if __name__ == "__main__":
    run_verification()
