import React, { useState, useRef } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Globe, 
  Mail, 
  Image as ImageIcon, 
  Upload, 
  Trash2, 
  Clipboard,
  RefreshCw, 
  XCircle, 
  Zap, 
  ChevronDown,
  ChevronUp,
  X
} from 'lucide-react';
import { normalizeUrlInput, extractProtocol, syncUrlWithProtocol } from '../utils/urlHelper';
import { scanTextMessage, scanUrl, scanImageFile } from '../utils/api';
import ScanResultCard from './ScanResultCard';

const MAX_MESSAGE_LENGTH = 5000;
const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

export default function HeroSection({ externalActivePanel, onPanelChange }) {
  // -------------------------------------------------------------
  // Message Scanner Input State
  // -------------------------------------------------------------
  const [messageText, setMessageText] = useState('');

  // -------------------------------------------------------------
  // Secondary Inline Panels State: null | 'image' | 'url'
  // -------------------------------------------------------------
  const [expandedPanel, setExpandedPanel] = useState(null);
  const [prevExternalPanel, setPrevExternalPanel] = useState(externalActivePanel);

  // Sync with external navigation triggers (e.g. from Navbar or Footer)
  if (externalActivePanel !== prevExternalPanel) {
    setPrevExternalPanel(externalActivePanel);
    if (externalActivePanel === 'text') {
      setExpandedPanel(null);
    } else if (externalActivePanel === 'url') {
      setExpandedPanel('url');
    } else if (externalActivePanel === 'image') {
      setExpandedPanel('image');
    }
  }

  // -------------------------------------------------------------
  // URL Input State
  // -------------------------------------------------------------
  const [urlProtocol, setUrlProtocol] = useState('https://');
  const [urlInput, setUrlInput] = useState('');

  // -------------------------------------------------------------
  // Image Upload State
  // -------------------------------------------------------------
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedPreview, setUploadedPreview] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  // -------------------------------------------------------------
  // Status, Loading, and Result State
  // -------------------------------------------------------------
  const [isScanning, setIsScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState('');
  const [activeScanType, setActiveScanType] = useState(null); // 'text' | 'url' | 'image'
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [clipboardNotice, setClipboardNotice] = useState(null);

  // Format file size helper
  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  // -------------------------------------------------------------
  // Clipboard Paste Handlers with Permission Error Handling
  // -------------------------------------------------------------
  const handlePasteToMessage = async () => {
    setClipboardNotice(null);
    if (!navigator.clipboard || !navigator.clipboard.readText) {
      setClipboardNotice('Clipboard access is not supported by your browser. Please paste manually using Ctrl+V.');
      return;
    }
    try {
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        setClipboardNotice('Clipboard is empty or contains no readable text.');
        return;
      }
      setMessageText(text.slice(0, MAX_MESSAGE_LENGTH));
      setScanResult(null);
      setScanError(null);
    } catch {
      setClipboardNotice('Clipboard permission was denied. Please paste your text manually (Ctrl+V).');
    }
  };

  const handlePasteToUrl = async () => {
    setClipboardNotice(null);
    if (!navigator.clipboard || !navigator.clipboard.readText) {
      setClipboardNotice('Clipboard access is not supported by your browser. Please paste manually using Ctrl+V.');
      return;
    }
    try {
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        setClipboardNotice('Clipboard is empty.');
        return;
      }
      const trimmed = text.trim();
      const detected = extractProtocol(trimmed);
      if (detected) {
        setUrlProtocol(detected);
      }
      setUrlInput(trimmed);
      setScanResult(null);
      setScanError(null);
    } catch {
      setClipboardNotice('Clipboard permission was denied. Please paste your URL manually (Ctrl+V).');
    }
  };

  // Toggle secondary inline panel
  const handleTogglePanel = (panel) => {
    setClipboardNotice(null);
    setScanError(null);
    const nextPanel = expandedPanel === panel ? null : panel;
    setExpandedPanel(nextPanel);
    if (onPanelChange) {
      onPanelChange(nextPanel);
    }
  };

  // -------------------------------------------------------------
  // Image Selection & Validation
  // -------------------------------------------------------------
  const validateAndSetImage = (file) => {
    setScanError(null);
    setClipboardNotice(null);
    if (!file) return;

    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
      setScanError({
        title: 'Unsupported Image Format',
        message: 'Please upload a PNG, JPG/JPEG, or WebP image file.'
      });
      return;
    }

    if (file.size > MAX_IMAGE_SIZE_BYTES) {
      setScanError({
        title: 'File Exceeds Limit',
        message: `Image size is ${formatFileSize(file.size)}. The maximum allowed file size is 5 MB.`
      });
      return;
    }

    setUploadedFile(file);
    const reader = new FileReader();
    reader.onload = () => {
      setUploadedPreview(reader.result);
    };
    reader.readAsDataURL(file);
  };

  const handleFileInputChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      validateAndSetImage(file);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      validateAndSetImage(file);
    }
  };

  const handleClearImage = () => {
    setUploadedFile(null);
    setUploadedPreview(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // -------------------------------------------------------------
  // URL Input Synchronization
  // -------------------------------------------------------------
  const handleUrlInputChange = (val) => {
    setUrlInput(val);
    if (scanResult) setScanResult(null);
    if (scanError) setScanError(null);

    const detected = extractProtocol(val);
    if (detected && detected !== urlProtocol) {
      setUrlProtocol(detected);
    }
  };

  const handleProtocolChange = (proto) => {
    setUrlProtocol(proto);
    if (scanResult) setScanResult(null);
    if (scanError) setScanError(null);
    setUrlInput((prev) => syncUrlWithProtocol(prev, proto));
  };

  // -------------------------------------------------------------
  // SCAN EXECUTIONS: Text, URL, Image
  // -------------------------------------------------------------
  
  // 1. Scan Message
  const handleScanMessage = async () => {
    const raw = messageText.trim();
    if (!raw) {
      setScanError({
        title: 'Input Required',
        message: 'Please enter or paste message text to scan.'
      });
      return;
    }

    setIsScanning(true);
    setActiveScanType('text');
    setScanResult(null);
    setScanError(null);
    setScanPhase('Analyzing text with ScamX ML Classifier (TF-IDF & Logistic Regression)...');

    try {
      const response = await scanTextMessage(raw);
      if (!response.ok) {
        let msg = `Server returned HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) msg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
          else if (errJson.error) msg = errJson.error;
        } catch {
          // ignore
        }
        setScanError({
          title: response.status === 422 ? 'Validation Error' : 'Scan Failed',
          message: msg
        });
        return;
      }

      const data = await response.json();
      const scamProb = Number(data.scam_probability || 0);
      const scamPct = Math.round(scamProb * 100);
      const isScam = data.is_scam === true || data.label === 'scam';
      const isSuspicious = !isScam && scamProb >= 0.35;
      const isInconclusive = false;
      const badgeLabel = isScam ? 'Likely Scam' : isSuspicious ? 'Suspicious' : 'Low Risk';

      setScanResult({
        scannerType: 'text',
        target: raw.slice(0, 70) + (raw.length > 70 ? '...' : ''),
        timestamp: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        label: data.label,
        isDanger: isScam,
        isSuspicious,
        isInconclusive,
        badgeLabel,
        scorePercent: scamPct,
        scoreLabel: 'Scam Likelihood',
        modelVersion: data.model_version || 'v1.0.0-baseline-tfidf-lr',
        explanation: data.explanation || (isScam ? 'High-risk scam phrasing and urgency triggers detected in message.' : 'No prominent scam patterns detected in message.'),
        recommendation: isScam 
          ? 'Do not click links or share OTPs. Verify through the official channel.'
          : 'No threat indicators detected. Always remain cautious with unfamiliar senders.',
        evidence: Array.isArray(data.evidence) ? data.evidence.map(e => ({
          token: e.token,
          desc: e.signal === 'scam_indicator' ? 'Scam keyword indicator' : 'Standard communication indicator',
          weight: e.weight,
          signal: e.signal
        })) : []
      });

      setTimeout(() => {
        const resultEl = document.getElementById('scan-result-card');
        if (resultEl) resultEl.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } catch {
      setScanError({
        title: 'Backend Unavailable',
        message: 'Cannot connect to ScamX backend at http://127.0.0.1:8000. Please ensure the backend server is running.'
      });
    } finally {
      setIsScanning(false);
      setScanPhase('');
    }
  };

  // 2. Scan URL
  const handleScanUrl = async () => {
    const raw = urlInput.trim();
    if (!raw) {
      setScanError({
        title: 'URL Required',
        message: 'Please enter a website link or domain to scan.'
      });
      return;
    }

    const fullUrl = normalizeUrlInput(raw, urlProtocol);
    setIsScanning(true);
    setActiveScanType('url');
    setScanResult(null);
    setScanError(null);
    setScanPhase('Inspecting URL structure, punycode spoofing, and threat intelligence feeds...');

    try {
      const response = await scanUrl(fullUrl);
      if (!response.ok) {
        let msg = `Server returned HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) msg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
          else if (errJson.error) msg = errJson.error;
        } catch {
          // ignore
        }
        setScanError({
          title: response.status === 422 ? 'Invalid URL Syntax' : 'URL Scan Failed',
          message: msg
        });
        return;
      }

      const data = await response.json();
      const riskScore = Number(data.risk_score || 0);
      const scorePct = Math.round(riskScore * 100);
      const verdict = (data.verdict || 'benign').toLowerCase();
      const riskLevel = (data.risk_level || 'low').toLowerCase();

      const isDanger = verdict === 'malicious' || riskLevel === 'critical';
      const isSuspicious = verdict === 'suspicious' || riskLevel === 'high' || riskLevel === 'medium';
      const isInconclusive = verdict === 'inconclusive' || riskLevel === 'inconclusive';

      const badgeLabel = isDanger
        ? 'Likely Scam'
        : isSuspicious
        ? 'Suspicious'
        : isInconclusive
        ? 'Inconclusive'
        : 'Low Risk';

      const explanation = isDanger
        ? 'High-risk heuristic signals detected: lookalike domain, punycode spoofing, or local threat feed match.'
        : isSuspicious
        ? 'Suspicious heuristic markers detected in URL structure. Verify domain ownership before submitting personal details.'
        : isInconclusive
        ? 'Offline static heuristics could not reach a conclusive determination.'
        : scorePct > 0
        ? `Static heuristics detected minor structural signals (${data.evidence?.map(e => e.signal).join(', ') || 'such as domain hyphens'}) contributing ${scorePct}% risk, below the suspicious threshold (30%). Offline analysis cannot verify safety.`
        : 'No structural anomalies detected in URL syntax. Offline static analysis cannot confirm guaranteed safety.';

      const recommendation = isDanger
        ? 'Do not open this link or submit credentials. Avoid navigating to this domain.'
        : isSuspicious
        ? 'Exercise caution: Verify domain authenticity through independent, official channels.'
        : isInconclusive
        ? 'Inconclusive heuristic analysis. Do not enter credentials on unverified websites.'
        : 'Do not submit sensitive credentials unless you have independently verified the official domain.';

      setScanResult({
        scannerType: 'url',
        target: data.normalized_url || fullUrl,
        timestamp: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        label: verdict,
        isDanger,
        isSuspicious,
        isInconclusive,
        badgeLabel,
        scorePercent: scorePct,
        scoreLabel: 'Heuristic Risk Score',
        modelVersion: data.analysis_method || 'offline_static_heuristic_v1',
        explanation,
        recommendation,
        evidence: Array.isArray(data.evidence) ? data.evidence.map(e => ({
          token: e.signal,
          desc: e.description,
          weight: e.weight,
          severity: e.severity || (e.weight >= 0.4 ? 'high' : e.weight >= 0.2 ? 'medium' : 'low'),
          signal: 'scam_indicator' // All detected URL heuristics represent risk signals / anomalies
        })) : [],
        reputationCheck: data.reputation_check,
        limitations: Array.isArray(data.limitations) ? data.limitations : []
      });

      setTimeout(() => {
        const resultEl = document.getElementById('scan-result-card');
        if (resultEl) resultEl.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } catch {
      setScanError({
        title: 'Backend Unavailable',
        message: 'Cannot connect to ScamX backend at http://127.0.0.1:8000. Please ensure the backend server is running.'
      });
    } finally {
      setIsScanning(false);
      setScanPhase('');
    }
  };

  // 3. Scan Image
  const handleScanImage = async () => {
    if (!uploadedFile) {
      setScanError({
        title: 'Image Required',
        message: 'Please select or drop an image file (PNG, JPG, or WebP) to scan.'
      });
      return;
    }

    setIsScanning(true);
    setActiveScanType('image');
    setScanResult(null);
    setScanError(null);
    setScanPhase('Extracting text with OCR and scanning for scam patterns...');

    try {
      const response = await scanImageFile(uploadedFile);
      if (!response.ok) {
        let msg = `Server returned HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) msg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
          else if (errJson.error) msg = errJson.error;
        } catch {
          // ignore
        }
        setScanError({
          title: 'Screenshot Scan Failed',
          message: msg
        });
        return;
      }

      const data = await response.json();
      const riskScore = Number(data.risk_score || 0);
      const scorePct = Math.round(riskScore * 100);
      const verdict = (data.combined_verdict || data.verdict || 'benign').toLowerCase();
      const riskLevel = (data.risk_level || 'low').toLowerCase();

      const isDanger = verdict === 'malicious' || riskLevel === 'critical';
      const isSuspicious = verdict === 'suspicious' || riskLevel === 'high' || riskLevel === 'medium';
      const isInconclusive = verdict === 'inconclusive' || riskLevel === 'inconclusive' || data.ocr_status === 'no_text_detected';

      const badgeLabel = isDanger
        ? 'Likely Scam'
        : isSuspicious
        ? 'Suspicious'
        : isInconclusive
        ? 'Inconclusive'
        : 'Low Risk';

      const charsCount = data.ocr_info?.characters_extracted ?? data.extracted_text?.length ?? 0;
      const textDetected = charsCount > 0;

      const explanation = data.text_analysis?.explanation
        ? data.text_analysis.explanation
        : textDetected
        ? (scorePct > 0
            ? `Extracted text evaluated as low risk (${scorePct}% risk score). Minor patterns did not exceed the scam threshold.`
            : 'Extracted text evaluated as low risk. No recognized scam patterns detected.')
        : 'No readable text detected in screenshot. Inconclusive analysis.';

      const recommendation = isDanger
        ? 'Critical scam patterns or malicious links detected in screenshot. Do not interact with the sender.'
        : isSuspicious
        ? 'Suspicious requests or deceptive patterns detected. Verify through independent official channels.'
        : isInconclusive
        ? 'Insufficient readable text to determine authenticity. Never assume unreadable content is safe.'
        : 'No obvious scam indicators detected. Continue to exercise normal security precautions.';

      setScanResult({
        scannerType: 'image',
        target: data.filename || uploadedFile.name,
        timestamp: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        label: verdict,
        isDanger,
        isSuspicious,
        isInconclusive,
        badgeLabel,
        scorePercent: scorePct,
        scoreLabel: 'Risk Score',
        modelVersion: `OCR Engine: ${data.ocr_info?.engine || 'tesseract'}`,
        explanation,
        recommendation,
        ocrInfo: data.ocr_info,
        extractedText: data.extracted_text,
        extractedUrls: data.extracted_urls,
        evidence: Array.isArray(data.evidence) ? data.evidence.map(e => ({
          token: e.token || (e.signal ? e.signal.replace(/^(text_|url_)/, '') : 'indicator'),
          desc: e.description,
          weight: e.weight != null ? e.weight : (e.severity === 'high' ? 1.0 : 0.5),
          signal: (e.severity === 'high' || e.severity === 'critical' || (e.signal && e.signal.includes('scam')))
            ? 'scam_indicator'
            : 'legitimate_indicator'
        })) : [],
        warnings: Array.isArray(data.warnings) ? data.warnings : [],
        limitations: Array.isArray(data.limitations) ? data.limitations : []
      });

      setTimeout(() => {
        const resultEl = document.getElementById('scan-result-card');
        if (resultEl) resultEl.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } catch {
      setScanError({
        title: 'Backend Unavailable',
        message: 'Cannot connect to ScamX backend at http://127.0.0.1:8000. Please ensure the backend server is running.'
      });
    } finally {
      setIsScanning(false);
      setScanPhase('');
    }
  };

  return (
    <section id="scanner-interface" className="relative pt-6 pb-12 sm:pt-8 md:pt-10 md:pb-16 overflow-hidden bg-plus-grid scroll-mt-24 sm:scroll-mt-28">
      
      {/* Decorative Radial Lighting Blurs */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-emerald-400/15 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="absolute top-20 right-10 w-[300px] h-[300px] bg-emerald-300/10 rounded-full blur-[100px] pointer-events-none -z-10" />

      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Top Trust Ribbon */}
        <div className="flex justify-center mb-4 sm:mb-5">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-emerald-100/90 border border-emerald-300/80 text-emerald-900 text-xs sm:text-sm font-semibold shadow-xs hover:bg-emerald-200/70 transition-colors">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-600"></span>
            </span>
            <span>AI-Assisted Scam Detection for Messages, Links & Screenshots</span>
            <span className="text-emerald-700 font-bold">→</span>
          </div>
        </div>

        {/* Hero Headings */}
        <div className="text-center max-w-2xl mx-auto mb-6 sm:mb-8">
          <h1 className="text-3xl sm:text-5xl font-extrabold text-[#052418] tracking-tight leading-[1.14]">
            Detect scams{' '}
            <span className="text-emerald-500 relative inline-block">
              before you click.
              <svg className="absolute -bottom-1.5 left-0 w-full h-2.5 text-emerald-400" viewBox="0 0 250 12" fill="none" preserveAspectRatio="none">
                <path d="M3 8.5C65 2.5 185 2 247 8.5" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
              </svg>
            </span>
          </h1>

          <p className="mt-3 text-sm sm:text-lg text-slate-700 font-medium max-w-xl mx-auto leading-relaxed">
            Analyze suspicious messages, links, and screenshots with AI-assisted scam detection.
          </p>
        </div>

        {/* ----------------------------------------------------------- */}
        {/* MAIN LIVE SCANNER WORKSPACE                                  */}
        {/* ----------------------------------------------------------- */}
        <div id="scanner-card" className="relative bg-white/95 backdrop-blur-md rounded-2xl sm:rounded-3xl p-4 sm:p-6 border-2 border-emerald-200/90 shadow-xl shadow-emerald-950/10 scroll-mt-24 sm:scroll-mt-28">
          
          {/* Header Bar of the Scanner Input */}
          <div className="flex flex-wrap items-center justify-between pb-2.5 mb-2.5 border-b border-slate-100 gap-2">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-700">
              <Mail className="w-3.5 h-3.5 text-emerald-600" />
              <span>Message Scanner</span>
            </div>
            
            <div className="flex items-center gap-3 text-xs">
              <span className="font-mono text-slate-500 text-[11px]">
                {messageText.length} / {MAX_MESSAGE_LENGTH} characters
              </span>
              {messageText && (
                <button
                  onClick={() => {
                    setMessageText('');
                    setScanResult(null);
                    setScanError(null);
                  }}
                  className="text-slate-400 hover:text-slate-700 text-xs font-semibold"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Multiline Message Textarea & Prominent Scan Button Layout */}
          <div className="flex flex-col lg:flex-row gap-3 sm:gap-3.5 items-stretch">
            
            {/* Input Box with Toolbar (desktop height ~140px) */}
            <div className="flex-1 relative rounded-2xl border-2 border-slate-200 focus-within:border-emerald-500 focus-within:ring-2 focus-within:ring-emerald-500/20 bg-slate-50/60 transition-all overflow-hidden flex flex-col justify-between lg:h-[142px]">
              
              <textarea
                id="message-textarea"
                rows={3}
                value={messageText}
                maxLength={MAX_MESSAGE_LENGTH}
                onChange={(e) => {
                  setMessageText(e.target.value);
                  if (scanResult) setScanResult(null);
                  if (scanError) setScanError(null);
                }}
                placeholder="Paste a suspicious SMS, WhatsApp message, or email here…"
                className="w-full flex-1 min-h-[76px] sm:min-h-[82px] bg-transparent p-3 sm:p-3.5 text-sm sm:text-[15px] text-slate-900 placeholder:text-slate-400 focus:outline-none resize-none leading-snug font-sans"
              />

              {/* Bottom Toolbar: Compact Paste Button & Character Counter */}
              <div className="px-3 py-1.5 bg-white/90 border-t border-slate-100 flex items-center justify-between">
                <button
                  type="button"
                  id="paste-message-btn"
                  onClick={handlePasteToMessage}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-50 hover:bg-emerald-100 text-emerald-800 text-xs font-bold border border-emerald-200/90 transition-colors shadow-2xs"
                  title="Paste text from clipboard"
                >
                  <Clipboard className="w-3.5 h-3.5" />
                  <span>Paste</span>
                </button>

                <span className="font-mono text-slate-400 text-[11px]">
                  {messageText.length} / {MAX_MESSAGE_LENGTH} characters
                </span>
              </div>

            </div>

            {/* Desktop: Scan Message Button (~142px on desktop aligned with textarea, stacks full-width on mobile) */}
            <div className="lg:w-44 flex items-stretch">
              <button
                type="button"
                id="scan-message-btn"
                onClick={handleScanMessage}
                disabled={isScanning}
                className="w-full h-11 lg:h-[142px] px-5 rounded-2xl bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 active:from-emerald-700 active:to-emerald-800 text-white font-extrabold text-sm sm:text-base tracking-wide shadow-lg shadow-emerald-700/20 hover:shadow-emerald-600/35 hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-60 disabled:cursor-not-allowed transition-all flex lg:flex-col items-center justify-center gap-1.5 sm:gap-2 group"
              >
                {isScanning && activeScanType === 'text' ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-5 h-5 fill-emerald-200 text-emerald-100 group-hover:scale-110 transition-transform" />
                    <span>Scan Message</span>
                  </>
                )}
              </button>
            </div>

          </div>

          {/* Clipboard Notice Alert if permission denied or unsupported */}
          {clipboardNotice && (
            <div className="mt-2.5 p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-700 flex-shrink-0" />
                <span>{clipboardNotice}</span>
              </div>
              <button onClick={() => setClipboardNotice(null)} className="text-amber-700 hover:text-amber-950">
                <XCircle className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* ----------------------------------------------------------- */}
          {/* SECONDARY ACTIONS: Upload Image & Check URL                  */}
          {/* ----------------------------------------------------------- */}
          <div className="mt-3.5 pt-3 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
              Additional Detection Options:
            </span>

            <div className="flex items-center gap-2 sm:justify-end">
              {/* Option A: Upload Image Button */}
              <button
                type="button"
                id="toggle-upload-image-btn"
                onClick={() => handleTogglePanel('image')}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 border-2 ${
                  expandedPanel === 'image'
                    ? 'bg-teal-50 text-teal-900 border-teal-500 shadow-xs'
                    : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200 hover:border-slate-300'
                }`}
              >
                <ImageIcon className={`w-3.5 h-3.5 ${expandedPanel === 'image' ? 'text-teal-600' : 'text-slate-500'}`} />
                <span>Upload Image</span>
                {expandedPanel === 'image' ? (
                  <ChevronUp className="w-3.5 h-3.5 text-teal-700 ml-0.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 ml-0.5" />
                )}
              </button>

              {/* Option B: Check URL Button */}
              <button
                type="button"
                id="toggle-check-url-btn"
                onClick={() => handleTogglePanel('url')}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 border-2 ${
                  expandedPanel === 'url'
                    ? 'bg-cyan-50 text-cyan-900 border-cyan-500 shadow-xs'
                    : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200 hover:border-slate-300'
                }`}
              >
                <Globe className={`w-3.5 h-3.5 ${expandedPanel === 'url' ? 'text-cyan-600' : 'text-slate-500'}`} />
                <span>Check URL</span>
                {expandedPanel === 'url' ? (
                  <ChevronUp className="w-3.5 h-3.5 text-cyan-700 ml-0.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 ml-0.5" />
                )}
              </button>
            </div>
          </div>

          {/* ----------------------------------------------------------- */}
          {/* INLINE PANEL 1: UPLOAD IMAGE FLOW                           */}
          {/* ----------------------------------------------------------- */}
          {expandedPanel === 'image' && (
            <div className="mt-3 p-3.5 sm:p-4 rounded-xl bg-teal-50/40 border border-teal-200 animate-in fade-in slide-in-from-top-2 duration-200 space-y-2.5">
              
              <div className="flex items-center justify-between pb-1.5 border-b border-teal-100">
                <div className="flex items-center gap-1.5">
                  <ImageIcon className="w-3.5 h-3.5 text-teal-700" />
                  <span className="text-xs font-bold text-teal-950 uppercase tracking-wider">
                    Screenshot & Chat Image Scanner
                  </span>
                </div>
                <button
                  onClick={() => setExpandedPanel(null)}
                  className="text-xs text-slate-400 hover:text-slate-700"
                >
                  Close
                </button>
              </div>

              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileInputChange}
                accept="image/png, image/jpeg, image/webp"
                className="hidden"
              />

              {uploadedPreview ? (
                /* Selected Image Preview State */
                <div className="rounded-xl border border-teal-300 bg-white p-3 space-y-2.5">
                  <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
                    <div className="flex items-center gap-2 truncate max-w-[240px] sm:max-w-md">
                      <ImageIcon className="w-3.5 h-3.5 text-teal-600 flex-shrink-0" />
                      <span className="text-xs font-bold text-slate-900 truncate">
                        {uploadedFile?.name}
                      </span>
                      <span className="text-[11px] text-slate-500 font-mono">
                        ({formatFileSize(uploadedFile?.size)})
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        className="px-2.5 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold"
                      >
                        Change
                      </button>
                      <button
                        type="button"
                        onClick={handleClearImage}
                        className="p-1 rounded hover:bg-red-50 text-red-600"
                        title="Remove image"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  <div className="max-h-44 overflow-hidden rounded-lg flex items-center justify-center bg-slate-900/5 p-1.5">
                    <img
                      src={uploadedPreview}
                      alt="Uploaded screenshot preview"
                      className="max-h-40 object-contain rounded shadow-2xs"
                    />
                  </div>

                  {/* Prominent Scan Image Button (Displayed after valid image selection) */}
                  <div className="pt-1 flex justify-end">
                    <button
                      type="button"
                      id="scan-image-btn"
                      onClick={handleScanImage}
                      disabled={isScanning}
                      className="w-full sm:w-auto px-5 py-2 rounded-xl bg-gradient-to-r from-teal-600 to-emerald-600 hover:from-teal-500 hover:to-emerald-500 text-white font-extrabold text-xs sm:text-sm shadow-md shadow-teal-700/20 flex items-center justify-center gap-2 disabled:opacity-60 transition-all"
                    >
                      {isScanning && activeScanType === 'image' ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Scanning Image with OCR...</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-4 h-4" />
                          <span>Scan Image</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ) : (
                /* Drag and drop / picker placeholder (~115-125px on desktop) */
                <div
                  id="image-dropzone"
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  className={`h-[115px] sm:h-[125px] flex flex-col items-center justify-center px-4 py-2 border-2 border-dashed rounded-xl cursor-pointer text-center transition-all bg-white ${
                    isDragging
                      ? 'border-teal-500 bg-teal-50/80 scale-[1.01]'
                      : 'border-teal-300 hover:border-teal-500 hover:bg-teal-50/30'
                  }`}
                >
                  <div className="w-8 h-8 rounded-lg bg-teal-100 text-teal-700 flex items-center justify-center mb-1.5 shadow-2xs">
                    <Upload className="w-4 h-4" />
                  </div>
                  <div className="text-xs sm:text-sm font-bold text-slate-800">
                    Click to browse or drag & drop screenshot here
                  </div>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Accepts PNG, JPG/JPEG, and WebP (up to 5 MB)
                  </p>
                </div>
              )}

            </div>
          )}

          {/* ----------------------------------------------------------- */}
          {/* INLINE PANEL 2: CHECK URL FLOW                              */}
          {/* ----------------------------------------------------------- */}
          {expandedPanel === 'url' && (
            <div className="mt-3 p-3.5 sm:p-4 rounded-xl bg-cyan-50/40 border border-cyan-200 animate-in fade-in slide-in-from-top-2 duration-200 space-y-2.5">
              
              <div className="flex items-center justify-between pb-1.5 border-b border-cyan-100">
                <div className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-cyan-700" />
                  <span className="text-xs font-bold text-cyan-950 uppercase tracking-wider">
                    URL Safety & Phishing Checker
                  </span>
                </div>
                <button
                  onClick={() => setExpandedPanel(null)}
                  className="text-xs text-slate-400 hover:text-slate-700"
                >
                  Close
                </button>
              </div>

              {/* URL Input Row with Protocol Dropdown, Input, Paste button, and Scan URL button */}
              <div className="flex flex-col sm:flex-row gap-2">
                
                <div className="flex-1 flex rounded-xl border border-cyan-300 bg-white focus-within:border-cyan-500 focus-within:ring-2 focus-within:ring-cyan-500/20 overflow-hidden shadow-2xs">
                  <select
                    value={urlProtocol}
                    onChange={(e) => handleProtocolChange(e.target.value)}
                    className="bg-cyan-50/80 text-xs font-mono font-bold text-cyan-800 px-2.5 py-2 border-r border-cyan-200 focus:outline-none"
                  >
                    <option value="https://">https://</option>
                    <option value="http://">http://</option>
                  </select>

                  <input
                    type="text"
                    id="url-input-field"
                    value={urlInput}
                    onChange={(e) => handleUrlInputChange(e.target.value)}
                    placeholder="Paste a suspicious website link here…"
                    className="flex-1 px-3 py-2 text-xs sm:text-sm font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none bg-transparent"
                  />

                  <button
                    type="button"
                    id="paste-url-btn"
                    onClick={handlePasteToUrl}
                    className="px-2.5 text-cyan-700 hover:text-cyan-950 text-xs font-bold flex items-center gap-1 border-l border-slate-100 hover:bg-cyan-50/50 transition-colors"
                    title="Paste URL from clipboard"
                  >
                    <Clipboard className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Paste</span>
                  </button>
                </div>

                <button
                  type="button"
                  id="scan-url-btn"
                  onClick={handleScanUrl}
                  disabled={isScanning}
                  className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500 text-white font-extrabold text-xs sm:text-sm shadow-md shadow-cyan-700/20 flex items-center justify-center gap-2 disabled:opacity-60 transition-all whitespace-nowrap h-10 sm:h-auto"
                >
                  {isScanning && activeScanType === 'url' ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Scanning...</span>
                    </>
                  ) : (
                    <>
                      <Globe className="w-3.5 h-3.5" />
                      <span>Scan URL</span>
                    </>
                  )}
                </button>

              </div>

            </div>
          )}

          {/* ----------------------------------------------------------- */}
          {/* SCAN IN-PROGRESS LOADING STATE                              */}
          {/* ----------------------------------------------------------- */}
          {isScanning && (
            <div className="mt-3.5 p-3 rounded-xl bg-emerald-50 border border-emerald-200 animate-pulse text-xs text-emerald-900 flex items-center gap-3">
              <RefreshCw className="w-4 h-4 text-emerald-600 animate-spin flex-shrink-0" />
              <div className="flex-1">
                <div className="font-bold">Analyzing threat signals with ScamX Engine...</div>
                <div className="text-[11px] text-emerald-700 font-mono mt-0.5">{scanPhase}</div>
              </div>
            </div>
          )}

          {/* ----------------------------------------------------------- */}
          {/* ERROR ALERT DISPLAY                                         */}
          {/* ----------------------------------------------------------- */}
          {scanError && !isScanning && (
            <div className="mt-3.5 p-3 rounded-xl bg-red-50 border border-red-200 text-red-950 text-xs space-y-2 animate-in fade-in">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-red-800">
                  <AlertTriangle className="w-4 h-4 text-red-600 flex-shrink-0" />
                  <span>{scanError.title || 'Scan Error'}</span>
                </div>
                <button
                  onClick={() => setScanError(null)}
                  className="text-red-400 hover:text-red-700"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="text-slate-700 leading-relaxed font-mono text-[11px] bg-white p-2.5 rounded-lg border border-red-100">
                {scanError.message}
              </div>
            </div>
          )}

          {/* ----------------------------------------------------------- */}
          {/* INLINE SCAN RESULT SHOWCASE                                 */}
          {/* ----------------------------------------------------------- */}
          {scanResult && !isScanning && (
            <div id="scan-result-card" className="scroll-mt-24 sm:scroll-mt-28">
              <ScanResultCard
                result={scanResult}
                onDismiss={() => setScanResult(null)}
              />
            </div>
          )}

        </div>

      </div>

    </section>
  );
}
