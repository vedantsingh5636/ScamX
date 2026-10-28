import React, { useState, useRef } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Globe, 
  Mail, 
  Image as ImageIcon, 
  Upload, 
  Trash2, 
  Copy, 
  Check, 
  RefreshCw, 
  Cpu, 
  CheckCircle2, 
  XCircle, 
  Terminal, 
  Zap, 
  Lock 
} from 'lucide-react';
import { SAMPLE_SCAN_TEMPLATES } from '../data/mockData';
import { normalizeUrlInput, extractProtocol, syncUrlWithProtocol } from '../utils/urlHelper';

const BACKEND_BASE_URL = 'http://127.0.0.1:8000';

export default function ShieldScanWorkstation({ selectedTab, onTabChange }) {
  // 3 Core Scanner Tabs: 'text' (Message Scanner), 'url' (URL Safety Checker), 'image' (Screenshot Scanner)
  const [activeTab, setActiveTab] = useState(selectedTab || 'url');
  const [prevSelectedTab, setPrevSelectedTab] = useState(selectedTab);

  // URL Input State
  const [protocol, setProtocol] = useState('https://');
  const [urlInput, setUrlInput] = useState('sbi-corporate-kyc-update.com/login.php');

  // Text / Message Input State
  const [textInput, setTextInput] = useState('');

  // Image Upload State
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedImage, setUploadedImage] = useState(null);
  const [imageName, setImageName] = useState('');
  const fileInputRef = useRef(null);

  // Scan & State Management (must be initialized before any conditional hook/state usage)
  const [isScanning, setIsScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [copied, setCopied] = useState(false);

  // Synchronize state when selectedTab prop changes from external action (Hero, Navbar, etc.)
  if (selectedTab && selectedTab !== prevSelectedTab) {
    setPrevSelectedTab(selectedTab);
    setActiveTab(selectedTab);
    setScanResult(null);
    setScanError(null);
  }

  // Tab switch handler: resets stale result & error, notifies parent
  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    setPrevSelectedTab(tab);
    setScanResult(null);
    setScanError(null);
    if (onTabChange) {
      onTabChange(tab);
    }
  };

  // Synchronized URL & Protocol Handlers
  const handleUrlInputChange = (val) => {
    setUrlInput(val);
    if (scanResult) setScanResult(null);
    if (scanError) setScanError(null);

    const detectedProto = extractProtocol(val);
    if (detectedProto && detectedProto !== protocol) {
      setProtocol(detectedProto);
    }
  };

  const handleProtocolChange = (newProto) => {
    setProtocol(newProto);
    if (scanResult) setScanResult(null);
    if (scanError) setScanError(null);

    setUrlInput((prev) => syncUrlWithProtocol(prev, newProto));
  };

  // Image Upload Handler
  const handleImageUpload = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedFile(file);
      setImageName(file.name);
      setScanResult(null);
      setScanError(null);
      const reader = new FileReader();
      reader.onload = () => {
        setUploadedImage(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const clearImage = () => {
    setUploadedFile(null);
    setUploadedImage(null);
    setImageName('');
    setScanResult(null);
    setScanError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // Run Real Scan against FastAPI backend
  const handleRunScan = async () => {
    setIsScanning(true);
    setScanResult(null);
    setScanError(null);
    setScanPhase("Connecting to ScamX Threat Detection Engine...");

    try {
      if (activeTab === 'text') {
        const rawText = textInput.trim();
        if (!rawText) {
          setScanError({
            title: "Input Required",
            message: "Please enter or paste message text to scan."
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        setScanPhase("Analyzing text with ScamX ML Classifier (TF-IDF & Logistic Regression)...");

        let response;
        let connectionError = null;

        // Try direct backend host, fallback to /api proxy
        try {
          response = await fetch(`${BACKEND_BASE_URL}/api/v1/scans/text`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: rawText })
          });
        } catch (fetchErr) {
          try {
            response = await fetch(`/api/v1/scans/text`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ text: rawText })
            });
          } catch {
            connectionError = fetchErr;
          }
        }

        if (connectionError || !response) {
          setScanError({
            title: "Backend Unavailable",
            message: "Cannot connect to the ScamX backend at http://127.0.0.1:8000. Please ensure the backend server is running (e.g. uvicorn backend.app.main:app)."
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        if (!response.ok) {
          let errorMsg = `Server returned HTTP ${response.status}`;
          try {
            const errJson = await response.json();
            if (errJson.detail) {
              errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
            } else if (errJson.error) {
              errorMsg = errJson.error;
            }
          } catch {
            // ignore JSON parse error
          }
          setScanError({
            title: response.status === 422 ? "Input Validation Error" : "Scan Request Error",
            message: errorMsg
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        const data = await response.json();
        const scamProb = Number(data.scam_probability || 0);
        const scamPct = (scamProb * 100).toFixed(1);
        const confPct = Number(data.confidence ? (data.confidence * 100).toFixed(1) : (scamProb * 100).toFixed(1));
        const isScam = data.is_scam === true || data.label === 'scam';

        setScanResult({
          scannerType: 'text',
          target: rawText.slice(0, 60) + (rawText.length > 60 ? "..." : ""),
          fullTarget: rawText,
          timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
          
          // Raw Backend Model Fields
          label: data.label,
          isScam: isScam,
          scamProbability: scamProb,
          scamPercentage: scamPct,
          confidence: data.confidence,
          confidencePercentage: confPct,
          scoreLabel: data.calibrated ? 'Calibrated Probability' : 'Model Scam Score',
          probabilities: data.probabilities,
          modelVersion: data.model_version || 'v1.0.0-baseline-tfidf-lr',
          explanation: data.explanation || (isScam ? "Scam keyword patterns identified in text." : "No strong scam keywords identified in text."),
          evidence: Array.isArray(data.evidence) ? data.evidence : [],
          
          // Grounded UI Representation
          badgeLabel: isScam ? "SUSPECTED SCAM" : "LIKELY LEGITIMATE",
          badgeColor: isScam ? 'danger' : 'safe',
          gaugePercent: Math.min(100, Math.max(0, scamProb * 100)),
          gaugeColor: isScam ? '#EF4444' : scamProb > 0.3 ? '#F59E0B' : '#10B981',
          recommendation: isScam
            ? "Exercise caution: Do not reply, click links, or provide financial information based on this message."
            : "No threat indicators detected: The message is consistent with legitimate communications."
        });

      } else if (activeTab === 'url') {
        const rawInput = urlInput.trim();
        if (!rawInput) {
          setScanError({
            title: "Input Required",
            message: "Please enter a web URL or domain to scan."
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        // Consistent input strategy:
        // 1. If complete URL (starts with scheme), send unchanged after trim.
        // 2. If hostname/path, combine with selected protocol exactly once.
        const fullUrl = normalizeUrlInput(rawInput, protocol);

        setScanPhase("Inspecting URL structure, punycode, and offline reputation feeds...");

        let response;
        let connectionError = null;

        try {
          response = await fetch(`${BACKEND_BASE_URL}/api/v1/scans/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: fullUrl })
          });
        } catch (fetchErr) {
          try {
            response = await fetch(`/api/v1/scans/url`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ url: fullUrl })
            });
          } catch {
            connectionError = fetchErr;
          }
        }

        if (connectionError || !response) {
          setScanError({
            title: "Backend Unavailable",
            message: "Cannot connect to the ScamX backend at http://127.0.0.1:8000. Please ensure the backend server is running."
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        if (!response.ok) {
          let errorTitle = response.status === 422 ? "Invalid URL Syntax" : "URL Scan Failed";
          let errorMsg = `Server returned HTTP ${response.status}`;
          try {
            const errJson = await response.json();
            if (errJson.detail) {
              errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
            } else if (errJson.error) {
              errorMsg = errJson.error;
            }
          } catch {
            // ignore
          }
          setScanError({
            title: errorTitle,
            message: errorMsg
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        const data = await response.json();
        const riskScore = Number(data.risk_score || 0);
        const riskPct = (riskScore * 100).toFixed(1);
        const verdict = (data.verdict || 'benign').toLowerCase();
        const riskLevel = (data.risk_level || (verdict === 'malicious' ? 'critical' : verdict === 'suspicious' ? 'high' : 'low')).toLowerCase();

        const isDanger = verdict === 'malicious' || riskLevel === 'critical';
        const isSuspicious = verdict === 'suspicious' || riskLevel === 'high' || riskLevel === 'medium';
        const isInconclusive = verdict === 'inconclusive';

        const badgeLabel = isDanger
          ? "MALICIOUS URL"
          : isSuspicious
          ? "SUSPICIOUS URL"
          : isInconclusive
          ? "INCONCLUSIVE"
          : "BENIGN / LOW RISK";

        const badgeColor = isDanger
          ? 'danger'
          : isSuspicious
          ? 'warn'
          : isInconclusive
          ? 'warn'
          : 'safe';

        const gaugeColor = isDanger
          ? '#EF4444'
          : isSuspicious
          ? '#F59E0B'
          : isInconclusive
          ? '#94A3B8'
          : '#10B981';

        setScanResult({
          scannerType: 'url',
          target: data.normalized_url || fullUrl,
          fullTarget: fullUrl,
          timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
          label: verdict,
          isScam: isDanger,
          scamProbability: riskScore,
          scamPercentage: riskPct,
          confidence: null,
          scoreLabel: 'Heuristic Risk Score',
          modelVersion: data.analysis_method || 'offline_static_heuristic_v1',
          explanation: isDanger
            ? "High-risk heuristic signals detected: punycode spoofing, suspicious domain patterns, or known reputation list match."
            : isSuspicious
            ? "Suspicious heuristic markers detected. Verify domain ownership before submitting personal credentials."
            : "No severe structural anomalies detected by offline static heuristics.",
          evidence: Array.isArray(data.evidence)
            ? data.evidence.map(e => ({
                token: e.signal,
                desc: e.description,
                weight: e.weight,
                signal: e.severity === 'high' ? 'scam_indicator' : 'legitimate_indicator'
              }))
            : [],
          limitations: Array.isArray(data.limitations) ? data.limitations : [],
          badgeLabel,
          badgeColor,
          gaugePercent: Math.min(100, Math.max(0, riskScore * 100)),
          gaugeColor,
          recommendation: isDanger
            ? "DO NOT OPEN: Avoid navigating to this domain or submitting sensitive credentials."
            : isSuspicious
            ? "Exercise caution: Verify the domain authenticity through official independent channels."
            : "Static heuristic analysis found no severe anomalies. Note that newly created domains may lack reputation history."
        });

      } else {
        // activeTab === 'image' (Screenshot Scanner)
        if (!uploadedFile) {
          setScanError({
            title: "File Required",
            message: "Please upload an image or screenshot (PNG, JPG, or WebP) to scan."
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        setScanPhase("Extracting text via OCR and scanning for scam indicators...");

        const formData = new FormData();
        formData.append('file', uploadedFile);

        let response;
        let connectionError = null;

        try {
          response = await fetch(`${BACKEND_BASE_URL}/api/v1/scans/image`, {
            method: 'POST',
            body: formData
          });
        } catch (fetchErr) {
          try {
            response = await fetch(`/api/v1/scans/image`, {
              method: 'POST',
              body: formData
            });
          } catch {
            connectionError = fetchErr;
          }
        }

        if (connectionError || !response) {
          setScanError({
            title: "Backend Unavailable",
            message: "Cannot connect to the ScamX backend at http://127.0.0.1:8000. Please ensure the backend server is running."
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        if (!response.ok) {
          let errorMsg = `Server returned HTTP ${response.status}`;
          try {
            const errJson = await response.json();
            if (errJson.detail) {
              errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
            }
          } catch {
            // ignore
          }
          setScanError({
            title: "Screenshot Scan Failed",
            message: errorMsg
          });
          setIsScanning(false);
          setScanPhase("");
          return;
        }

        const data = await response.json();
        const riskScore = Number(data.risk_score || 0);
        const riskPct = (riskScore * 100).toFixed(1);
        const verdict = (data.combined_verdict || data.verdict || 'benign').toLowerCase();
        const riskLevel = (data.risk_level || (verdict === 'malicious' ? 'critical' : verdict === 'suspicious' ? 'high' : 'low')).toLowerCase();

        const isMalicious = verdict === 'malicious' || riskLevel === 'critical';
        const isSuspicious = verdict === 'suspicious' || riskLevel === 'high' || riskLevel === 'medium';
        const isInconclusive = verdict === 'inconclusive' || riskLevel === 'inconclusive';

        const badgeLabel = isMalicious
          ? "MALICIOUS CONTENT"
          : isSuspicious
          ? "SUSPICIOUS CONTENT"
          : isInconclusive
          ? "INCONCLUSIVE"
          : "BENIGN / LOW RISK";

        const badgeColor = isMalicious
          ? 'danger'
          : isSuspicious
          ? 'warn'
          : isInconclusive
          ? 'warn'
          : 'safe';

        const gaugeColor = isMalicious
          ? '#EF4444'
          : isSuspicious
          ? '#F59E0B'
          : isInconclusive
          ? '#94A3B8'
          : '#10B981';

        const recommendation = isMalicious
          ? "CRITICAL THREAT: Verified malicious URL or severe scam pattern detected in screenshot."
          : isSuspicious
          ? "Exercise caution: Deceptive patterns or suspicious requests detected in screenshot text or links."
          : isInconclusive
          ? "Inconclusive: No readable text detected or OCR unavailable. Authenticity cannot be confirmed."
          : "No scam indicators detected. The text is consistent with benign, legitimate content.";

        setScanResult({
          scannerType: 'image',
          target: data.filename || imageName || "Uploaded_Screenshot.png",
          fullTarget: data.filename || imageName,
          timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
          label: verdict,
          isScam: isMalicious || isSuspicious,
          scamProbability: riskScore,
          scamPercentage: riskPct,
          confidence: null,
          scoreLabel: 'Heuristic Risk Score',
          modelVersion: `OCR Engine: ${data.ocr_info?.engine || 'tesseract'}`,
          explanation: data.text_analysis?.explanation
            ? `Extracted ${data.ocr_info?.characters_extracted ?? data.extracted_text?.length ?? 0} characters via local OCR. ${data.text_analysis.explanation}`
            : data.extracted_text
            ? `Extracted ${data.ocr_info?.characters_extracted ?? data.extracted_text?.length ?? 0} characters via local OCR. No recognized scam patterns detected.`
            : "No readable text detected in screenshot. Inconclusive analysis.",
          evidence: Array.isArray(data.evidence)
            ? data.evidence.map(e => ({
                token: e.token || (e.signal ? e.signal.replace(/^(text_|url_)/, '') : 'indicator'),
                desc: e.description,
                weight: e.weight != null ? e.weight : (e.severity === 'high' ? 1.0 : 0.5),
                signal: (e.severity === 'high' || e.severity === 'critical' || (e.signal && e.signal.includes('scam')))
                  ? 'scam_indicator'
                  : 'legitimate_indicator'
              }))
            : [],
          limitations: Array.isArray(data.limitations) ? data.limitations : [],
          warnings: Array.isArray(data.warnings) ? data.warnings : [],
          badgeLabel,
          badgeColor,
          gaugePercent: Math.min(100, Math.max(0, riskScore * 100)),
          gaugeColor,
          recommendation
        });
      }
    } catch (err) {
      console.error("Scan processing error:", err);
      setScanError({
        title: "Unexpected Error",
        message: err.message || "An unexpected error occurred while processing the scan."
      });
    } finally {
      setIsScanning(false);
      setScanPhase("");
    }
  };

  // Helper copy to clipboard
  const handleCopyReport = () => {
    if (!scanResult) return;
    const text = `ScamX - Threat Intelligence Report
Target: ${scanResult.target}
Verdict: ${scanResult.badgeLabel} (Backend Label: ${scanResult.label})
Scam Probability: ${scanResult.scamPercentage}%
${scanResult.confidencePercentage ? `Confidence: ${scanResult.confidencePercentage}%\n` : ''}Model Version: ${scanResult.modelVersion}
Explanation: ${scanResult.explanation}
Timestamp: ${scanResult.timestamp}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="scanners" className="py-20 bg-[#0B1521] text-slate-100 relative overflow-hidden border-t border-cyan-900/40">
      <div id="shieldscan" className="absolute -top-10" />
      
      {/* Background Cyber Ambient Lights */}
      <div className="absolute top-0 right-1/4 w-[600px] h-[400px] bg-cyan-500/10 rounded-full blur-[160px] pointer-events-none" />
      <div className="absolute bottom-0 left-1/4 w-[500px] h-[400px] bg-emerald-500/10 rounded-full blur-[160px] pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Workstation Header */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between mb-10 gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 text-xs font-mono font-bold tracking-wider mb-3 shadow-lg shadow-cyan-950/50">
              <Terminal className="w-3.5 h-3.5" />
              <span>SCAMX DETECTION SUITE</span>
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            </div>

            <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-white flex items-center gap-3">
              <span>ScamX</span>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-emerald-400 to-teal-300">
                Core Scanner Engine
              </span>
            </h2>

            <p className="mt-3 text-sm sm:text-base text-slate-400 max-w-2xl leading-relaxed">
              Analyze suspicious messages, links, and screenshots in real-time with verified backend threat detection.
            </p>
          </div>

          {/* Supported Scanner Engine Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-[11px] text-slate-400 self-start lg:self-auto">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>FastAPI Live ML Detection</span>
          </div>
        </div>

        {/* ========================================================= */}
        {/* CORE SCANNER WORKSTATION                                 */}
        {/* ========================================================= */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* Left 7 Columns: Input Workstation */}
          <div className="lg:col-span-7 space-y-6">
            
            <div className="bg-slate-900/90 backdrop-blur-xl rounded-3xl border border-slate-800 shadow-2xl p-6 sm:p-8">
              
              {/* Three Core Scanner Tabs */}
              <div className="flex flex-wrap gap-2 pb-6 border-b border-slate-800">
                <button
                  onClick={() => handleTabSwitch('text')}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                    activeTab === 'text'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-md shadow-emerald-500/20'
                      : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  <Mail className="w-3.5 h-3.5" />
                  <span>1. Message Scanner</span>
                </button>

                <button
                  onClick={() => handleTabSwitch('url')}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                    activeTab === 'url'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-md shadow-cyan-500/20'
                      : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>2. URL Safety Checker</span>
                </button>

                <button
                  onClick={() => handleTabSwitch('image')}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                    activeTab === 'image'
                      ? 'bg-teal-500/20 text-teal-300 border border-teal-500/50 shadow-md shadow-teal-500/20'
                      : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  <ImageIcon className="w-3.5 h-3.5" />
                  <span>3. Screenshot Scanner</span>
                </button>
              </div>

              {/* ---------------------------------------------------- */}
              {/* TAB 1: MESSAGE SCANNER                               */}
              {/* ---------------------------------------------------- */}
              {activeTab === 'text' && (
                <div className="pt-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold uppercase tracking-wider text-slate-400">
                      Email Body, SMS, or WhatsApp Message Text
                    </label>
                    <span className="text-[11px] font-mono text-slate-500">
                      {textInput.length} chars
                    </span>
                  </div>

                  <textarea
                    rows={7}
                    value={textInput}
                    onChange={(e) => {
                      setTextInput(e.target.value);
                      if (scanResult) setScanResult(null);
                      if (scanError) setScanError(null);
                    }}
                    placeholder="Paste suspicious message, SMS, email, or chat text here..."
                    className="w-full bg-slate-950 p-4 rounded-xl border border-slate-700 text-xs sm:text-sm text-slate-200 font-mono focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 leading-relaxed resize-y"
                  />

                  {/* Presets */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[11px] font-semibold text-slate-400">
                        Pre-loaded sample messages:
                      </span>
                      {textInput && (
                        <button
                          onClick={() => {
                            setTextInput('');
                            setScanResult(null);
                            setScanError(null);
                          }}
                          className="text-[11px] text-slate-500 hover:text-slate-300"
                        >
                          Clear Text
                        </button>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {SAMPLE_SCAN_TEMPLATES.text.map((tpl, i) => (
                        <button
                          key={i}
                          onClick={() => {
                            setTextInput(tpl.content);
                            setScanResult(null);
                            setScanError(null);
                          }}
                          className="p-2.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-left text-xs text-slate-300 border border-slate-700 hover:border-emerald-500/40 transition-all"
                        >
                          <div className="font-bold truncate text-[11px]">{tpl.label}</div>
                          <div className="text-[10px] text-slate-500 mt-0.5">{tpl.type}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* ---------------------------------------------------- */}
              {/* TAB 2: URL SAFETY CHECKER                           */}
              {/* ---------------------------------------------------- */}
              {activeTab === 'url' && (
                <div className="pt-6 space-y-4">
                  <div>
                    <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                      Suspicious Link or Web Address
                    </label>
                    <div className="flex rounded-xl overflow-hidden border border-slate-700 bg-slate-950 focus-within:border-cyan-500 focus-within:ring-2 focus-within:ring-cyan-500/30">
                      <select
                        value={protocol}
                        onChange={(e) => handleProtocolChange(e.target.value)}
                        className="bg-slate-900 text-xs font-mono font-bold text-cyan-400 px-3 py-3 border-r border-slate-800 focus:outline-none"
                      >
                        <option value="https://">https://</option>
                        <option value="http://">http://</option>
                      </select>
                      <input
                        type="text"
                        value={urlInput}
                        onChange={(e) => handleUrlInputChange(e.target.value)}
                        placeholder="e.g. example.com or https://example.com"
                        className="flex-1 bg-transparent px-4 py-3 text-xs sm:text-sm font-mono text-white focus:outline-none"
                      />
                      {urlInput && (
                        <button
                          onClick={() => {
                            setUrlInput('');
                            setScanResult(null);
                            setScanError(null);
                          }}
                          className="px-3 text-slate-500 hover:text-slate-300 text-xs"
                        >
                          Clear
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Quick Presets */}
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400">
                      Try realistic URL test cases:
                    </span>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {SAMPLE_SCAN_TEMPLATES.url.map((tpl, i) => (
                        <button
                          key={i}
                          onClick={() => {
                            const detected = extractProtocol(tpl.url) || 'https://';
                            setProtocol(detected);
                            setUrlInput(tpl.url);
                            if (scanResult) setScanResult(null);
                            if (scanError) setScanError(null);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 border border-slate-700 hover:border-cyan-500/50 transition-all"
                        >
                          {tpl.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* ---------------------------------------------------- */}
              {/* TAB 3: SCREENSHOT SCANNER                           */}
              {/* ---------------------------------------------------- */}
              {activeTab === 'image' && (
                <div className="pt-6 space-y-4">
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400">
                    Upload WhatsApp Chat, QR Code, or Payment Notice Image
                  </label>

                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleImageUpload}
                    accept="image/png, image/jpeg, image/webp"
                    className="hidden"
                  />

                  {uploadedImage ? (
                    <div className="relative rounded-2xl overflow-hidden border border-slate-700 bg-slate-950 p-4">
                      <div className="flex items-center justify-between mb-3 pb-3 border-b border-slate-800">
                        <div className="flex items-center gap-2">
                          <ImageIcon className="w-4 h-4 text-teal-400" />
                          <span className="text-xs font-bold text-white truncate max-w-[200px]">
                            {imageName}
                          </span>
                        </div>
                        <button
                          onClick={clearImage}
                          className="p-1.5 rounded-lg bg-red-950/60 text-red-400 hover:bg-red-900 border border-red-800 text-xs flex items-center gap-1 font-semibold"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Remove</span>
                        </button>
                      </div>

                      <div className="max-h-60 overflow-hidden rounded-xl flex items-center justify-center bg-black/40">
                        <img 
                          src={uploadedImage} 
                          alt="Uploaded preview" 
                          className="max-h-60 object-contain rounded-lg"
                        />
                      </div>

                      <div className="mt-3 flex items-center justify-between text-xs text-slate-400 px-1">
                        <span>Image ready for OCR text extraction</span>
                        <span className="text-emerald-400 font-mono font-bold">READY</span>
                      </div>
                    </div>
                  ) : (
                    <div
                      onClick={() => fileInputRef.current?.click()}
                      className="border-2 border-dashed border-slate-700 hover:border-teal-400/60 rounded-2xl p-8 text-center bg-slate-950/60 hover:bg-slate-950 cursor-pointer transition-all duration-200 group"
                    >
                      <div className="w-14 h-14 rounded-2xl bg-teal-500/10 text-teal-400 flex items-center justify-center mx-auto mb-4 border border-teal-500/30 group-hover:scale-110 transition-transform">
                        <Upload className="w-7 h-7" />
                      </div>
                      <div className="text-sm font-bold text-white">
                        Click to upload or drag & drop screenshot
                      </div>
                      <div className="text-xs text-slate-400 mt-1">
                        Supports PNG, JPG, or WebP (max 5MB)
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Action Button: Run Scan */}
              <div className="pt-6 mt-6 border-t border-slate-800">
                <button
                  onClick={handleRunScan}
                  disabled={isScanning}
                  className="w-full py-4 px-6 rounded-2xl bg-gradient-to-r from-emerald-500 via-cyan-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-black text-sm sm:text-base tracking-wide shadow-xl shadow-cyan-900/30 flex items-center justify-center gap-3 transition-all transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-75 disabled:cursor-not-allowed"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-5 h-5 animate-spin text-slate-950" />
                      <span>ANALYZING THREAT SIGNALS...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-5 h-5 fill-slate-950" />
                      <span>RUN SCAM DETECTION SCAN</span>
                    </>
                  )}
                </button>

                {/* Scan Progress Indicators */}
                {isScanning && (
                  <div className="mt-4 p-3 rounded-xl bg-cyan-950/60 border border-cyan-800/80 animate-pulse">
                    <div className="flex items-center gap-2 text-cyan-300 text-xs font-mono">
                      <Terminal className="w-3.5 h-3.5 flex-shrink-0" />
                      <span>{scanPhase}</span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-cyan-400 to-emerald-400 animate-pulse" style={{ width: '85%' }} />
                    </div>
                  </div>
                )}
              </div>

            </div>

          </div>

          {/* Right 5 Columns: Detailed Scan Report & Results Panel */}
          <div className="lg:col-span-5 space-y-6">
            
            <div className="bg-slate-900/90 backdrop-blur-xl rounded-3xl border border-slate-800 shadow-2xl p-6 sm:p-8 min-h-[460px] flex flex-col justify-between">
              
              <div>
                <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-cyan-400" />
                    <span className="text-sm font-bold text-white uppercase tracking-wider">
                      Forensic Scan Report
                    </span>
                  </div>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                    isScanning ? 'bg-cyan-900/50 text-cyan-300 animate-pulse' :
                    scanError ? 'bg-red-900/50 text-red-300' :
                    scanResult ? 'bg-emerald-900/50 text-emerald-300' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {isScanning ? 'SCANNING...' : scanError ? 'ERROR' : scanResult ? 'SCAN COMPLETE' : 'AWAITING SCAN'}
                  </span>
                </div>

                {/* STATE 1: SCANNING / LOADING */}
                {isScanning && (
                  <div className="py-20 text-center space-y-4 animate-in fade-in duration-200">
                    <div className="w-16 h-16 rounded-2xl bg-cyan-950/70 text-cyan-400 flex items-center justify-center mx-auto border border-cyan-800/80 shadow-lg shadow-cyan-950/50">
                      <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
                    </div>
                    <div className="text-base font-bold text-white">
                      Analyzing with ScamX Threat Engine...
                    </div>
                    <p className="text-xs text-cyan-300 font-mono max-w-xs mx-auto">
                      {scanPhase}
                    </p>
                    <div className="w-48 mx-auto bg-slate-800 rounded-full h-1.5 overflow-hidden mt-2">
                      <div className="h-full bg-gradient-to-r from-cyan-400 to-emerald-400 animate-pulse w-3/4" />
                    </div>
                  </div>
                )}

                {/* STATE 2: ERROR STATE */}
                {!isScanning && scanError && (
                  <div className="pt-6 space-y-4 animate-in fade-in duration-200">
                    <div className="p-5 rounded-2xl bg-red-950/40 border border-red-500/50 space-y-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-9 h-9 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 flex-shrink-0">
                          <AlertTriangle className="w-5 h-5" />
                        </div>
                        <div>
                          <h4 className="text-sm font-bold text-red-200">{scanError.title || "Scan Error"}</h4>
                          <span className="text-[10px] text-red-300/80 font-mono">Backend Communication Issue</span>
                        </div>
                      </div>

                      <div className="text-xs text-red-200 leading-relaxed bg-black/40 p-3 rounded-xl border border-red-900/60 font-mono">
                        {scanError.message}
                      </div>

                      <div className="pt-2 flex items-center justify-between">
                        <button
                          onClick={() => setScanError(null)}
                          className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white transition-colors"
                        >
                          Dismiss
                        </button>
                        <button
                          onClick={handleRunScan}
                          className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow-md transition-colors flex items-center gap-1.5"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                          <span>Retry Scan</span>
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* STATE 3: SCAN RESULT */}
                {!isScanning && !scanError && scanResult && (
                  <div className="pt-6 space-y-6 animate-in fade-in duration-300">
                    
                    {/* Overall Risk Meter Gauge */}
                    <div className="flex flex-col items-center justify-center p-6 rounded-2xl bg-slate-950/80 border border-slate-800 relative">
                      
                      {/* Semi-circle Gauge */}
                      <div className="relative w-44 h-24 flex items-end justify-center overflow-hidden">
                        <svg className="w-44 h-44 -rotate-90 transform" viewBox="0 0 100 100">
                          {/* Background Track */}
                          <circle
                            cx="50"
                            cy="50"
                            r="40"
                            fill="none"
                            stroke="#1E293B"
                            strokeWidth="10"
                            strokeDasharray="125.6 125.6"
                            strokeDashoffset="0"
                          />
                          {/* Progress Value */}
                          <circle
                            cx="50"
                            cy="50"
                            r="40"
                            fill="none"
                            stroke={scanResult.gaugeColor}
                            strokeWidth="10"
                            strokeDasharray="125.6 125.6"
                            strokeDashoffset={125.6 - (125.6 * (scanResult.gaugePercent / 100))}
                            strokeLinecap="round"
                            className="transition-all duration-1000 ease-out"
                          />
                        </svg>

                        {/* Center Score Readout */}
                        <div className="absolute bottom-1 text-center">
                          <span className="text-3xl font-black text-white">
                            {scanResult.scamPercentage}%
                          </span>
                          <span className="text-[10px] text-slate-400 font-bold block uppercase tracking-wider">
                            {scanResult.scoreLabel || (scanResult.scannerType === 'text' ? 'Scam Probability' : 'Heuristic Risk Score')}
                          </span>
                        </div>
                      </div>

                      {/* Severity / Classification Badge */}
                      <div className="mt-3">
                        <span className={`px-3 py-1 rounded-full text-xs font-black tracking-wider uppercase inline-flex items-center gap-1.5 ${
                          scanResult.badgeColor === 'danger'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                            : scanResult.badgeColor === 'warn'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                        }`}>
                          {scanResult.badgeColor === 'danger' && <AlertTriangle className="w-3.5 h-3.5" />}
                          {scanResult.badgeColor === 'warn' && <AlertTriangle className="w-3.5 h-3.5" />}
                          {scanResult.badgeColor === 'safe' && <CheckCircle2 className="w-3.5 h-3.5" />}
                          <span>{scanResult.badgeLabel}</span>
                          <span className="text-[10px] opacity-75 font-mono">({(scanResult.label || '').toUpperCase()})</span>
                        </span>
                      </div>

                      {/* Scan Meta */}
                      <div className="mt-3 text-center space-y-0.5">
                        <div className="text-xs text-slate-300 font-mono truncate max-w-[280px]">
                          {scanResult.target}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          Scanned at: {scanResult.timestamp}
                        </div>
                        {scanResult.confidencePercentage && (
                          <div className="text-[10px] text-cyan-400 font-mono">
                            Model Confidence: {scanResult.confidencePercentage}% | {scanResult.modelVersion}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Actionable Explanation Card */}
                    <div className={`p-4 rounded-2xl border ${
                      scanResult.badgeColor === 'danger'
                        ? 'bg-red-950/40 border-red-500/40'
                        : scanResult.badgeColor === 'warn'
                        ? 'bg-amber-950/40 border-amber-500/40'
                        : 'bg-emerald-950/40 border-emerald-500/40'
                    }`}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                          AI Model Explanation
                        </span>
                        <span className={`text-xs font-black uppercase ${
                          scanResult.badgeColor === 'danger' ? 'text-red-400' :
                          scanResult.badgeColor === 'warn' ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {scanResult.label}
                        </span>
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed font-medium">
                        {scanResult.explanation}
                      </p>
                      <div className="mt-2 pt-2 border-t border-slate-800 text-[11px] text-slate-300 leading-snug">
                        <strong>Advice:</strong> {scanResult.recommendation}
                      </div>
                    </div>

                    {/* Itemized Evidence Breakdown */}
                    <div className="space-y-2.5">
                      <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                        <span>Keyword Evidence Signals ({scanResult.evidence.length})</span>
                        <span className="text-[10px] text-slate-500">TF-IDF Model Weight</span>
                      </div>

                      {scanResult.evidence.length > 0 ? (
                        <div className="space-y-2">
                          {scanResult.evidence.map((f, idx) => (
                            <div 
                              key={idx}
                              className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs flex items-start justify-between gap-2.5"
                            >
                              <div className="flex items-start gap-2.5">
                                {f.signal === 'scam_indicator' ? (
                                  <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                                ) : (
                                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                                )}
                                <div>
                                  <div className="font-mono font-bold text-slate-200">
                                    "{f.token}"
                                  </div>
                                  <div className="text-[11px] text-slate-400 mt-0.5">
                                    {f.desc || (f.signal === 'scam_indicator' ? 'Scam Indicator Token' : 'Legitimate Indicator Token')}
                                  </div>
                                </div>
                              </div>

                              {typeof f.weight === 'number' && (
                                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded whitespace-nowrap ${
                                  f.weight > 0 ? 'bg-red-950/60 text-red-400 border border-red-800/60' : 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60'
                                }`}>
                                  {f.weight > 0 ? `+${f.weight.toFixed(2)}` : f.weight.toFixed(2)}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-400 italic">
                          No distinctive keyword signals detected in this content.
                        </div>
                      )}
                    </div>

                    {/* Heuristic Limitations & Scope */}
                    {scanResult.limitations && scanResult.limitations.length > 0 && (
                      <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 text-xs space-y-1.5">
                        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                          Analysis Scope & Limitations ({scanResult.limitations.length})
                        </div>
                        <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px] leading-relaxed">
                          {scanResult.limitations.map((lim, idx) => (
                            <li key={idx}>{lim}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Inconclusive Result Advisory */}
                    <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div className="leading-snug">
                        <strong className="text-amber-300">Safety Notice:</strong> An inconclusive or low-risk result does not guarantee that content is safe. Always verify senders and links independently before taking action.
                      </div>
                    </div>

                    {/* Report Utilities: Copy */}
                    <div className="pt-2 flex items-center justify-end border-t border-slate-800 text-xs">
                      <button
                        onClick={handleCopyReport}
                        className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors font-semibold"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copied ? 'Copied Report' : 'Copy Report'}</span>
                      </button>
                    </div>

                  </div>
                )}

                {/* STATE 4: AWAITING SCAN (INITIAL EMPTY STATE) */}
                {!isScanning && !scanError && !scanResult && (
                  <div className="py-20 text-center space-y-4">
                    <div className="w-16 h-16 rounded-2xl bg-slate-800/80 text-slate-500 flex items-center justify-center mx-auto border border-slate-700">
                      <Cpu className="w-8 h-8" />
                    </div>
                    <div className="text-sm font-bold text-slate-300">
                      No Active Scan Loaded
                    </div>
                    <p className="text-xs text-slate-500 max-w-xs mx-auto">
                      Enter or paste message content, and click <strong>RUN SCAM DETECTION SCAN</strong> to evaluate threat signals with the live AI backend.
                    </p>
                  </div>
                )}
              </div>

            </div>

          </div>

        </div>

      </div>

    </section>
  );
}
