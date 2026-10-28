import React, { useState } from 'react';
import { 
  AlertTriangle, 
  CheckCircle2, 
  Copy, 
  Check, 
  X, 
  Globe, 
  Mail, 
  Image as ImageIcon,
  HelpCircle,
  ShieldCheck,
  ChevronDown,
  FileText
} from 'lucide-react';

export default function ScanResultCard({ result, onDismiss }) {
  const [copied, setCopied] = useState(false);
  const [showTechDetails, setShowTechDetails] = useState(false);

  if (!result) return null;

  const {
    scannerType,
    target,
    timestamp,
    label,
    isDanger,
    isSuspicious,
    isInconclusive,
    badgeLabel,
    scorePercent,
    scoreLabel,
    modelVersion,
    explanation,
    recommendation,
    evidence = [],
    limitations = [],
    warnings = [],
    ocrInfo = null,
    extractedText = '',
    extractedUrls = [],
    reputationCheck = null
  } = result;

  const handleCopyReport = () => {
    const text = `ScamX Threat Assessment
Scanner: ${scannerType === 'text' ? 'Message Scanner' : scannerType === 'url' ? 'URL Safety Checker' : 'Screenshot Scanner'}
Target: ${target}
Verdict: ${badgeLabel} (${label})
${scoreLabel || 'Risk Score'}: ${scorePercent}%
Explanation: ${explanation || 'None provided'}
Recommended Action: ${recommendation || 'None provided'}
Timestamp: ${timestamp || new Date().toLocaleString()}`;

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Color theme mapping for the card
  const borderClass = isDanger
    ? 'border-red-200 shadow-red-950/5'
    : isSuspicious
    ? 'border-amber-200 shadow-amber-950/5'
    : isInconclusive
    ? 'border-slate-200 shadow-slate-950/5'
    : 'border-emerald-200/90 shadow-emerald-950/5';

  const badgeClass = isDanger
    ? 'bg-red-50 text-red-700 border-red-200'
    : isSuspicious
    ? 'bg-amber-50 text-amber-800 border-amber-200'
    : isInconclusive
    ? 'bg-slate-100 text-slate-700 border-slate-200'
    : 'bg-emerald-50 text-emerald-800 border-emerald-200';

  const gaugeFillColor = isDanger
    ? '#EF4444'
    : isSuspicious
    ? '#F59E0B'
    : isInconclusive
    ? '#94A3B8'
    : '#10B981';

  // Translate evidence into clear, plain-English phrases
  const translateEvidence = (ev) => {
    if (scannerType === 'text') {
      const isRisk = ev.signal === 'scam_indicator';
      return {
        title: isRisk ? `Suspicious term: "${ev.token}"` : `Standard wording: "${ev.token}"`,
        description: isRisk 
          ? 'Commonly found in high-pressure or fraudulent messages' 
          : 'Consistent with normal conversational phrasing',
        isRisk
      };
    }

    if (scannerType === 'url') {
      const signalMap = {
        'excessive_domain_hyphens': {
          title: 'Multiple domain hyphens',
          desc: 'Contains multiple dashes, often used to spoof legitimate brand names'
        },
        'ip_address_host': {
          title: 'Direct IP address hostname',
          desc: 'Uses a raw IP address instead of a registered domain name'
        },
        'punycode_domain': {
          title: 'Lookalike character spoofing',
          desc: 'Uses internationalized characters designed to mimic genuine domains'
        },
        'threat_intel_match': {
          title: 'Known threat feed match',
          desc: 'Domain is listed in active threat intelligence databases'
        },
        'suspicious_tld': {
          title: 'High-risk domain extension',
          desc: 'Domain extension frequently associated with phishing campaigns'
        }
      };

      const mapped = signalMap[ev.token] || signalMap[ev.signal];
      if (mapped) {
        return {
          title: mapped.title,
          description: mapped.desc,
          isRisk: true
        };
      }

      return {
        title: ev.desc || (ev.token ? `Signal: ${ev.token.replace(/_/g, ' ')}` : 'Structural indicator'),
        description: ev.description || 'Structural anomaly detected during URL heuristic check',
        isRisk: true
      };
    }

    // Image scanner
    const isRisk = ev.signal === 'scam_indicator' || ev.severity === 'high';
    return {
      title: ev.token ? `Flagged pattern: "${ev.token}"` : (ev.desc || 'Detected pattern'),
      description: ev.description || (isRisk ? 'Suspicious keyword or phrase detected in screenshot text' : 'Normal communication cue'),
      isRisk
    };
  };

  // Up to 3 key findings for default view
  const topEvidence = Array.isArray(evidence) ? evidence.slice(0, 3) : [];
  const charsCount = ocrInfo?.characters_extracted ?? extractedText?.length ?? 0;

  return (
    <div className={`mt-5 rounded-2xl sm:rounded-3xl p-5 sm:p-6 border-2 ${borderClass} shadow-lg transition-all duration-300 animate-in fade-in slide-in-from-top-2 bg-white`}>
      
      {/* 1. Header Row */}
      <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-slate-100 gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className={`w-8 h-8 rounded-xl flex items-center justify-center font-bold text-white shadow-xs flex-shrink-0 ${
            isDanger ? 'bg-red-500' : isSuspicious ? 'bg-amber-500' : isInconclusive ? 'bg-slate-600' : 'bg-emerald-600'
          }`}>
            {scannerType === 'text' && <Mail className="w-4 h-4" />}
            {scannerType === 'url' && <Globe className="w-4 h-4" />}
            {scannerType === 'image' && <ImageIcon className="w-4 h-4" />}
          </div>
          <div className="min-w-0">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              {scannerType === 'text' ? 'Message Scan Result' : scannerType === 'url' ? 'URL Safety Result' : 'Screenshot Scan Result'}
            </div>
            <div className="text-xs sm:text-sm font-bold text-slate-800 truncate font-mono mt-0.5">
              {target}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="hidden sm:inline text-[11px] text-slate-400 font-mono">
            {timestamp}
          </span>
          <button
            type="button"
            onClick={handleCopyReport}
            className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-slate-800 transition-colors"
            title="Copy summary report"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
          </button>
          {onDismiss && (
            <button
              type="button"
              onClick={onDismiss}
              className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors"
              title="Close report"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* 2. Main Verdict & Score Section */}
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-4 sm:gap-6 items-center">
        
        {/* Left: Gauge & Verdict Badge (4 cols) */}
        <div className="sm:col-span-4 flex sm:flex-col items-center justify-between sm:justify-center p-4 rounded-xl bg-slate-50/70 border border-slate-200/70 text-center gap-3">
          
          {/* Semi-circle Gauge */}
          <div className="relative w-32 h-16 flex items-end justify-center overflow-hidden">
            <svg className="w-32 h-32 -rotate-90 transform" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke="#E2E8F0"
                strokeWidth="10"
                strokeDasharray="125.6 125.6"
                strokeDashoffset="0"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke={gaugeFillColor}
                strokeWidth="10"
                strokeDasharray="125.6 125.6"
                strokeDashoffset={125.6 - (125.6 * (Math.min(100, Math.max(0, scorePercent)) / 100))}
                strokeLinecap="round"
                className="transition-all duration-700 ease-out"
              />
            </svg>

            <div className="absolute bottom-0 text-center">
              <span className="text-2xl font-black text-slate-900 leading-none">
                {scorePercent}%
              </span>
              <span className="text-[9px] text-slate-500 font-bold block uppercase tracking-wider mt-0.5">
                {scoreLabel || 'Risk Score'}
              </span>
            </div>
          </div>

          {/* Verdict Classification Badge */}
          <div className="flex-1 sm:flex-initial">
            <span className={`px-3 py-1 rounded-full text-xs font-black tracking-wide uppercase inline-flex items-center gap-1.5 border ${badgeClass}`}>
              {isDanger && <AlertTriangle className="w-3.5 h-3.5" />}
              {isSuspicious && <AlertTriangle className="w-3.5 h-3.5" />}
              {isInconclusive && <HelpCircle className="w-3.5 h-3.5" />}
              {!isDanger && !isSuspicious && !isInconclusive && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />}
              <span>{badgeLabel}</span>
            </span>
          </div>
        </div>

        {/* Right: Explanation & Context (8 cols) */}
        <div className="sm:col-span-8 space-y-2.5">
          <div>
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1">
              Assessment Summary
            </div>
            <p className="text-xs sm:text-sm text-slate-800 leading-relaxed font-medium">
              {explanation || 'Analysis completed with no abnormal patterns identified.'}
            </p>
          </div>

          {/* URL Heuristic Notice when Low Risk */}
          {scannerType === 'url' && !isDanger && !isSuspicious && !isInconclusive && (
            <div className="text-[11px] text-slate-500 leading-snug">
              Assessed via static structural heuristics. Absence of known threat listings does not guarantee that an unfamiliar link is safe.
            </div>
          )}
        </div>

      </div>

      {/* 3. Up to 3 Key Findings / Evidence Indicators */}
      {topEvidence.length > 0 && (
        <div className="mt-4 pt-3.5 border-t border-slate-100 space-y-2">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
            Key Findings ({topEvidence.length})
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {topEvidence.map((ev, idx) => {
              const translated = translateEvidence(ev);
              return (
                <div 
                  key={idx}
                  className={`p-2.5 rounded-xl border flex items-start gap-2 text-xs transition-colors ${
                    translated.isRisk 
                      ? 'bg-amber-50/60 border-amber-200/90 text-amber-950'
                      : 'bg-emerald-50/50 border-emerald-200/80 text-emerald-950'
                  }`}
                >
                  {translated.isRisk ? (
                    <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />
                  )}
                  <div className="min-w-0">
                    <div className="font-bold text-slate-900 leading-snug truncate">
                      {translated.title}
                    </div>
                    <div className="text-[11px] text-slate-600 mt-0.5 leading-snug">
                      {translated.description}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 4. Single Recommended Action Banner */}
      {recommendation && (
        <div className={`mt-4 rounded-xl p-3 sm:p-3.5 border flex items-start gap-2.5 text-xs ${
          isDanger 
            ? 'bg-red-50/80 border-red-200 text-red-950'
            : isSuspicious
            ? 'bg-amber-50/80 border-amber-200 text-amber-950'
            : isInconclusive
            ? 'bg-slate-50 border-slate-200 text-slate-800'
            : 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
        }`}>
          {isDanger || isSuspicious ? (
            <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${isDanger ? 'text-red-600' : 'text-amber-600'}`} />
          ) : isInconclusive ? (
            <HelpCircle className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />
          )}
          <div className="leading-relaxed">
            <strong className="font-bold block sm:inline mr-1">Recommended Action:</strong>
            <span>{recommendation}</span>
          </div>
        </div>
      )}

      {/* 5. Collapsible Technical Details Section */}
      <div className="mt-4 pt-3 border-t border-slate-100">
        <button
          type="button"
          onClick={() => setShowTechDetails(prev => !prev)}
          className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-500 hover:text-emerald-700 transition-colors py-1 focus:outline-none"
        >
          <span>{showTechDetails ? 'Hide technical details' : 'View technical details'}</span>
          <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${
            showTechDetails ? 'rotate-180' : ''
          }`} />
        </button>

        {showTechDetails && (
          <div className="mt-3 p-4 rounded-xl bg-slate-50 border border-slate-200/90 space-y-3.5 text-xs animate-in fade-in duration-200">
            
            {/* Model / Engine Version */}
            <div className="flex flex-wrap items-center justify-between pb-2 border-b border-slate-200 gap-2">
              <span className="font-bold text-slate-700">Detection Engine / Model:</span>
              <span className="font-mono text-slate-600 bg-white px-2 py-0.5 rounded border border-slate-200">
                {modelVersion || 'ScamX Static Heuristic v1'}
              </span>
            </div>

            {/* Complete Evidence Signals List with Raw Numerical Weights */}
            {evidence && evidence.length > 0 && (
              <div className="space-y-1.5">
                <div className="font-bold text-slate-700">Detailed Evidence Signals ({evidence.length}):</div>
                <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
                  {evidence.map((ev, i) => (
                    <div key={i} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between text-[11px] gap-2">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="font-mono font-bold text-slate-900 truncate">
                          "{ev.token || ev.signal}"
                        </span>
                        {ev.desc && <span className="text-slate-500 truncate">- {ev.desc}</span>}
                      </div>
                      {typeof ev.weight === 'number' && (
                        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 whitespace-nowrap">
                          weight: {ev.weight > 0 ? `+${ev.weight.toFixed(3)}` : ev.weight.toFixed(3)}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* URL Threat Intel Details if applicable */}
            {scannerType === 'url' && reputationCheck && (
              <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1">
                <div className="font-bold text-slate-700">Threat Intelligence Feed Lookup:</div>
                <div className="text-[11px] text-slate-600">
                  Status: <strong className="font-mono">{reputationCheck.matched ? 'MATCHED (MALICIOUS)' : 'NOT LISTED'}</strong>
                </div>
                {reputationCheck.notes && (
                  <div className="text-[11px] text-slate-500">{reputationCheck.notes}</div>
                )}
              </div>
            )}

            {/* Image OCR Metadata (Technical details view only) */}
            {scannerType === 'image' && ocrInfo && (
              <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1">
                <div className="font-bold text-slate-700 flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-slate-500" />
                  <span>OCR Engine & Text Extraction Details:</span>
                </div>
                <div className="text-[11px] text-slate-600 flex flex-wrap items-center gap-3">
                  <span>Engine: <strong className="font-mono">{ocrInfo.engine || 'tesseract'}</strong></span>
                  <span>Status: <strong className="font-mono">{ocrInfo.status}</strong></span>
                  <span>Characters Extracted: <strong className="font-mono">{charsCount}</strong></span>
                </div>
              </div>
            )}

            {/* Image Extracted Text Preview */}
            {scannerType === 'image' && extractedText && (
              <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1">
                <div className="font-bold text-slate-700">Raw Extracted OCR Text:</div>
                <div className="font-mono text-[11px] text-slate-700 max-h-24 overflow-y-auto whitespace-pre-wrap p-2 rounded bg-slate-50 border border-slate-100">
                  {extractedText}
                </div>
              </div>
            )}

            {/* Extracted URLs in Image */}
            {scannerType === 'image' && extractedUrls && extractedUrls.length > 0 && (
              <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1">
                <div className="font-bold text-slate-700">Extracted Links in Screenshot ({extractedUrls.length}):</div>
                <div className="space-y-1">
                  {extractedUrls.map((u, i) => (
                    <div key={i} className="font-mono text-[11px] text-slate-700 truncate bg-slate-50 p-1.5 rounded">
                      {u}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Analysis Limitations & Warnings */}
            {((limitations && limitations.length > 0) || (warnings && warnings.length > 0)) && (
              <div className="space-y-1 text-[11px] text-slate-600">
                <div className="font-bold text-slate-700">Analysis Scope & Limitations:</div>
                <ul className="list-disc list-inside space-y-0.5">
                  {limitations.map((lim, i) => (
                    <li key={`lim-${i}`}>{lim}</li>
                  ))}
                  {warnings.map((w, i) => (
                    <li key={`w-${i}`}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

          </div>
        )}
      </div>

    </div>
  );
}
