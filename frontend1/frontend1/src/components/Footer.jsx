import React from 'react';
import {
  ShieldCheck,
  ArrowUp,
  AlertTriangle
} from 'lucide-react';

const CURRENT_YEAR = new Date().getFullYear();

export default function Footer({ onOpenWorkstation, onSelectScanner }) {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleScannerClick = (tab) => {
    if (onSelectScanner) {
      onSelectScanner(tab);
    } else if (onOpenWorkstation) {
      onOpenWorkstation(tab);
    }
  };

  return (
    <footer className="bg-[#052418] text-slate-300 relative border-t border-emerald-900/60 pt-16 pb-24 lg:pb-16 overflow-hidden">

      {/* Background Subtle Mesh */}
      <div className="absolute inset-0 bg-plus-grid-dark opacity-20 pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

        {/* Top Footer Section: Brand & Contact Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-10 pb-12 border-b border-emerald-900/60">

          {/* Brand Info (Span 2) */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400 to-emerald-700 flex items-center justify-center text-white shadow-md shadow-emerald-500/20">
                <ShieldCheck className="w-6 h-6 stroke-[2.2]" />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-2xl tracking-tight text-white">
                  Scam<span className="text-emerald-400">X</span>
                </span>
              </div>
            </div>

            <p className="text-sm text-slate-400 leading-relaxed max-w-sm">
              AI-assisted scam detection platform. Analyze suspicious messages, links, and screenshots to detect scams before you click, reply, or share credentials.
            </p>

            <div className="p-3.5 rounded-2xl bg-emerald-950/70 border border-emerald-800/60 text-xs text-emerald-200/90 leading-relaxed max-w-md">
              <div className="font-bold flex items-center gap-1.5 text-emerald-300 mb-1">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Safety Disclaimer</span>
              </div>
              An inconclusive result does not mean content is safe. Always verify senders and links through official channels and never share sensitive credentials or transfer funds based solely on automated scan outputs.
            </div>
          </div>

          {/* Column 1: Scanners */}
          <div className="space-y-3">
            <h4 className="text-sm font-bold text-white uppercase tracking-wider">
              ScamX Scanners
            </h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <button onClick={() => handleScannerClick('text')} className="hover:text-emerald-300 transition-colors text-left flex items-center gap-1.5">
                  <span>💬</span> Message Scanner
                </button>
              </li>
              <li>
                <button onClick={() => handleScannerClick('url')} className="hover:text-emerald-300 transition-colors text-left flex items-center gap-1.5">
                  <span>🔗</span> URL Safety Checker
                </button>
              </li>
              <li>
                <button onClick={() => handleScannerClick('image')} className="hover:text-emerald-300 transition-colors text-left flex items-center gap-1.5">
                  <span>🖼️</span> Screenshot Scanner
                </button>
              </li>
              <li>
                <button onClick={() => handleScannerClick('text')} className="hover:text-emerald-300 transition-colors text-left">
                  Instant Scam Detection
                </button>
              </li>
            </ul>
          </div>

          {/* Column 2: Resources & Navigation */}
          <div className="space-y-3">
            <h4 className="text-sm font-bold text-white uppercase tracking-wider">
              Resources
            </h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li><a href="#how-it-works" className="hover:text-emerald-300 transition-colors">How It Works</a></li>
              <li><a href="#scanner-interface" className="hover:text-emerald-300 transition-colors">Scam Scanners</a></li>
              <li><a href="#faq" className="hover:text-emerald-300 transition-colors">Frequently Asked Questions</a></li>
              <li><a href="#faq" className="hover:text-emerald-300 transition-colors">Safety Guidance</a></li>
            </ul>
          </div>

        </div>

        {/* Bottom Compliance & Recognition Badges */}
        <div className="pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex flex-wrap items-center gap-4">
            <span className="text-slate-500 font-medium">Platform Modes:</span>
            <span className="bg-emerald-950 px-2.5 py-1 rounded-md border border-emerald-800 text-emerald-300 font-bold">
              Message Analysis
            </span>
            <span className="bg-emerald-950 px-2.5 py-1 rounded-md border border-emerald-800 text-emerald-300 font-bold">
              URL & Domain Safety
            </span>
            <span className="bg-emerald-950 px-2.5 py-1 rounded-md border border-emerald-800 text-emerald-300 font-bold">
              Screenshot OCR
            </span>
          </div>

          <div className="text-slate-500 text-center sm:text-right">
            © {CURRENT_YEAR} ScamX. All rights reserved.
          </div>
        </div>

      </div>

      {/* Floating Security Button Bottom-Left */}
      <div className="fixed bottom-5 left-5 z-40 hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#052418]/90 backdrop-blur-md border border-emerald-500/40 text-emerald-300 text-xs font-mono font-bold shadow-xl shadow-emerald-950/40">
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        <span>ScamX Sentinel Active</span>
      </div>

      {/* Circular Back-to-Top Button Bottom-Right */}
      <button
        onClick={scrollToTop}
        title="Back to top"
        className="fixed bottom-5 right-5 z-40 w-11 h-11 rounded-full bg-emerald-600 hover:bg-emerald-500 text-white shadow-xl shadow-emerald-950/30 flex items-center justify-center transition-all duration-200 hover:scale-110 focus:outline-none"
        aria-label="Back to top"
      >
        <ArrowUp className="w-5 h-5 stroke-[2.5]" />
      </button>

    </footer>
  );
}
