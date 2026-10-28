import React, { useState, useRef, useEffect } from 'react';
import { 
  ShieldCheck, 
  Menu, 
  X, 
  ChevronDown, 
  Sparkles,
  HelpCircle,
  ArrowRight
} from 'lucide-react';

export default function Navbar({ onSelectScanner }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [scannersDropdownOpen, setScannersDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);
  const buttonRef = useRef(null);

  // Close dropdown when clicking outside or touching outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target) &&
        buttonRef.current &&
        !buttonRef.current.contains(event.target)
      ) {
        setScannersDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
    };
  }, []);

  // Close dropdown or mobile menu when pressing Escape
  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === 'Escape') {
        setScannersDropdownOpen(false);
        setMobileMenuOpen(false);
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleScannerSelect = (tab) => {
    setScannersDropdownOpen(false);
    setMobileMenuOpen(false);
    if (onSelectScanner) {
      onSelectScanner(tab);
    }
  };

  const scrollTo = (id) => {
    setMobileMenuOpen(false);
    setScannersDropdownOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className="sticky top-2 sm:top-4 z-50 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto transition-all duration-300 pointer-events-none">
      <nav className="glass-nav rounded-full px-4 sm:px-6 py-2.5 sm:py-3 shadow-lg shadow-emerald-950/5 flex items-center justify-between border border-emerald-100/90 relative pointer-events-auto">
        
        {/* Brand Logo: ScamX */}
        <a href="#" className="flex items-center gap-2.5 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400 to-emerald-700 flex items-center justify-center text-white shadow-md shadow-emerald-500/30 group-hover:scale-105 transition-transform duration-200">
            <ShieldCheck className="w-6 h-6 stroke-[2.2]" />
          </div>
          <div className="flex items-center gap-1.5">
            <span className="font-extrabold text-2xl tracking-tight text-[#052418]">
              Scam<span className="text-emerald-600">X</span>
            </span>
          </div>
        </a>

        {/* Desktop Navigation Links */}
        <div className="hidden md:flex items-center gap-3 text-sm font-semibold text-slate-700">
          
          {/* Scanners Button (Toggles Scanners Menu in normal document flow) */}
          <div>
            <button
              type="button"
              id="scanners-menu-btn"
              ref={buttonRef}
              aria-haspopup="true"
              aria-expanded={scannersDropdownOpen}
              aria-controls="scanners-dropdown-menu"
              aria-label="Toggle scam detection engines"
              onClick={() => setScannersDropdownOpen(prev => !prev)}
              className={`px-4 py-2 rounded-full font-bold transition-all flex items-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-emerald-500/30 ${
                scannersDropdownOpen
                  ? 'bg-emerald-100 text-emerald-900 border border-emerald-300/80 shadow-sm'
                  : 'hover:text-emerald-800 hover:bg-emerald-50/80 text-slate-800'
              }`}
            >
              <Sparkles className="w-4 h-4 text-emerald-600" />
              <span>Scanners</span>
              <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${
                scannersDropdownOpen ? 'rotate-180 text-emerald-700' : 'text-slate-500'
              }`} />
            </button>
          </div>

          {/* How It Works Link */}
          <button 
            onClick={() => scrollTo('how-it-works')}
            className="px-4 py-2 rounded-full hover:text-emerald-700 hover:bg-emerald-50/70 transition-colors"
          >
            <span>How It Works</span>
          </button>

          {/* Help Button */}
          <button 
            onClick={() => scrollTo('faq')}
            className="px-4 py-2 rounded-full hover:text-emerald-700 hover:bg-emerald-50/70 transition-colors flex items-center gap-1.5"
          >
            <HelpCircle className="w-4 h-4 text-emerald-600" />
            <span>Help</span>
          </button>
        </div>

        {/* Right Action: Scan Now */}
        <div className="hidden sm:flex items-center gap-3">
          <button
            onClick={() => handleScannerSelect('text')}
            className="bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white font-bold text-xs sm:text-sm px-5 py-2.5 rounded-full shadow-md shadow-emerald-600/30 hover:shadow-emerald-600/50 hover:scale-[1.02] active:scale-[0.98] transition-all duration-200 flex items-center gap-2"
          >
            <span>Scan Now</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Mobile menu button */}
        <div className="flex md:hidden items-center gap-2">
          <button
            onClick={() => handleScannerSelect('text')}
            className="bg-emerald-600 text-white font-bold text-xs px-3.5 py-1.5 rounded-full"
          >
            Scan Now
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-xl text-slate-700 hover:bg-emerald-50 focus:outline-none"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {/* Desktop Scanners Dropdown Panel (rendered in normal document flow directly below navbar pill so it pushes content down and never overlaps the hero section) */}
      {scannersDropdownOpen && (
        <div 
          id="scanners-dropdown-menu"
          role="menu"
          aria-labelledby="scanners-menu-btn"
          ref={dropdownRef}
          className="hidden md:block mt-2.5 mx-auto max-w-3xl bg-white/98 backdrop-blur-2xl rounded-2xl p-2.5 border border-emerald-100/90 shadow-2xl shadow-emerald-950/15 animate-in fade-in slide-in-from-top-2 duration-150 pointer-events-auto"
        >
          <div className="grid grid-cols-3 gap-2">
            {/* Option 1: Message Scanner */}
            <button
              type="button"
              role="menuitem"
              onClick={() => handleScannerSelect('text')}
              className="text-left p-2.5 rounded-xl hover:bg-emerald-50/80 transition-colors flex items-start gap-3 group focus:outline-none focus:ring-2 focus:ring-emerald-500/30"
            >
              <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center flex-shrink-0 group-hover:scale-105 transition-transform mt-0.5">
                <span className="text-base">💬</span>
              </div>
              <div className="min-w-0">
                <div className="text-xs font-bold text-slate-900 group-hover:text-emerald-800 flex items-center gap-1">
                  <span className="truncate">Message Scanner</span>
                  <span className="text-[10px] bg-emerald-100 text-emerald-800 font-bold px-1.5 py-0.2 rounded-full flex-shrink-0">Text</span>
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                  Analyze suspicious messages, SMS & emails
                </div>
              </div>
            </button>

            {/* Option 2: URL Safety Checker */}
            <button
              type="button"
              role="menuitem"
              onClick={() => handleScannerSelect('url')}
              className="text-left p-2.5 rounded-xl hover:bg-emerald-50/80 transition-colors flex items-start gap-3 group focus:outline-none focus:ring-2 focus:ring-emerald-500/30"
            >
              <div className="w-8 h-8 rounded-xl bg-cyan-100 text-cyan-700 flex items-center justify-center flex-shrink-0 group-hover:scale-105 transition-transform mt-0.5">
                <span className="text-base">🔗</span>
              </div>
              <div className="min-w-0">
                <div className="text-xs font-bold text-slate-900 group-hover:text-emerald-800 flex items-center gap-1">
                  <span className="truncate">URL Safety Checker</span>
                  <span className="text-[10px] bg-cyan-100 text-cyan-800 font-bold px-1.5 py-0.2 rounded-full flex-shrink-0">Link</span>
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                  Check links for phishing & lookalike domains
                </div>
              </div>
            </button>

            {/* Option 3: Screenshot Scanner */}
            <button
              type="button"
              role="menuitem"
              onClick={() => handleScannerSelect('image')}
              className="text-left p-2.5 rounded-xl hover:bg-emerald-50/80 transition-colors flex items-start gap-3 group focus:outline-none focus:ring-2 focus:ring-emerald-500/30"
            >
              <div className="w-8 h-8 rounded-xl bg-teal-100 text-teal-700 flex items-center justify-center flex-shrink-0 group-hover:scale-105 transition-transform mt-0.5">
                <span className="text-base">🖼️</span>
              </div>
              <div className="min-w-0">
                <div className="text-xs font-bold text-slate-900 group-hover:text-emerald-800 flex items-center gap-1">
                  <span className="truncate">Screenshot Scanner</span>
                  <span className="text-[10px] bg-teal-100 text-teal-800 font-bold px-1.5 py-0.2 rounded-full flex-shrink-0">OCR</span>
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                  Extract & inspect text from chat images
                </div>
              </div>
            </button>
          </div>
        </div>
      )}

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-2 bg-white/95 backdrop-blur-xl rounded-3xl p-5 border border-emerald-100 shadow-xl shadow-emerald-950/10 space-y-4 animate-in fade-in slide-in-from-top-2 duration-200 pointer-events-auto">
          
          {/* Mobile Scanners List */}
          <div className="space-y-1">
            <div className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400 px-3 py-1">
              Scanners
            </div>

            <button 
              onClick={() => handleScannerSelect('text')}
              className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-emerald-50 text-xs font-bold text-slate-800 flex items-center gap-2.5"
            >
              <span>💬</span>
              <div>
                <div>Message Scanner</div>
                <div className="text-[10px] text-slate-500 font-normal">Analyze suspicious messages, SMS & emails</div>
              </div>
            </button>

            <button 
              onClick={() => handleScannerSelect('url')}
              className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-emerald-50 text-xs font-bold text-slate-800 flex items-center gap-2.5"
            >
              <span>🔗</span>
              <div>
                <div>URL Safety Checker</div>
                <div className="text-[10px] text-slate-500 font-normal">Phishing link & domain check</div>
              </div>
            </button>

            <button 
              onClick={() => handleScannerSelect('image')}
              className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-emerald-50 text-xs font-bold text-slate-800 flex items-center gap-2.5"
            >
              <span>🖼️</span>
              <div>
                <div>Screenshot Scanner</div>
                <div className="text-[10px] text-slate-500 font-normal">OCR + scam pattern detection</div>
              </div>
            </button>
          </div>

          {/* How It Works & Help links */}
          <div className="pt-2 border-t border-slate-100 space-y-1">
            <button 
              onClick={() => scrollTo('how-it-works')}
              className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-emerald-50 text-xs font-bold text-slate-800 flex items-center gap-2"
            >
              <Sparkles className="w-4 h-4 text-emerald-600" />
              <span>How It Works</span>
            </button>

            <button 
              onClick={() => scrollTo('faq')}
              className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-emerald-50 text-xs font-bold text-slate-800 flex items-center gap-2"
            >
              <HelpCircle className="w-4 h-4 text-emerald-600" />
              <span>Help & FAQ</span>
            </button>
          </div>

        </div>
      )}
    </header>
  );
}
