import React from 'react';
import { 
  ShieldCheck, 
  ArrowRight, 
  Sparkles, 
  MessageSquare,
  Globe,
  AlertTriangle,
  Lock
} from 'lucide-react';

export default function CtaBanner({ onSelectScanner, onOpenWorkstation }) {
  const handleScanMessage = () => {
    if (onSelectScanner) {
      onSelectScanner('text');
    } else if (onOpenWorkstation) {
      onOpenWorkstation('text');
    }
  };

  const handleCheckUrl = () => {
    if (onSelectScanner) {
      onSelectScanner('url');
    } else if (onOpenWorkstation) {
      onOpenWorkstation('url');
    }
  };

  return (
    <section className="py-16 sm:py-24 bg-gradient-to-b from-white to-[#F4FAF6]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Mint Green Card Container */}
        <div className="relative rounded-3xl p-8 sm:p-12 lg:p-16 bg-gradient-to-br from-[#E4F5EB] via-[#D2EEDB] to-[#BCDFCA] border-2 border-emerald-300 shadow-2xl shadow-emerald-950/10 overflow-hidden">
          
          {/* Subtle Plus Grid background */}
          <div className="absolute inset-0 bg-plus-grid opacity-30 pointer-events-none" />

          <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            
            {/* Left 8 Cols: Content */}
            <div className="lg:col-span-8 space-y-6">
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-800 text-emerald-100 text-xs font-bold uppercase tracking-wider shadow-sm">
                <Sparkles className="w-3.5 h-3.5 text-emerald-300" />
                <span>AI-Assisted Scam Detection</span>
              </div>

              <h2 className="text-3xl sm:text-5xl lg:text-6xl font-black text-[#052418] tracking-tight leading-[1.15]">
                Detect scams before you click.
              </h2>

              <p className="text-base sm:text-lg text-emerald-950 font-medium max-w-xl leading-relaxed">
                Analyze suspicious messages, links, and screenshots with AI-assisted scam detection.
              </p>

              <div className="flex flex-col sm:flex-row items-center gap-4 pt-2">
                <button
                  onClick={handleScanMessage}
                  className="w-full sm:w-auto px-8 py-4 rounded-full bg-gradient-to-r from-[#052418] to-[#0B3D2B] hover:from-[#083020] hover:to-[#0F523A] text-white font-extrabold text-sm sm:text-base shadow-xl shadow-emerald-950/25 flex items-center justify-center gap-3 transition-transform hover:scale-105"
                >
                  <MessageSquare className="w-4 h-4 text-emerald-400" />
                  <span>Scan a Message</span>
                  <ArrowRight className="w-5 h-5 text-emerald-400" />
                </button>

                <button
                  onClick={handleCheckUrl}
                  className="w-full sm:w-auto px-7 py-4 rounded-full bg-white hover:bg-emerald-50 text-emerald-950 font-bold text-sm sm:text-base border-2 border-emerald-300 shadow-md flex items-center justify-center gap-2.5 transition-transform hover:scale-105"
                >
                  <Globe className="w-4 h-4 text-emerald-600" />
                  <span>Check a URL</span>
                  <ArrowRight className="w-4 h-4 text-emerald-600" />
                </button>
              </div>

              {/* Crucial Advisory Notice */}
              <div className="pt-2 flex items-start gap-2 text-xs font-semibold text-emerald-900">
                <AlertTriangle className="w-4 h-4 text-emerald-800 flex-shrink-0 mt-0.5" />
                <span>Important: An inconclusive result does not mean content is safe. Always verify unknown senders.</span>
              </div>
            </div>

            {/* Right 4 Cols: 3D Shield graphic */}
            <div className="lg:col-span-4 flex justify-center lg:justify-end">
              <div className="relative">
                <div className="w-48 h-48 sm:w-56 sm:h-56 rounded-3xl bg-gradient-to-br from-emerald-500 via-emerald-700 to-emerald-950 p-2 shadow-2xl shadow-emerald-900/30 flex items-center justify-center transform hover:rotate-3 transition-transform duration-300">
                  <div className="w-full h-full rounded-[20px] bg-gradient-to-b from-emerald-600/90 to-emerald-950 flex flex-col items-center justify-center text-white border border-emerald-300/40 p-4 text-center">
                    <ShieldCheck className="w-20 h-20 text-emerald-200 stroke-[2.2] drop-shadow-lg" />
                    <span className="text-sm font-black tracking-wider text-emerald-200 mt-2 uppercase">
                      ScamX
                    </span>
                    <span className="text-[10px] text-emerald-300/80 font-mono mt-0.5">
                      Threat Intelligence Engine
                    </span>
                  </div>
                </div>

                {/* Badge attached to shield */}
                <div className="absolute -bottom-3 -right-3 px-3.5 py-1.5 rounded-full bg-white text-emerald-900 font-extrabold text-xs shadow-lg border border-emerald-200 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Verified Safe Mode</span>
                </div>
              </div>
            </div>

          </div>

        </div>

      </div>
    </section>
  );
}
