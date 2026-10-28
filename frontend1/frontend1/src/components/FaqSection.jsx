import React, { useState } from 'react';
import { ChevronDown, HelpCircle, AlertTriangle } from 'lucide-react';

export default function FaqSection() {
  const [openIndex, setOpenIndex] = useState(0);

  const faqs = [
    {
      q: "What is ScamX and how does it work?",
      a: "ScamX is an AI-assisted scam detection platform designed to help you analyze suspicious messages, links, and screenshots before you interact with them. It inspects domain registrations for lookalike indicators, evaluates message texts for coercive urgency and deception cues, and uses optical character recognition (OCR) to extract and analyze text from uploaded screenshots."
    },
    {
      q: "Does an inconclusive result mean the content is safe?",
      a: "No. An inconclusive result does NOT mean the content is safe. It simply means our automated checks could not conclusively prove malicious intent based on available indicators. Scammers frequently invent new templates, use compromised legitimate accounts, or deploy zero-day domains. If a scan is inconclusive or indicates low risk, you should still exercise caution, never share sensitive passwords or OTPs, and verify independently through official channels."
    },
    {
      q: "Does ScamX provide guaranteed protection against all scams?",
      a: "No automated tool can provide guaranteed protection against every threat. ScamX is designed as an assistive detection tool to help identify common warning signs, lookalike patterns, and phishing formulas. Users must remain vigilant, cross-check unexpected requests through verified phone numbers or official websites, and avoid clicking unverified links."
    },
    {
      q: "What can I analyze with each of the three scanner options?",
      a: "ScamX provides three specialized scanners: (1) Message Scanner: Inspect email text, SMS messages, or chat communications for social engineering and payment coercion. (2) URL Safety Checker: Check suspicious web links, shortened URLs, and login domains for punycode spoofing, recent registration flags, and phishing indicators. (3) Screenshot Scanner: Upload images of chat messages, notices, or digital payment requests for OCR text extraction and scam analysis."
    },
    {
      q: "What should I do if ScamX flags content as high risk?",
      a: "If ScamX flags a message or link as high risk, do not click the link, do not reply to the sender, and do not provide any passwords, credentials, or funds. If the message claims to come from an organization you deal with (like a bank, utility, or colleague), contact them directly using a known, trusted phone number or their official verified website."
    },
    {
      q: "How does ScamX handle uploaded text and screenshots?",
      a: "Inputs provided to the scanner are processed ephemerally solely to perform threat analysis, compute the risk assessment, and generate the audit scorecard. We advise never submitting unredacted personal identification numbers, passwords, or confidential account credentials."
    }
  ];

  const toggleFaq = (index) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section id="faq" className="py-20 bg-white border-b border-emerald-100/70 scroll-mt-24 sm:scroll-mt-28">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="text-center mb-14">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-50 text-emerald-800 text-xs font-bold uppercase tracking-wider mb-4 border border-emerald-200">
            <HelpCircle className="w-3.5 h-3.5 text-emerald-600" />
            <span>Got Questions?</span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#052418] tracking-tight">
            Frequently asked <span className="text-emerald-600">questions.</span>
          </h2>

          <p className="mt-4 text-base text-slate-600">
            Learn more about how ScamX analyzes suspicious content and how to interpret your scan results.
          </p>
        </div>

        {/* Accordion List */}
        <div className="space-y-4">
          {faqs.map((faq, idx) => {
            const isOpen = openIndex === idx;
            return (
              <div 
                key={idx}
                className={`rounded-2xl border transition-all duration-200 overflow-hidden ${
                  isOpen 
                    ? 'border-emerald-400 bg-emerald-50/40 shadow-md shadow-emerald-950/5' 
                    : 'border-slate-200 hover:border-emerald-200 bg-white'
                }`}
              >
                <button
                  onClick={() => toggleFaq(idx)}
                  className="w-full p-5 sm:p-6 text-left flex items-center justify-between gap-4 focus:outline-none"
                >
                  <span className="font-bold text-base sm:text-lg text-[#052418]">
                    {faq.q}
                  </span>
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 transition-transform duration-200 ${
                    isOpen ? 'bg-emerald-600 text-white rotate-180' : 'bg-slate-100 text-slate-500'
                  }`}>
                    <ChevronDown className="w-4 h-4" />
                  </div>
                </button>

                {isOpen && (
                  <div className="px-5 pb-6 sm:px-6 text-sm text-slate-600 leading-relaxed border-t border-emerald-100/60 pt-4 animate-in fade-in duration-200">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Advisory Callout Card */}
        <div className="mt-12 p-6 rounded-3xl bg-amber-50 border-2 border-amber-200/90 text-amber-950 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-700 flex-shrink-0 mt-0.5" />
            <div className="text-xs sm:text-sm leading-relaxed">
              <strong className="block font-bold text-amber-900 mb-0.5">Remember: Inconclusive does not mean safe</strong>
              <span>Always verify suspicious communications with the sender using independent, verified contact details before clicking or sharing information.</span>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}
