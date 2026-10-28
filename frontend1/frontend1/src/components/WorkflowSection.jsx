import React, { useState } from 'react';
import { 
  Inbox, 
  Cpu, 
  CheckSquare, 
  ArrowRight, 
  Check, 
  AlertTriangle,
  Sparkles
} from 'lucide-react';

export default function WorkflowSection() {
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      id: "input",
      stepNum: "01",
      title: "Input",
      tagline: "Submit suspicious content",
      icon: Inbox,
      desc: "Provide the material you want to check. You can paste a suspicious link, paste email or SMS text, or upload a chat screenshot into ScamX.",
      highlights: [
        "URL Safety Checker accepts direct web links and domains",
        "Message Scanner accepts raw email text, WhatsApp messages, and SMS",
        "Screenshot Scanner accepts PNG, JPG, and WebP chat images"
      ],
      previewBadge: "Step 1: Input Ready",
      previewContent: {
        title: "Submission Inputs",
        items: [
          { type: "Link / URL", example: "https://suspicious-portal-login.com", icon: "🔗" },
          { type: "Message Text", example: "Urgent: Verify your account immediately...", icon: "💬" },
          { type: "Image / Screenshot", example: "chat_screenshot_demand.png", icon: "🖼️" },
        ]
      }
    },
    {
      id: "analysis",
      stepNum: "02",
      title: "Analysis",
      tagline: "AI-assisted threat evaluation",
      icon: Cpu,
      desc: "ScamX analyzes the submission across multiple threat indicators: inspecting domain authenticity, looking for deceptive urgency language, and extracting visual text.",
      highlights: [
        "Domain inspection evaluates lookalike names, punycode, and SSL indicators",
        "Linguistic analysis flags impersonation, threats, and coercion triggers",
        "OCR text extraction parses words and links embedded inside images"
      ],
      previewBadge: "Step 2: Analysis",
      previewContent: {
        title: "Evaluation Indicators",
        items: [
          { check: "Domain & Host Check", detail: "Lookalike name inspection & SSL flag", state: "warn" },
          { check: "Language & Intent", detail: "Coercive urgency & deactivation lure", state: "danger" },
          { check: "OCR Forensic Text", detail: "Extracted unverified destination handle", state: "warn" },
        ]
      }
    },
    {
      id: "results",
      stepNum: "03",
      title: "Results",
      tagline: "Actionable verdict & clear advice",
      icon: CheckSquare,
      desc: "Review a transparent threat score, categorized evidence breakdown, and clear advice to help you decide how to handle the communication.",
      highlights: [
        "Risk score from 0 to 100 with clear severity rating",
        "Itemized findings detailing each warning sign detected",
        "Actionable guidance on whether to proceed, report, or discard"
      ],
      previewBadge: "Step 3: Verdict",
      previewContent: {
        title: "Assessment Summary",
        verdict: "HIGH-RISK PHISHING LURE",
        score: "Risk Score: 92/100",
        advice: "Do not open the link or enter credentials. Verify directly with the genuine institution."
      }
    }
  ];

  return (
    <section id="how-it-works" className="py-20 bg-white border-y border-emerald-100/80 scroll-mt-24 sm:scroll-mt-28">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-14">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-bold uppercase tracking-wider mb-4">
            <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            <span>How It Works</span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#052418] tracking-tight">
            How ScamX <span className="text-emerald-600">detects scams.</span>
          </h2>

          <p className="mt-4 text-base sm:text-lg text-slate-600">
            A concise, transparent 3-step process to analyze suspicious content before you click or reply.
          </p>
        </div>

        {/* Step Selector Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            const isSelected = activeStep === idx;
            return (
              <button
                key={step.id}
                onClick={() => setActiveStep(idx)}
                className={`p-5 sm:p-6 rounded-2xl text-left transition-all duration-200 border-2 relative ${
                  isSelected 
                    ? 'bg-emerald-50/80 border-emerald-500 shadow-lg shadow-emerald-900/5' 
                    : 'bg-white border-slate-100 hover:border-emerald-200 hover:bg-slate-50/60'
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-md ${
                    isSelected ? 'bg-emerald-600 text-white' : 'bg-slate-100 text-slate-500'
                  }`}>
                    Step {step.stepNum}
                  </span>
                  <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                    isSelected ? 'bg-emerald-500 text-white' : 'bg-slate-100 text-slate-600'
                  }`}>
                    <Icon className="w-4 h-4" />
                  </div>
                </div>

                <div className={`font-bold text-lg ${
                  isSelected ? 'text-emerald-950' : 'text-slate-800'
                }`}>
                  {step.title}
                </div>
                
                <div className="text-xs text-slate-500 mt-1 line-clamp-1">
                  {step.tagline}
                </div>

                {isSelected && (
                  <div className="hidden md:block absolute -bottom-2.5 left-1/2 -translate-x-1/2 w-4 h-4 bg-emerald-500 rotate-45 rounded-sm" />
                )}
              </button>
            );
          })}
        </div>

        {/* Active Step Detailed Card */}
        <div className="bg-gradient-to-br from-emerald-950 via-[#062A1E] to-[#041D14] rounded-3xl p-6 sm:p-10 lg:p-12 text-white shadow-2xl shadow-emerald-950/20 border border-emerald-800/40 relative overflow-hidden">
          
          {/* Subtle Grid overlay */}
          <div className="absolute inset-0 bg-plus-grid-dark opacity-40 pointer-events-none" />

          <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            
            {/* Left Column: Description & Highlights */}
            <div className="lg:col-span-7 space-y-6">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/20 border border-emerald-400/30 text-emerald-300 text-xs font-bold">
                <span>Phase {steps[activeStep].stepNum} of 03</span>
                <span>•</span>
                <span>{steps[activeStep].title}: {steps[activeStep].tagline}</span>
              </div>

              <h3 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
                {steps[activeStep].title}: {steps[activeStep].tagline}
              </h3>

              <p className="text-emerald-100/80 text-sm sm:text-base leading-relaxed">
                {steps[activeStep].desc}
              </p>

              <div className="space-y-3 pt-2">
                {steps[activeStep].highlights.map((point, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <div className="w-5 h-5 rounded-full bg-emerald-500/30 text-emerald-300 flex items-center justify-center flex-shrink-0 mt-0.5 border border-emerald-400/40">
                      <Check className="w-3.5 h-3.5 stroke-[3]" />
                    </div>
                    <span className="text-sm text-emerald-100 font-medium">
                      {point}
                    </span>
                  </div>
                ))}
              </div>

              <div className="pt-4 flex items-center gap-4">
                <button
                  onClick={() => setActiveStep((prev) => (prev + 1) % steps.length)}
                  className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-emerald-600/30 transition-all"
                >
                  <span>Next: {steps[(activeStep + 1) % steps.length].title}</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Right Column: Interactive Step Preview Box */}
            <div className="lg:col-span-5">
              <div className="bg-[#0A3828]/90 backdrop-blur-md rounded-2xl p-6 border border-emerald-500/30 shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-emerald-800/60">
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-300">
                    {steps[activeStep].previewContent.title}
                  </span>
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-400/40">
                    {steps[activeStep].previewBadge}
                  </span>
                </div>

                {/* Step specific preview contents */}
                {activeStep === 0 && (
                  <div className="space-y-2.5">
                    {steps[0].previewContent.items.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 rounded-xl bg-emerald-950/60 border border-emerald-700/40 text-xs">
                        <div className="flex items-center gap-2.5">
                          <span className="text-base">{item.icon}</span>
                          <div>
                            <div className="font-bold text-white">{item.type}</div>
                            <div className="text-emerald-300/70 text-[11px] font-mono truncate max-w-[190px]">{item.example}</div>
                          </div>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold text-[10px]">
                          Supported
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {activeStep === 1 && (
                  <div className="space-y-2.5">
                    {steps[1].previewContent.items.map((item, idx) => (
                      <div key={idx} className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-700/40 text-xs flex items-center justify-between">
                        <div>
                          <span className="text-emerald-300/80 font-medium">{item.check}</span>
                          <div className="text-white font-bold text-[11px] mt-0.5">{item.detail}</div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          item.state === 'danger' ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                          'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}>
                          {item.state.toUpperCase()}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {activeStep === 2 && (
                  <div className="space-y-3">
                    <div className="p-4 rounded-xl bg-red-950/50 border border-red-500/40 text-center space-y-1.5">
                      <div className="text-red-400 text-xs font-black uppercase tracking-wider">
                        {steps[2].previewContent.verdict}
                      </div>
                      <div className="text-base font-black text-white">
                        {steps[2].previewContent.score}
                      </div>
                      <div className="text-xs text-red-200 leading-snug">
                        {steps[2].previewContent.advice}
                      </div>
                    </div>
                    <div className="text-[11px] text-center text-emerald-300/80">
                      Clear advice to help you proceed safely.
                    </div>
                  </div>
                )}

              </div>
            </div>

          </div>

        </div>

        {/* Prominent Critical Advisory Box (Explicit Requirement) */}
        <div className="mt-10 rounded-2xl p-5 sm:p-6 bg-amber-50 border-2 border-amber-300 text-amber-950 flex flex-col sm:flex-row items-start sm:items-center gap-4 shadow-sm">
          <div className="w-10 h-10 rounded-xl bg-amber-200/80 text-amber-900 flex items-center justify-center flex-shrink-0 font-black text-lg">
            <AlertTriangle className="w-5 h-5 text-amber-800" />
          </div>
          <div className="flex-1 text-xs sm:text-sm leading-relaxed">
            <strong className="block text-amber-950 font-bold mb-0.5">
              Crucial Safety Note: An Inconclusive Result Does Not Mean Content Is Safe
            </strong>
            <span>
              Automated AI analysis is an assistive tool and cannot guarantee 100% protection against new, evolving, or targeted deception tactics. If an analysis returns an inconclusive verdict or low risk score, never assume the message or link is safe. Always verify independently through official, verified channels and never share sensitive credentials, OTPs, or passwords.
            </span>
          </div>
        </div>

      </div>
    </section>
  );
}
