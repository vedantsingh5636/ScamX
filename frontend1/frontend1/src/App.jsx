import React, { useState } from 'react';
import Navbar from './components/Navbar';
import HeroSection from './components/HeroSection';
import WorkflowSection from './components/WorkflowSection';
import FaqSection from './components/FaqSection';
import CtaBanner from './components/CtaBanner';
import Footer from './components/Footer';
import ErrorBoundary from './components/ErrorBoundary';

export default function App() {
  // Active scanner panel on landing page: null | 'text' | 'url' | 'image'
  const [activeScannerPanel, setActiveScannerPanel] = useState(null);

  const scrollToScanner = () => {
    const el = document.getElementById('scanner-card') || document.getElementById('scanner-interface');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleSelectScanner = (panel) => {
    setActiveScannerPanel(panel);
    scrollToScanner();
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#F4FAF6] text-[#052418] relative selection:bg-emerald-200 selection:text-emerald-950">

      {/* Floating Header: ScamX branding, Scanners dropdown, How It Works, Help, Scan Now */}
      <Navbar
        onSelectScanner={handleSelectScanner}
      />

      {/* Main Content Sections: All scans are performed directly on the Landing Page */}
      <main className="flex-1">
        {/* 1. Main Landing Page Scanner: Hero, Message Scanner, Inline URL & Image, and Results */}
        <ErrorBoundary title="ScamX Main Scanner">
          <HeroSection
            externalActivePanel={activeScannerPanel}
            onPanelChange={setActiveScannerPanel}
          />
        </ErrorBoundary>

        {/* 2. "How It Works" Section: Input, Analysis, Results + Inconclusive Advisory */}
        <WorkflowSection />

        {/* 3. FAQ Accordion with Inconclusive Advisory & Guidance */}
        <FaqSection />

        {/* 4. Mint-Green CTA Banner */}
        <CtaBanner
          onSelectScanner={handleSelectScanner}
        />
      </main>

      {/* Footer: ScamX Branding, Disclaimers & Scanner Links */}
      <Footer
        onSelectScanner={handleSelectScanner}
      />

    </div>
  );
}
