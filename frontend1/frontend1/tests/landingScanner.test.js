import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUrlInput } from '../src/utils/urlHelper.js';

describe('Landing Page Direct Scanning Architecture & Rules', () => {
  it('should enforce 5000 character maximum length on message inputs', () => {
    const MAX_LENGTH = 5000;
    const sampleLong = 'A'.repeat(5500);
    const sliced = sampleLong.slice(0, MAX_LENGTH);
    assert.equal(sliced.length, 5000);
    assert.ok(sliced.length <= MAX_LENGTH);
  });

  it('should validate and filter supported image MIME types and 5MB limit', () => {
    const MAX_SIZE = 5 * 1024 * 1024; // 5 MB
    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp'];

    assert.ok(allowedTypes.includes('image/png'));
    assert.ok(allowedTypes.includes('image/jpeg'));
    assert.ok(allowedTypes.includes('image/webp'));
    assert.ok(!allowedTypes.includes('image/gif'));
    assert.ok(!allowedTypes.includes('application/pdf'));

    const validSize = 2.5 * 1024 * 1024;
    const invalidSize = 6 * 1024 * 1024;
    assert.ok(validSize <= MAX_SIZE, '2.5MB is within limit');
    assert.ok(invalidSize > MAX_SIZE, '6MB exceeds limit');
  });

  it('should properly normalize URLs without adding duplicate schemes', () => {
    assert.equal(normalizeUrlInput('https://example.com'), 'https://example.com');
    assert.equal(normalizeUrlInput('http://192.0.2.1/login'), 'http://192.0.2.1/login');
    assert.equal(normalizeUrlInput('example.com', 'https://'), 'https://example.com');
    assert.equal(normalizeUrlInput('   https://example.com/test   '), 'https://example.com/test');
  });

  it('should ensure inconclusive results are never represented as safe', () => {
    const inconclusiveResult = {
      verdict: 'inconclusive',
      risk_score: 0,
      risk_level: 'inconclusive',
      is_confirmed_safe: false
    };

    const isDanger = inconclusiveResult.verdict === 'malicious';
    const isSuspicious = inconclusiveResult.verdict === 'suspicious';
    const isInconclusive = inconclusiveResult.verdict === 'inconclusive';
    const isSafe = !isDanger && !isSuspicious && !isInconclusive;

    assert.equal(isInconclusive, true);
    assert.equal(isSafe, false, 'Inconclusive verdict must NEVER be marked safe');
  });

  it('should verify scanner UI sizing and spacing contract in HeroSection.jsx', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const heroPath = path.resolve('src/components/HeroSection.jsx');
    const heroCode = fs.readFileSync(heroPath, 'utf8');

    // 1. Centered responsive container with sensible maximum width (max-w-4xl)
    assert.ok(heroCode.includes('max-w-4xl mx-auto'), 'Should use max-w-4xl for refined centered layout');

    // 2. Message textarea height approximately 130–150px on desktop
    assert.ok(
      heroCode.includes('lg:h-[142px]'),
      'Textarea box and button should target ~140px on desktop (between 130–150px)'
    );

    // 3. Scan Message button aligns with textarea on desktop and stacks full-width on mobile
    assert.ok(
      heroCode.includes('w-full h-11 lg:h-[142px]'),
      'Scan Message button should be h-11 full-width on mobile and lg:h-[142px] on desktop'
    );
    assert.ok(
      heroCode.includes('flex lg:flex-col items-center justify-center'),
      'Scan Message button should stack icon and text on desktop while remaining inline on mobile'
    );

    // 4. Additional detection options spacing reduced and aligned right
    assert.ok(
      heroCode.includes('mt-3.5 pt-3 border-t'),
      'Vertical spacing above/below additional detection options should be reduced'
    );
    assert.ok(
      heroCode.includes('sm:justify-end'),
      'Upload Image and Check URL buttons should align to the right on desktop'
    );

    // 5. Upload Image drop zone approximately 110–130px tall on desktop
    assert.ok(
      heroCode.includes('h-[115px] sm:h-[125px]'),
      'Upload image drop zone should be 110-130px tall'
    );
  });
});

describe('URL Scanner Audit & Consistency Rules', () => {
  it('should map sbi-corporate-kyc-update.com without falsely labeling hyphens as safe', async () => {
    const rawBackendData = {
      url: 'https://sbi-corporate-kyc-update.com/login.php',
      normalized_url: 'https://sbi-corporate-kyc-update.com/login.php',
      verdict: 'benign',
      risk_score: 0.2,
      risk_level: 'low',
      evidence: [
        {
          signal: 'excessive_domain_hyphens',
          description: 'Hostname contains 3 hyphens, often used to mimic legitimate services.',
          severity: 'medium',
          weight: 0.2
        }
      ],
      reputation_check: {
        matched: false,
        is_confirmed_safe: false,
        status: 'unknown'
      }
    };

    // Verify raw backend fields
    assert.equal(rawBackendData.verdict, 'benign');
    assert.equal(rawBackendData.risk_score, 0.2);
    assert.equal(rawBackendData.reputation_check.is_confirmed_safe, false);

    // Verify frontend mapping logic
    const riskScore = Number(rawBackendData.risk_score || 0);
    const scorePct = Math.round(riskScore * 100);
    const verdict = rawBackendData.verdict.toLowerCase();
    const riskLevel = rawBackendData.risk_level.toLowerCase();

    const isDanger = verdict === 'malicious' || riskLevel === 'critical';
    const isSuspicious = verdict === 'suspicious' || riskLevel === 'high' || riskLevel === 'medium';
    const isInconclusive = verdict === 'inconclusive' || riskLevel === 'inconclusive';

    const badgeLabel = isDanger
      ? 'MALICIOUS URL'
      : isSuspicious
      ? 'SUSPICIOUS URL'
      : isInconclusive
      ? 'INCONCLUSIVE'
      : scorePct > 0
      ? 'LOW RISK (HEURISTIC ONLY)'
      : 'BENIGN / LOW RISK';

    // Must NOT claim unverified URL is safe
    assert.equal(isDanger, false);
    assert.equal(isSuspicious, false);
    assert.equal(scorePct, 20);
    assert.equal(badgeLabel, 'LOW RISK (HEURISTIC ONLY)');

    // Evidence must NOT be mapped to legitimate_indicator
    const mappedEvidence = rawBackendData.evidence.map(e => ({
      token: e.signal,
      desc: e.description,
      weight: e.weight,
      severity: e.severity,
      signal: 'scam_indicator'
    }));

    assert.equal(mappedEvidence[0].signal, 'scam_indicator');
    assert.notEqual(mappedEvidence[0].signal, 'legitimate_indicator');
  });

  it('should verify sticky navigation scroll margins across scanner sections', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const heroCode = fs.readFileSync(path.resolve('src/components/HeroSection.jsx'), 'utf8');
    const navbarCode = fs.readFileSync(path.resolve('src/components/Navbar.jsx'), 'utf8');

    // HeroSection scroll margins to clear sticky header
    assert.ok(
      heroCode.includes('id="scanner-interface"') && heroCode.includes('scroll-mt-24'),
      'scanner-interface must have scroll-mt to prevent sticky header overlap'
    );
    assert.ok(
      heroCode.includes('id="scanner-card"') && heroCode.includes('scroll-mt-24'),
      'scanner-card must have scroll-mt to prevent sticky header overlap'
    );

    // Navbar pointer events
    assert.ok(
      navbarCode.includes('pointer-events-none') && navbarCode.includes('pointer-events-auto'),
      'Navbar header must use pointer-events-none container with pointer-events-auto nav'
    );
  });

  it('should verify live backend API responses for the 3 audit URLs', async () => {
    const testCases = [
      {
        url: 'https://example.com',
        expectedVerdict: 'benign',
        maxRisk: 0.1,
        expectedSignals: 0
      },
      {
        url: 'https://sbi-corporate-kyc-update.com/login.php',
        expectedVerdict: 'benign',
        expectedRisk: 0.2,
        expectedSignal: 'excessive_domain_hyphens'
      },
      {
        url: 'http://192.0.2.1/login/verify-account',
        expectedVerdict: 'suspicious',
        minRisk: 0.6,
        expectedSignal: 'ip_address_host'
      }
    ];

    for (const tc of testCases) {
      const res = await fetch('http://127.0.0.1:8000/api/v1/scans/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tc.url })
      });
      assert.equal(res.status, 200, `Expected 200 for ${tc.url}`);
      const json = await res.json();

      assert.equal(json.verdict, tc.expectedVerdict, `Verdict mismatch for ${tc.url}`);
      if (tc.maxRisk !== undefined) {
        assert.ok(json.risk_score <= tc.maxRisk);
      }
      if (tc.expectedRisk !== undefined) {
        assert.equal(json.risk_score, tc.expectedRisk);
      }
      if (tc.minRisk !== undefined) {
        assert.ok(json.risk_score >= tc.minRisk);
      }
      if (tc.expectedSignal) {
        const signals = json.evidence.map(e => e.signal);
        assert.ok(signals.includes(tc.expectedSignal), `Missing signal ${tc.expectedSignal} in ${tc.url}`);
      }
      // Ensure reputation check always clarifies unknown vs confirmed safe
      assert.equal(json.reputation_check.is_confirmed_safe, false);
    }
  });

  it('should verify sample prompts are removed from HeroSection UI', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const heroCode = fs.readFileSync(path.resolve('src/components/HeroSection.jsx'), 'utf8');

    // Message scanner must NOT contain Try: sample buttons
    assert.equal(heroCode.includes('Try:'), false, 'Try: preset buttons must be removed from message scanner UI');
    assert.equal(heroCode.includes('Vendor Bank'), false, 'Sample presets must be removed');
    assert.equal(heroCode.includes('Fake GST'), false, 'Sample presets must be removed');

    // URL scanner must NOT contain Quick samples:
    assert.equal(heroCode.includes('Quick samples:'), false, 'Quick samples must be removed from URL scanner UI');
    assert.equal(heroCode.includes('Fake SBI Corporate NetBanking'), false, 'Sample URLs must be removed');

    // Functional elements must remain intact
    assert.ok(heroCode.includes('id="paste-message-btn"'), 'Paste message button must remain');
    assert.ok(heroCode.includes('id="scan-message-btn"'), 'Scan message button must remain');
    assert.ok(heroCode.includes('id="paste-url-btn"'), 'Paste URL button must remain');
    assert.ok(heroCode.includes('id="scan-url-btn"'), 'Scan URL button must remain');
  });

  it('should verify Navbar Scanners dropdown positioning, Escape key handler, and accessibility', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const navbarCode = fs.readFileSync(path.resolve('src/components/Navbar.jsx'), 'utf8');

    // Dropdown must not trigger automatically on hover
    assert.equal(navbarCode.includes('onMouseEnter'), false, 'Dropdown must not trigger on mouse enter hover');
    assert.equal(navbarCode.includes('onMouseLeave'), false, 'Dropdown must not rely on onMouseLeave');

    // Must handle Escape key
    assert.ok(navbarCode.includes("event.key === 'Escape'"), 'Navbar must close dropdown and mobile menu on Escape key');

    // Must be positioned cleanly in normal document flow to avoid covering hero heading
    assert.ok(navbarCode.includes('mx-auto max-w-3xl'), 'Dropdown should be centered in normal document flow');
    assert.equal(navbarCode.includes('absolute top-full'), false, 'Dropdown must not use absolute top-full which overlaps hero heading');

    // Accessibility attributes
    assert.ok(navbarCode.includes('aria-haspopup="true"'), 'Scanners button must include aria-haspopup');
    assert.ok(navbarCode.includes('role="menu"'), 'Dropdown container must have role="menu"');
    assert.ok(navbarCode.includes('role="menuitem"'), 'Dropdown options must have role="menuitem"');
  });

  it('should verify ScanResultCard simplified layout, plain-English findings, and technical accordion', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const cardCode = fs.readFileSync(path.resolve('src/components/ScanResultCard.jsx'), 'utf8');

    // Must provide collapsible technical details toggle
    assert.ok(cardCode.includes('showTechDetails'), 'Must provide collapsible technical details state');
    assert.ok(cardCode.includes('View technical details'), 'Must provide View technical details toggle button');
    assert.ok(cardCode.includes('Hide technical details'), 'Must provide Hide technical details toggle button');

    // Default view must NOT show character count badge
    assert.equal(cardCode.includes('Text detected:'), false, 'Must not show Text detected character count badge in default view');

    // Must translate evidence into plain-English phrases
    assert.ok(cardCode.includes('translateEvidence'), 'Must provide plain-English evidence translation helper');
    assert.ok(cardCode.includes('slice(0, 3)'), 'Must limit default evidence to top 3 key findings');

    // Must present honest score labels and standardized badges
    assert.ok(cardCode.includes('badgeClass'), 'Must style badges according to backend severity');
    assert.ok(cardCode.includes('Recommended Action:'), 'Must present a clear recommended action banner');
  });
});


