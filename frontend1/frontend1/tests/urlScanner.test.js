import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUrlInput, extractProtocol, syncUrlWithProtocol } from '../src/utils/urlHelper.js';

describe('URL Normalization & Scanner Input Strategy', () => {
  it('should send https://example.com unchanged after trimming whitespace', () => {
    const input = 'https://example.com';
    const normalized = normalizeUrlInput(input, 'https://');
    assert.equal(normalized, 'https://example.com');

    // Even if dropdown is set to http://, the complete URL scheme must be preserved unchanged
    const normalizedWithHttpDropdown = normalizeUrlInput(input, 'http://');
    assert.equal(normalizedWithHttpDropdown, 'https://example.com');

    // With leading and trailing whitespace
    const withWhitespace = normalizeUrlInput('   https://example.com   ', 'https://');
    assert.equal(withWhitespace, 'https://example.com');
  });

  it('should send http://192.0.2.1/login/verify-account unchanged', () => {
    const input = 'http://192.0.2.1/login/verify-account';
    // Even if dropdown is set to https://, the complete http:// scheme must be preserved unchanged
    const normalized = normalizeUrlInput(input, 'https://');
    assert.equal(normalized, 'http://192.0.2.1/login/verify-account');

    // With whitespace
    const withWhitespace = normalizeUrlInput('  http://192.0.2.1/login/verify-account \n', 'https://');
    assert.equal(withWhitespace, 'http://192.0.2.1/login/verify-account');
  });

  it('should combine a hostname entered without a protocol with selected protocol exactly once', () => {
    // When dropdown is set to http://
    const input = 'example.com';
    const normalizedHttp = normalizeUrlInput(input, 'http://');
    assert.equal(normalizedHttp, 'http://example.com');

    // With path
    const inputWithPath = '192.0.2.1/login/verify-account';
    const normalizedPath = normalizeUrlInput(inputWithPath, 'http://');
    assert.equal(normalizedPath, 'http://192.0.2.1/login/verify-account');
  });

  it('should combine a hostname entered when the dropdown is set to HTTPS exactly once', () => {
    const input = 'example.com';
    const normalizedHttps = normalizeUrlInput(input, 'https://');
    assert.equal(normalizedHttps, 'https://example.com');

    // Hostname with path
    const inputWithPath = 'example.com/login/auth';
    const normalizedPath = normalizeUrlInput(inputWithPath, 'https://');
    assert.equal(normalizedPath, 'https://example.com/login/auth');
  });

  it('should handle edge cases like empty string, leading slashes, and protocol variations', () => {
    assert.equal(normalizeUrlInput('', 'https://'), '');
    assert.equal(normalizeUrlInput('   ', 'https://'), '');
    assert.equal(normalizeUrlInput('//example.com', 'https://'), 'https://example.com');
    assert.equal(normalizeUrlInput('/example.com', 'https://'), 'https://example.com');
    assert.equal(normalizeUrlInput('example.com', 'https'), 'https://example.com');
    assert.equal(normalizeUrlInput('example.com', 'http'), 'http://example.com');
  });
});

describe('Protocol Dropdown & Input Synchronization', () => {
  it('should automatically extract and reflect https:// protocol from complete URL', () => {
    assert.equal(extractProtocol('https://example.com'), 'https://');
    assert.equal(extractProtocol('  https://example.com/login  '), 'https://');
    assert.equal(extractProtocol('HTTPS://EXAMPLE.COM'), 'https://');
  });

  it('should automatically extract and reflect http:// protocol from complete URL', () => {
    assert.equal(extractProtocol('http://192.0.2.1/login/verify-account'), 'http://');
    assert.equal(extractProtocol('  http://example.com  '), 'http://');
    assert.equal(extractProtocol('HTTP://192.0.2.1/LOGIN'), 'http://');
  });

  it('should return null when input is only a hostname or path without scheme', () => {
    assert.equal(extractProtocol('example.com'), null);
    assert.equal(extractProtocol('192.0.2.1/login/verify-account'), null);
    assert.equal(extractProtocol(''), null);
    assert.equal(extractProtocol('   '), null);
  });

  it('should update the input prefix when user changes dropdown protocol', () => {
    // If input had https://, changing dropdown to http:// updates input prefix
    assert.equal(syncUrlWithProtocol('https://example.com', 'http://'), 'http://example.com');
    // If input had http://, changing dropdown to https:// updates input prefix
    assert.equal(syncUrlWithProtocol('http://192.0.2.1/login/verify-account', 'https://'), 'https://192.0.2.1/login/verify-account');
    // If input was a bare hostname, it remains unchanged
    assert.equal(syncUrlWithProtocol('example.com', 'http://'), 'example.com');
    assert.equal(syncUrlWithProtocol('192.0.2.1/login/verify-account', 'https://'), '192.0.2.1/login/verify-account');
  });
});

describe('Live Backend URL Scanner Endpoint Integration', () => {
  const BACKEND_URL = 'http://127.0.0.1:8000/api/v1/scans/url';

  async function checkBackendAvailability() {
    try {
      const res = await fetch('http://127.0.0.1:8000/health');
      return res.ok;
    } catch {
      return false;
    }
  }

  it('POST /api/v1/scans/url should accept https://example.com without duplicate protocol', async () => {
    const isUp = await checkBackendAvailability();
    if (!isUp) {
      console.log('Skipping live backend test: backend is offline');
      return;
    }

    const normalizedUrl = normalizeUrlInput('https://example.com', 'https://');
    assert.equal(normalizedUrl, 'https://example.com');

    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: normalizedUrl })
    });

    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.verdict, 'benign');
    assert.equal(data.url, 'https://example.com');
    assert.equal(data.risk_level, 'low');
    assert.ok(typeof data.risk_score === 'number', 'Risk score should be a number');
    assert.ok(Array.isArray(data.evidence), 'Evidence should be an array');
    assert.ok(Array.isArray(data.limitations) && data.limitations.length > 0, 'Limitations should be preserved');
  });

  it('POST /api/v1/scans/url should accept http://192.0.2.1/login/verify-account and return structural risk', async () => {
    const isUp = await checkBackendAvailability();
    if (!isUp) return;

    const normalizedUrl = normalizeUrlInput('http://192.0.2.1/login/verify-account', 'https://');
    assert.equal(normalizedUrl, 'http://192.0.2.1/login/verify-account');

    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: normalizedUrl })
    });

    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.verdict, 'suspicious');
    assert.equal(data.url, 'http://192.0.2.1/login/verify-account');
    assert.ok(typeof data.risk_score === 'number', 'Risk score should be a number');
    assert.ok(data.risk_score >= 0.45, 'Risk score should reflect suspicious flags');
    assert.ok(Array.isArray(data.evidence), 'Evidence should be an array');
    assert.ok(Array.isArray(data.limitations) && data.limitations.length > 0, 'Limitations should be preserved');
    const signals = data.evidence.map(e => e.signal);
    assert.ok(signals.includes('ip_address_host'), 'Expected ip_address_host signal in evidence');
    assert.ok(signals.includes('unencrypted_http'), 'Expected unencrypted_http signal in evidence');
  });

  it('POST /api/v1/scans/url should accept a bare hostname normalized with HTTPS dropdown', async () => {
    const isUp = await checkBackendAvailability();
    if (!isUp) return;

    const normalizedUrl = normalizeUrlInput('example.com', 'https://');
    assert.equal(normalizedUrl, 'https://example.com');

    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: normalizedUrl })
    });

    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.verdict, 'benign');
  });

  it('POST /api/v1/scans/url should return 422 for malformed URLs and not crash', async () => {
    const isUp = await checkBackendAvailability();
    if (!isUp) return;

    // Send an invalid URL structure
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://https://example.com' })
    });

    assert.equal(response.status, 422);
    const data = await response.json();
    assert.equal(data.error, 'Validation Error');
    assert.ok(data.detail.includes('Malformed URL'));
  });
});
