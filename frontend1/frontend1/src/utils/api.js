// Shared API utility for ScamX scanner endpoints
// In production (Vercel), requests use VITE_API_BASE_URL (pointing to Render).
// In local development, leaving VITE_API_BASE_URL empty preserves relative /api paths
// so the Vite development server proxy forwards them to the local backend.

const rawBaseUrl = typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL
  ? import.meta.env.VITE_API_BASE_URL
  : '';

export const API_BASE_URL = rawBaseUrl.trim().replace(/\/+$/, '');

/**
 * Builds the destination URL for an API endpoint.
 * - When VITE_API_BASE_URL is configured, builds an absolute URL (e.g. https://scamx.onrender.com/api/v1/scans/text).
 * - When empty (local dev), preserves the relative path (/api/v1/scans/text) for Vite proxy.
 */
export function getApiUrl(endpoint) {
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return API_BASE_URL ? `${API_BASE_URL}${normalizedEndpoint}` : normalizedEndpoint;
}

/**
 * Perform an API fetch request directly to the target URL.
 * Returns the raw Fetch Response object so callers can verify response.ok and inspect errors.
 * No localhost fallback is attempted in production.
 */
async function requestApi(endpoint, options = {}) {
  const url = getApiUrl(endpoint);
  return fetch(url, options);
}

export async function scanTextMessage(text) {
  return requestApi('/api/v1/scans/text', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
}

export async function scanUrl(url) {
  return requestApi('/api/v1/scans/url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
}

export async function scanImageFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  return requestApi('/api/v1/scans/image', {
    method: 'POST',
    body: formData,
  });
}

export async function checkBackendHealth() {
  try {
    const res = await requestApi('/health', { method: 'GET' });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err.message || 'Cannot reach backend server' };
  }
}
