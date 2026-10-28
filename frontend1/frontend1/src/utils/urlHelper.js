/**
 * Normalizes user URL input before submission to the ScamX backend.
 *
 * Requirements:
 * 1. If the input contains a complete URL (e.g. starts with http:// or https://),
 *    send it unchanged after trimming whitespace.
 * 2. If the input contains only a hostname/path, combine it with the selected protocol exactly once.
 *
 * @param {string} rawInput - The URL string entered into the input field.
 * @param {string} selectedProtocol - The protocol selected in the dropdown (e.g. 'https://' or 'http://').
 * @returns {string} The normalized URL ready for backend submission.
 */
export function normalizeUrlInput(rawInput, selectedProtocol = 'https://') {
  if (!rawInput || typeof rawInput !== 'string') {
    return '';
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return '';
  }

  // Rule 1: If input contains a complete URL (starts with a valid URI scheme like http:// or https://),
  // return it unchanged after trimming whitespace.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    return trimmed;
  }

  // Handle protocol-relative inputs starting with // (e.g. //example.com)
  if (trimmed.startsWith('//')) {
    const cleanProto = selectedProtocol.replace(/\/+$/, '');
    return `${cleanProto}${trimmed}`;
  }

  // Rule 2: If the input contains only a hostname/path, combine with the selected protocol exactly once.
  const proto = selectedProtocol.endsWith('://')
    ? selectedProtocol
    : selectedProtocol.endsWith(':')
    ? `${selectedProtocol}//`
    : `${selectedProtocol}://`;

  // Avoid duplicate slashes at the start of the hostname/path
  const cleanPath = trimmed.replace(/^\/+/, '');
  return `${proto}${cleanPath}`;
}

/**
 * Extracts protocol from input if it starts with http:// or https:// (case-insensitive).
 * Returns 'http://' or 'https://', or null if no matching protocol is present.
 *
 * @param {string} input - The URL input string.
 * @returns {'http://' | 'https://' | null}
 */
export function extractProtocol(input) {
  if (!input || typeof input !== 'string') {
    return null;
  }
  const trimmed = input.trim();
  if (/^https:\/\//i.test(trimmed)) {
    return 'https://';
  }
  if (/^http:\/\//i.test(trimmed)) {
    return 'http://';
  }
  return null;
}

/**
 * Synchronizes the URL input string when the dropdown protocol changes.
 * If the input already starts with http:// or https://, replaces the protocol prefix.
 * If the input contains only a hostname/path without a scheme, returns it unchanged.
 *
 * @param {string} input - Current URL input string.
 * @param {string} newProtocol - The newly selected protocol ('https://' or 'http://').
 * @returns {string} Synchronized URL input string.
 */
export function syncUrlWithProtocol(input, newProtocol) {
  if (!input || typeof input !== 'string') {
    return input || '';
  }
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed.replace(/^https?:\/\//i, newProtocol);
  }
  return input;
}
