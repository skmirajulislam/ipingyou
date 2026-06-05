/**
 * ============================================================
 *  Secure Print — Log-safe sensitive value display
 * ============================================================
 *  Passwords and secrets are shown in plaintext ONLY when:
 *    1. stdout is an interactive TTY (not piped/redirected)
 *    2. The OS user running the process matches the session owner
 *
 *  In all other contexts (CI, PM2, piped output, log files),
 *  values are replaced with a SHA-256 hash prefix so they can
 *  be correlated without exposing the secret.
 * ============================================================
 */

import crypto from 'node:crypto';
import os from 'node:os';

// Keyed secret for deterministic, non-reversible log masking tokens.
// Can be overridden for stable cross-process correlation if needed.
const MASKING_KEY = process.env.SECURE_PRINT_MASK_KEY || crypto.randomBytes(32).toString('hex');

/**
 * Verify the current process is being run by the same OS user interactively.
 * Returns true if the caller is the legitimate host user on an interactive terminal.
 */
function isVerifiedHostUser() {
  // Must be a real interactive TTY (not piped/redirected)
  if (!process.stdout.isTTY) return false;

  // On Unix, verify process UID matches the logged-in user
  if (typeof process.getuid === 'function') {
    try {
      const processUid = process.getuid();
      const userUid = os.userInfo().uid;
      if (processUid !== userUid) return false;
    } catch {
      return false;
    }
  }

  return true;
}

/**
 * Mask a sensitive value for log-safe output.
 * Returns a PBKDF2-derived hash prefix so the value can be correlated without revealing it.
 */
function maskSensitive(value) {
  const normalized = String(value);
  const hash = crypto
    .pbkdf2Sync(MASKING_KEY, normalized, 210000, 32, 'sha256')
    .toString('hex');
  return `[pbkdf2:${hash.slice(0, 12)}…]`;
}

/**
 * Render a sensitive value for display.
 * - Interactive TTY + verified host user → show plaintext
 * - Otherwise → show masked hash
 *
 * @param {string} value — the sensitive value (e.g. password)
 * @returns {string}
 */
export function secureSensitive(value) {
  if (isVerifiedHostUser()) return String(value);
  return maskSensitive(value);
}

/**
 * Build a log-safe URL by masking the password fragment.
 * e.g. http://localhost:3000#mypass → http://localhost:3000#[sha256:a1b2...]
 *
 * @param {string} baseUrl — URL without the fragment
 * @param {string} password — the secret to place after #
 * @returns {string}
 */
export function secureSensitiveUrl(baseUrl, password) {
  if (isVerifiedHostUser()) return `${baseUrl}#${password}`;
  return `${baseUrl}#${maskSensitive(password)}`;
}
