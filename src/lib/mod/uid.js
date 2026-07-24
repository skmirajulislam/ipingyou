/**
 * ============================================================
 *  Session UID Generator
 * ============================================================
 *  Generates cryptographically random 8-character UIDs.
 *  NOT based on hardware/MAC — purely random per-session,
 *  so the "door" closes permanently when the session ends.
 * ============================================================
 */

import crypto from 'node:crypto';

// Use lowercase alphanumeric only — easy to share verbally
const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Generate a random 8-character session UID.
 * @returns {string}
 */
export function generateUID() {
  let uid = '';
  for (let index = 0; index < 8; index += 1) {
    uid += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return uid;
}

/**
 * Validate a UID string.
 * @param {string} uid
 * @returns {true|string} true if valid, or an error message string
 */
export function validateUID(uid) {
  const trimmed = (uid || '').trim();
  if (trimmed.length < 6 || trimmed.length > 16) return 'UID must be 6-16 characters';
  if (!/^[a-z0-9]+$/.test(trimmed)) return 'UID should be lowercase alphanumeric';
  return true;
}
