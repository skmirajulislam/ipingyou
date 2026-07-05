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
