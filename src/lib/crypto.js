/**
 * ============================================================
 *  AES-256-CBC Encryption Utilities
 * ============================================================
 *  Shared crypto module used by both broker and CLI.
 *  All sensitive data is encrypted before transit/storage.
 * ============================================================
 */

import crypto from 'node:crypto';
import { canUseWorkers, runWorkerTask } from './worker-runtime.js';

/**
 * Derive a 256-bit encryption key from a password and salt using PBKDF2.
 * @param {string} password 
 * @param {Buffer} salt 
 * @returns {Buffer}
 */
export function deriveKey(password, salt) {
  // Use 100,000 iterations for strong security
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

/**
 * Encrypt a plaintext string with AES-256-CBC using a password.
 * @param {string} plaintext
 * @param {string} password
 * @returns {{ iv: string, ciphertext: string, salt: string }}
 */
export function encrypt(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(16);
  
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(plaintext, 'utf8', 'base64');
  enc += cipher.final('base64');
  
  return {
    iv: iv.toString('hex'),
    ciphertext: enc,
    salt: salt.toString('hex')
  };
}

export async function encryptAsync(plaintext, password) {
  if (!canUseWorkers()) return encrypt(plaintext, password);
  try {
    const result = await runWorkerTask('encrypt', { plaintext, password });
    return {
      iv: result.iv,
      ciphertext: result.ciphertext,
      salt: result.salt,
    };
  } catch {
    return encrypt(plaintext, password);
  }
}

/**
 * Decrypt a ciphertext with AES-256-CBC using a password and salt.
 * @param {string} ivHex  — 32-char hex IV
 * @param {string} cipherBase64
 * @param {string} password
 * @param {string} saltHex
 * @returns {string}
 */
export function decrypt(ivHex, cipherBase64, password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const key = deriveKey(password, salt);
  const iv = Buffer.from(ivHex, 'hex');
  
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let dec = decipher.update(cipherBase64, 'base64', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

export async function decryptAsync(ivHex, cipherBase64, password, saltHex) {
  if (!canUseWorkers()) return decrypt(ivHex, cipherBase64, password, saltHex);
  try {
    const result = await runWorkerTask('decrypt', { ivHex, cipherBase64, password, saltHex });
    return result.plaintext;
  } catch {
    return decrypt(ivHex, cipherBase64, password, saltHex);
  }
}
