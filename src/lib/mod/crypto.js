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
 * Encrypt a plaintext string with authenticated AES-256-GCM using a password.
 * @param {string} plaintext
 * @param {string} password
 * @returns {{ iv: string, ciphertext: string, salt: string }}
 */
export function encrypt(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  
  return {
    iv: iv.toString('hex'),
    ciphertext: enc.toString('base64'),
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
  } catch (err) {
    if (err?.code === 'WORKER_QUEUE_FULL') throw err;
    return encrypt(plaintext, password);
  }
}

/**
 * Decrypt a ciphertext using AES-256-GCM. Legacy CBC records remain readable
 * for sessions created before the authenticated format was introduced.
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
  const encrypted = Buffer.from(cipherBase64, 'base64');

  if (iv.length === 12) {
    if (encrypted.length <= 16) throw new Error('Invalid authenticated ciphertext');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(encrypted.subarray(-16));
    return Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]).toString('utf8');
  }

  // Backward compatibility for live sessions issued by versions before GCM.
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
  } catch (err) {
    if (err?.code === 'WORKER_QUEUE_FULL') throw err;
    return decrypt(ivHex, cipherBase64, password, saltHex);
  }
}
