import { parentPort } from 'node:worker_threads';
import crypto from 'node:crypto';
import fs from 'node:fs';

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function encryptPayload(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(plaintext, 'utf8', 'base64');
  enc += cipher.final('base64');

  return {
    iv: iv.toString('hex'),
    ciphertext: enc,
    salt: salt.toString('hex'),
  };
}

function decryptPayload(ivHex, cipherBase64, password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const key = deriveKey(password, salt);
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let dec = decipher.update(cipherBase64, 'base64', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

function checksumFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function executeTask(type, payload) {
  switch (type) {
    case 'encrypt':
      return encryptPayload(payload.plaintext, payload.password);
    case 'decrypt':
      return {
        plaintext: decryptPayload(payload.ivHex, payload.cipherBase64, payload.password, payload.saltHex),
      };
    case 'checksum':
      return {
        digest: await checksumFile(payload.filePath),
      };
    default:
      throw new Error(`Unsupported worker task: ${type}`);
  }
}

parentPort.on('message', async (message) => {
  const { id, type, payload } = message || {};
  try {
    const result = await executeTask(type, payload || {});
    parentPort.postMessage({ id, ok: true, result });
  } catch (err) {
    parentPort.postMessage({ id, ok: false, error: err.message });
  }
});
