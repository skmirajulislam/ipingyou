/**
 * Full integration test — proves E2E encryption between CLI ↔ Broker
 * Run: node test/test_broker_integration.js
 * Starts and stops an isolated local broker automatically.
 */

import { encrypt, decrypt } from '../src/lib/mod/crypto.js';
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(err => err ? reject(err) : resolve(port));
    });
  });
}

async function startBroker() {
  const port = await reservePort();
  const child = spawn(process.execPath, [path.join(__dirname, '../src/server.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let startupError = '';
  child.stderr.on('data', chunk => { startupError += chunk.toString(); });
  const broker = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const res = await fetch(`${broker}/health`);
      if (res.ok) return { broker, child };
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  child.kill();
  throw new Error(`Broker did not start${startupError ? `: ${startupError.trim()}` : ''}`);
}

const { broker: BROKER, child: brokerProcess } = await startBroker();
const stopBroker = () => {
  if (!brokerProcess.killed) brokerProcess.kill('SIGTERM');
};
process.once('exit', stopBroker);

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
  } catch (err) {
    console.error(`  ❌ ${name}`);
    console.error(`     ${err.message}`);
    process.exit(1);
  }
}

console.log('');
console.log('══════════════════════════════════════════════════════════');
console.log('  Integration Test: E2E Encrypted Broker Communication');
console.log('══════════════════════════════════════════════════════════');
console.log('');

// 1. Health
await test('Health check', async () => {
  const res = await fetch(`${BROKER}/health`);
  const data = await res.json();
  if (data.status !== 'ok') throw new Error(`Expected "ok", got "${data.status}"`);
});

// 2. Host encrypts locally, registers encrypted blob
const tunnelUrl = 'https://secret-tunnel-xyz.trycloudflare.com';
const password = 'test-password';
const encrypted = encrypt(tunnelUrl, password);
const uid = 'test' + Date.now().toString(36).slice(-4);

let hostToken = null;

await test(`Register encrypted payload (UID: ${uid})`, async () => {
  const res = await fetch(`${BROKER}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid, iv: encrypted.iv, ciphertext: encrypted.ciphertext, salt: encrypted.salt }),
  });
  const data = await res.json();
  if (data.status !== 'registered') throw new Error(`Expected "registered", got "${data.status}"`);
  hostToken = data.hostToken;
  if (!hostToken) throw new Error('Register did not return a hostToken');
});

// 3. Broker returns encrypted blob (NOT plaintext)
await test('Resolve returns encrypted blob (no plaintext)', async () => {
  const res = await fetch(`${BROKER}/resolve/${uid}`);
  const data = await res.json();

  // MUST have iv + ciphertext
  if (!data.iv) throw new Error('Response missing iv');
  if (!data.ciphertext) throw new Error('Response missing ciphertext');
  if (!data.salt) throw new Error('Response missing salt');

  // MUST NOT have a plaintext tunnelUrl
  if (data.tunnelUrl) throw new Error('SECURITY FAIL: Broker returned plaintext tunnelUrl!');
});

// 4. Client decrypts locally
await test('Client decrypts locally — correct URL', async () => {
  const res = await fetch(`${BROKER}/resolve/${uid}`);
  const data = await res.json();
  const decryptedUrl = decrypt(data.iv, data.ciphertext, password, data.salt);

  if (decryptedUrl !== tunnelUrl) {
    throw new Error(`Decrypted "${decryptedUrl}" !== original "${tunnelUrl}"`);
  }
});

// 5. Reject plaintext registration (missing iv/ciphertext)
await test('Reject plaintext registration (no iv)', async () => {
  const res = await fetch(`${BROKER}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid: 'plain123', tunnelUrl: 'https://plaintext.com' }),
  });
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
  const data = await res.json();
  if (!data.error.includes('Missing')) throw new Error(`Unexpected error: ${data.error}`);
});

// 6. Reject invalid IV
await test('Reject invalid IV format', async () => {
  const res = await fetch(`${BROKER}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid: 'badiv123', iv: 'ZZZZ', ciphertext: 'abc', salt: encrypted.salt }),
  });
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

// 7. Reject invalid salt
await test('Reject invalid salt format', async () => {
  const res = await fetch(`${BROKER}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid: 'badsalt1', iv: encrypted.iv, ciphertext: encrypted.ciphertext, salt: 'ZZZZ' }),
  });
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

// 8. Reject short UID
await test('Reject short UID', async () => {
  const res = await fetch(`${BROKER}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid: 'ab', iv: encrypted.iv, ciphertext: encrypted.ciphertext, salt: encrypted.salt }),
  });
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

// 9. 404 on missing UID
await test('404 on missing UID', async () => {
  const res = await fetch(`${BROKER}/resolve/nonexist99`);
  if (res.status !== 404) throw new Error(`Expected 404, got ${res.status}`);
});

// 10. Revoke works
await test(`Revoke UID: ${uid}`, async () => {
  const res = await fetch(`${BROKER}/revoke/${uid}`, {
    method: 'DELETE',
    headers: { 'x-host-token': hostToken },
  });
  const data = await res.json();
  if (data.status !== 'revoked') throw new Error(`Expected "revoked", got "${data.status}"`);
});

// 11. 404 after revoke
await test('404 after revoke', async () => {
  const res = await fetch(`${BROKER}/resolve/${uid}`);
  if (res.status !== 404) throw new Error(`Expected 404, got ${res.status}`);
});

console.log('');
console.log('══════════════════════════════════════════════════════════');
console.log('  ✅ ALL 11 TESTS PASSED — E2E encryption verified');
console.log('     Broker is zero-knowledge: never sees plaintext');
console.log('══════════════════════════════════════════════════════════');
console.log('');

stopBroker();
