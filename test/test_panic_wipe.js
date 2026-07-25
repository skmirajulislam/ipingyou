import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performPanicWipe } from '../src/lib/mod/panic-wipe.js';

function assert(condition, message) {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

async function runTest() {
  console.log('Testing Panic Mode wipe functionality...');

  const homeDir = os.homedir();
  const tmpDir = os.tmpdir();

  const ipingyouDir = path.join(homeDir, '.ipingyou');
  const binDir = path.join(ipingyouDir, 'bin');
  const logsDir = path.join(ipingyouDir, 'logs');
  const cloudflaredBin = path.join(binDir, process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared');
  const extraBin = path.join(binDir, 'dummy_tool.sh');

  const configPath = path.join(ipingyouDir, 'config.json');
  const logFile = path.join(logsDir, 'session-events.jsonl');

  const testDropbox = path.join(homeDir, 'ipingyou-dropbox-unit-test-123');
  const testTmpLog = path.join(tmpDir, 'ipingyou-test-unit-log.tmp');
  const testTmpTgz = path.join(tmpDir, 'cloudflared.tgz');

  const sshDir = path.join(homeDir, '.ssh');
  const authKeys = path.join(sshDir, 'authorized_keys');

  // Setup mock files
  fs.mkdirSync(binDir, { recursive: true });
  fs.mkdirSync(logsDir, { recursive: true });
  fs.mkdirSync(testDropbox, { recursive: true });
  fs.mkdirSync(sshDir, { recursive: true });

  fs.writeFileSync(cloudflaredBin, 'binary content');
  fs.writeFileSync(extraBin, 'echo hello');
  fs.writeFileSync(configPath, '{"test":true}');
  fs.writeFileSync(logFile, 'log line');

  fs.writeFileSync(path.join(testDropbox, 'dropped.txt'), 'file data');
  fs.writeFileSync(testTmpLog, 'tmp log');
  fs.writeFileSync(testTmpTgz, 'tgz data');

  let existingKeys = '';
  if (fs.existsSync(authKeys)) {
    existingKeys = fs.readFileSync(authKeys, 'utf8');
  }

  const testKey1 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI111 user@test';
  const ipingyouKey = 'no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI222 ipingyou-ephemeral';
  const testKey2 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI333 user2@test';

  const mockAuthKeysContent = [testKey1, ipingyouKey, testKey2].join('\n');
  fs.writeFileSync(authKeys, mockAuthKeysContent, { mode: 0o600 });

  try {
    // Execute panic wipe
    await performPanicWipe();

    // Verify preservation of cloudflared
    assert(fs.existsSync(cloudflaredBin), 'cloudflared binary must be PRESERVED in ~/.ipingyou/bin/');

    // Verify deletion of non-preserved binary & ipingyou files
    assert(!fs.existsSync(extraBin), 'Non-cloudflared/ssh binaries in ~/.ipingyou/bin must be deleted');
    assert(!fs.existsSync(configPath), 'config.json in ~/.ipingyou must be deleted');
    assert(!fs.existsSync(logFile), 'logs in ~/.ipingyou must be deleted');
    assert(!fs.existsSync(testDropbox), 'ipingyou-dropbox-* in home directory must be deleted');
    assert(!fs.existsSync(testTmpLog), 'ipingyou* files in os.tmpdir() must be deleted');
    assert(!fs.existsSync(testTmpTgz), 'cloudflared.tgz in os.tmpdir() must be deleted');

    // Verify authorized_keys cleanup
    const updatedAuthKeys = fs.readFileSync(authKeys, 'utf8');
    assert(!updatedAuthKeys.includes('ipingyou-ephemeral'), 'ipingyou key must be removed from authorized_keys');
    assert(updatedAuthKeys.includes('user@test'), 'Original non-ipingyou SSH key user@test must be preserved');
    assert(updatedAuthKeys.includes('user2@test'), 'Original non-ipingyou SSH key user2@test must be preserved');

    console.log('✅ Panic Mode wipe tests passed successfully.');
  } finally {
    // Clean up test cloudflared mock binary if still present
    try { fs.rmSync(ipingyouDir, { recursive: true, force: true }); } catch {}
    // Restore original authorized_keys
    if (existingKeys) {
      fs.writeFileSync(authKeys, existingKeys, { mode: 0o600 });
    }
  }
}

runTest().catch(err => {
  console.error('❌ Panic Mode test failed:', err);
  process.exit(1);
});
