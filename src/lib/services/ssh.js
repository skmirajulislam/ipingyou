import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function getCloudflaredPathSync() {
  const localBinDir = path.join(os.homedir(), '.ipingyou', 'bin');
  const localPath = path.join(localBinDir, process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared');
  if (fs.existsSync(localPath)) {
    return localPath;
  }
  return 'cloudflared';
}

const SAFE_HOSTNAME_PATTERN = /^(?=.{1,253}$)(?!.*\.\.)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export function assertSafeHostname(hostname, label = 'hostname') {
  const normalized = String(hostname || '').trim().replace(/\.$/, '').toLowerCase();
  if (!normalized || !SAFE_HOSTNAME_PATTERN.test(normalized)) {
    throw new Error(`Invalid ${label}`);
  }
  return normalized;
}

export function extractHostname(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid tunnel URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('Tunnel URL must use HTTPS');
  }
  return assertSafeHostname(parsed.hostname, 'tunnel hostname');
}

export function quoteRemoteShell(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

export function formatRemoteCd(remotePath) {
  const trimmed = String(remotePath || '').trim();
  if (!trimmed || trimmed === '~') return '';
  return quoteRemoteShell(trimmed);
}

export function formatScpRemotePath(remotePath) {
  const trimmed = String(remotePath || '').trim();
  if (!trimmed || trimmed === '~') return trimmed || '~';
  if (/[\u0000\r\n]/.test(trimmed) || trimmed.length > 4096) {
    throw new Error('Invalid remote path');
  }
  if (trimmed.startsWith('~/')) {
    return `~/${quoteRemoteShell(trimmed.slice(2))}`;
  }
  return quoteRemoteShell(trimmed);
}

export function getSshControlOptions(hostname) {
  const safeHostname = assertSafeHostname(hostname, 'ssh hostname');
  if (process.platform === 'win32') return [];
  const hash = crypto.createHash('sha256').update(safeHostname).digest('hex').slice(0, 10);
  return [
    '-o', 'ControlMaster=auto',
    '-o', 'ControlPersist=5m',
    '-o', `ControlPath=/tmp/ipingyou-${process.pid}-${hash}-%r.sock`,
  ];
}

export function getKeyOnlyAuthOptions() {
  return [
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
  ];
}

export function buildProxyCommandOption(hostname) {
  const safeHostname = assertSafeHostname(hostname, 'tunnel hostname');
  const cfExecutable = getCloudflaredPathSync();
  return ['-o', `ProxyCommand=${cfExecutable} access tcp --hostname ${safeHostname}`];
}

export function getKnownHostsOptions(persistKnownHosts = true) {
  if (persistKnownHosts) {
    return ['-o', 'StrictHostKeyChecking=accept-new'];
  }
  const nullDevice = process.platform === 'win32' ? 'NUL' : '/dev/null';
  return [
    '-o', 'StrictHostKeyChecking=no',
    '-o', `UserKnownHostsFile=${nullDevice}`,
    '-o', 'LogLevel=ERROR',
  ];
}

export function buildSshArgs(hostname, privateKeyPath, extraOptions = [], options = {}) {
  const { persistKnownHosts = true, controlMaster = true, keyOnly = false } = options;
  const sshArgs = [
    ...buildProxyCommandOption(hostname),
    ...getKnownHostsOptions(persistKnownHosts),
    '-o', 'IdentitiesOnly=yes',
    ...(controlMaster ? getSshControlOptions(hostname) : ['-o', 'ControlMaster=no', '-o', 'ControlPath=none']),
    ...(privateKeyPath && keyOnly ? getKeyOnlyAuthOptions() : []),
  ];

  if (privateKeyPath) {
    sshArgs.push('-i', privateKeyPath, '-o', 'IdentityAgent=none');
  }

  sshArgs.push(...extraOptions);

  return sshArgs;
}
