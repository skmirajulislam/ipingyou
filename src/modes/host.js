/**
 * ============================================================
 *  Host Mode — "Allow Remote Access"
 * ============================================================
 *  1. Generate a session UID
 *  2. Ensure local SSH service is running
 *  3. Spawn cloudflared tunnel → localhost:22
 *  4. ENCRYPT tunnel URL locally, send ciphertext to Broker
 *  5. Monitor connections & provide termination controls
 *
 *  Security: The broker NEVER sees the plaintext tunnel URL.
 *  Only someone with the shared SECRET_KEY can decrypt.
 * ============================================================
 */

import { execa } from 'execa';
import chalk from 'chalk';
import inquirer from 'inquirer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import net from 'node:net';
import { generateUID } from '../lib/mod/uid.js';
import { openUrl } from '../lib/mod/open-url.js';
import { decryptAsync, encryptAsync } from '../lib/mod/crypto.js';
import { cleanupAll, killProcessTree, trackPID, untrackPID, setRevokeOnExit, addCleanupHook } from '../lib/mod/cleanup.js';
import { detectOS, isLinuxSSHActive, startLinuxSSH } from '../lib/services/platform.js';
import { createSpinner, networkSpinner, typeText } from '../lib/mod/animations.js';
import { startChatServer, openLocalChatUI } from '../lib/services/chat.js';
import { secureSensitive } from '../lib/mod/secure-print.js';
import { spawnTunnelSupervised } from '../lib/services/tunnel.js';
import { decideApprovalRequest, fetchApprovalRequests, pingBroker, registerWithBroker, revokeUID, kickClient, extendSession } from '../lib/client/broker.js';
import { cleanupSessionLog, getSessionLogPath, initSessionLog, logSessionEvent, recordEvent } from '../lib/mod/session-log.js';
import { notifyDesktop } from '../lib/mod/notifier.js';
import { generateTerminalQR } from '../lib/mod/qrcode.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

function escapeDashboardHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

async function waitForValue(getValue, timeoutMs, label) {
  const startedAt = Date.now();
  while (!getValue()) {
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`${label} timed out after ${Math.round(timeoutMs / 1000)}s`);
    }
    await new Promise(r => setTimeout(r, 100));
  }
  return getValue();
}

function formatTelemetryTime(value) {
  if (!value) return 'unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function getTelemetryClientKey(item) {
  return [
    item.username || 'unknown',
    item.hostname || '',
    item.ip || 'unknown',
    item.os || 'unknown',
  ].join('|');
}

function summarizeTelemetryClient(group) {
  const latest = group.events[group.events.length - 1] || {};
  const actions = [...new Set(group.events.map(event => event.action || 'connected'))];
  return {
    username: latest.username || group.username || 'unknown',
    hostname: latest.hostname || 'unknown',
    ip: latest.ip || 'unknown',
    localIp: latest.localIp || 'unknown',
    os: latest.os || 'unknown',
    cpu: latest.cpu || 'unknown',
    ram: latest.ram || 'unknown',
    latestAction: latest.action || 'connected',
    latestTime: latest.time || latest.seenAt || null,
    actionCount: group.events.length,
    uniqueActions: actions,
  };
}

async function decryptTelemetryRecords(clientBlobs, password) {
  const records = [];
  const failures = [];

  for (const [index, clientBlob] of clientBlobs.entries()) {
    try {
      const decrypted = await decryptAsync(clientBlob.iv, clientBlob.ciphertext, password, clientBlob.salt);
      const parsed = JSON.parse(decrypted);
      records.push({
        ...parsed,
        brokerSeenAt: clientBlob.seenAt || null,
        telemetryIndex: index + 1,
      });
    } catch (err) {
      failures.push({ index: index + 1, error: err.message });
      logSessionEvent('host_telemetry_decrypt_failed', { index: index + 1 }, 'warn');
    }
  }

  return { records, failures };
}

function groupTelemetryByClient(records) {
  const grouped = new Map();

  for (const record of records) {
    const key = getTelemetryClientKey(record);
    if (!grouped.has(key)) {
      grouped.set(key, {
        key,
        username: record.username || 'unknown',
        events: [],
      });
    }
    grouped.get(key).events.push(record);
  }

  return [...grouped.values()]
    .map(group => ({
      ...group,
      events: group.events.sort((a, b) => {
        const aTime = Date.parse(a.time || a.brokerSeenAt || 0) || 0;
        const bTime = Date.parse(b.time || b.brokerSeenAt || 0) || 0;
        return aTime - bTime;
      }),
    }))
    .sort((a, b) => {
      const aLatest = a.events[a.events.length - 1] || {};
      const bLatest = b.events[b.events.length - 1] || {};
      const aTime = Date.parse(aLatest.time || aLatest.brokerSeenAt || 0) || 0;
      const bTime = Date.parse(bLatest.time || bLatest.brokerSeenAt || 0) || 0;
      return bTime - aTime;
    });
}

function printTelemetryClientDetails(group) {
  const summary = summarizeTelemetryClient(group);

  console.log('');
  console.log(chalk.bold.cyan(`  Client: ${summary.username}`));
  console.log(chalk.dim('  ─────────────────────────────────────'));
  console.log(`  IP:       ${chalk.white(summary.ip)}`);
  console.log(`  Local IP: ${chalk.dim(summary.localIp)}`);
  console.log(`  Hostname: ${chalk.dim(summary.hostname)}`);
  console.log(`  OS:       ${chalk.dim(summary.os)}`);
  console.log(`  CPU:      ${chalk.dim(summary.cpu)}`);
  console.log(`  RAM:      ${chalk.dim(summary.ram)}`);
  console.log(`  Actions:  ${chalk.yellow(summary.uniqueActions.join(', '))}`);
  console.log(`  Latest:   ${chalk.yellow(summary.latestAction)} ${chalk.dim(`at ${formatTelemetryTime(summary.latestTime)}`)}`);
  console.log('');
  console.log(chalk.bold('  Action timeline'));

  for (const [index, event] of group.events.entries()) {
    console.log(`    ${String(index + 1).padStart(2, ' ')}. ${chalk.yellow(event.action || 'connected')} ${chalk.dim(formatTelemetryTime(event.time || event.brokerSeenAt))}`);
    console.log(`        User: ${event.username || 'unknown'} | Hostname: ${event.hostname || 'unknown'}`);
    console.log(`        IP:   ${event.ip || 'unknown'} | Local: ${event.localIp || 'unknown'}`);
    console.log(`        OS:   ${event.os || 'unknown'}`);
    if (event.cpu || event.ram) {
      console.log(`        HW:   ${event.cpu || 'unknown'} | ${event.ram || 'unknown'}`);
    }
  }
}

async function showDetailedClientTelemetry(uid, password, hostToken) {
  const spinner = createSpinner('Fetching secure client telemetry...', networkSpinner).start();
  try {
    const res = await fetch(`${BROKER_URL}/clients/${uid}`, {
      headers: hostToken ? { 'x-host-token': hostToken } : {}
    });
    if (!res.ok) throw new Error('Failed to fetch from broker');
    const data = await res.json();

    if (!data.clients || data.clients.length === 0) {
      spinner.warn('No clients have successfully connected and sent telemetry yet.');
      return;
    }

    const { records, failures } = await decryptTelemetryRecords(data.clients, password);
    if (records.length === 0) {
      spinner.warn('Telemetry exists, but none could be decrypted with this session password.');
      return;
    }

    const clientGroups = groupTelemetryByClient(records);
    spinner.succeed(`Found ${clientGroups.length} client(s), ${records.length} action event(s).`);

    if (failures.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${failures.length} telemetry payload(s) could not be decrypted.`));
    }

    let keepInspecting = true;
    while (keepInspecting) {
      const { selectedClientKey } = await inquirer.prompt([{
        type: 'list',
        name: 'selectedClientKey',
        message: 'Select a client to view associated actions:',
        pageSize: 12,
        choices: [
          ...clientGroups.map(group => {
            const summary = summarizeTelemetryClient(group);
            return {
              name: `${summary.username}@${summary.hostname} | ${summary.ip} | ${summary.latestAction} | ${summary.actionCount} event(s) | ${formatTelemetryTime(summary.latestTime)}`,
              value: group.key,
            };
          }),
          new inquirer.Separator(),
          { name: '↩ Back to host controls', value: '__back' },
        ],
      }]);

      if (selectedClientKey === '__back') break;
      const selected = clientGroups.find(group => group.key === selectedClientKey);
      if (selected) printTelemetryClientDetails(selected);

      const { inspectAnother } = await inquirer.prompt([{
        type: 'confirm',
        name: 'inspectAnother',
        message: 'View another client?',
        default: false,
      }]);
      keepInspecting = inspectAnother;
    }
  } catch (err) {
    spinner.fail(`Could not load telemetry: ${err.message}`);
    logSessionEvent('host_telemetry_fetch_failed', { error: err.message }, 'warn');
  }
}

/**
 * Ensure the local SSH server is running.
 */
async function ensureSSHRunning() {
  const spinner = createSpinner('Checking SSH service...', networkSpinner).start();
  const osInfo = detectOS();

  try {
    if (osInfo.isLinux) {
      const active = await isLinuxSSHActive();
      if (active) {
        spinner.succeed('SSH service is active');
      } else {
        spinner.text = 'Starting SSH service...';
        await startLinuxSSH();
        spinner.succeed('SSH service started');
      }
    } else if (osInfo.isMac) {
      try {
        const { stdout } = await execa('sudo', ['systemsetup', '-getremotelogin'], { reject: false });
        if (stdout.toLowerCase().includes('off')) {
          spinner.text = 'Enabling Remote Login...';
          await execa('sudo', ['systemsetup', '-setremotelogin', 'on'], { stdio: 'inherit' });
          spinner.succeed('Remote Login enabled');
        } else {
          spinner.succeed('SSH (Remote Login) is active');
        }
      } catch {
        spinner.warn('Could not verify SSH status — ensure Remote Login is enabled in System Preferences');
      }
    } else if (osInfo.isWindows) {
      try {
        const { stdout } = await execa('sc', ['query', 'sshd'], { reject: false });
        if (stdout.includes('STOPPED')) {
          spinner.text = 'Starting OpenSSH Server...';
          await execa('net', ['start', 'sshd'], { stdio: 'inherit' });
          spinner.succeed('OpenSSH Server started');
        } else if (stdout.includes('RUNNING')) {
          spinner.succeed('OpenSSH Server is running');
        } else {
          spinner.warn('OpenSSH Server status unknown — ensure it is installed');
        }
      } catch {
        spinner.warn('Could not check SSH service — ensure OpenSSH Server is installed');
      }
    }
  } catch (err) {
    spinner.fail(`Service check failed: ${err.message}`);
    console.log(chalk.dim('  Continue anyway? The tunnel will still start, but connections may fail.'));
  }
}

function formatAndPrintLogLine(line) {
  try {
    const data = JSON.parse(line);
    const time = new Date(data.time || data.timestamp).toLocaleTimeString();
    const typeLabel = chalk.bold(data.type);
    
    let color = chalk.white;
    let icon = 'ℹ️';
    if (data.level === 'warn') {
      color = chalk.yellow;
      icon = '⚠️';
    } else if (data.level === 'error') {
      color = chalk.red;
      icon = '❌';
    } else if (data.type.includes('success') || data.type.includes('complete') || data.type.includes('granted') || data.type.includes('start')) {
      color = chalk.green;
      icon = '✓';
    }

    const detailsStr = Object.keys(data.details || {}).length > 0 
      ? chalk.dim(JSON.stringify(data.details))
      : '';
      
    console.log(`  [${chalk.dim(time)}] ${color(icon)} ${color(typeLabel)} ${detailsStr}`);
  } catch {
    if (line.trim()) {
      console.log(`  ${chalk.dim(line)}`);
    }
  }
}

async function viewLiveClientLogs(sharedDropPath) {
  if (!sharedDropPath) {
    console.log(chalk.red('  ❌ Error: Shared drop path is not configured.'));
    return;
  }

  try {
    const files = await fs.promises.readdir(sharedDropPath);
    const clientLogs = files.filter(f => f.startsWith('client-') && f.endsWith('.log'));
    
    if (clientLogs.length === 0) {
      console.log(chalk.yellow('\n  No active client logs found in the shared drop folder.'));
      console.log(chalk.dim('     Clients automatically share their logs once connected.'));
      return;
    }

    const { selectedLog } = await inquirer.prompt([
      {
        type: 'list',
        name: 'selectedLog',
        message: 'Select a client to monitor activity in live:',
        choices: clientLogs.map(f => {
          const clientName = f.replace('client-', '').replace('.log', '');
          return { name: `👤 ${clientName}`, value: f };
        })
      }
    ]);

    const logFilePath = path.join(sharedDropPath, selectedLog);
    const clientName = selectedLog.replace('client-', '').replace('.log', '');
    
    console.log('');
    console.log(chalk.bold.cyan(`  📊 Live Monitor: ${clientName}`));
    console.log(chalk.dim('  ──────────────────────────────────────────────────'));
    console.log(chalk.dim('  Showing log stream. Press Enter to exit.'));
    console.log('');

    let filePosition = 0;
    let keepWatching = true;

    if (fs.existsSync(logFilePath)) {
      const stats = fs.statSync(logFilePath);
      filePosition = stats.size;
      const content = fs.readFileSync(logFilePath, 'utf8');
      const lines = content.split('\n').filter(Boolean);
      const lastLines = lines.slice(-10);
      for (const line of lastLines) {
        formatAndPrintLogLine(line);
      }
    }

    const intervalId = setInterval(() => {
      if (!keepWatching) return;
      try {
        if (!fs.existsSync(logFilePath)) return;
        const stats = fs.statSync(logFilePath);
        if (stats.size > filePosition) {
          const fd = fs.openSync(logFilePath, 'r');
          const bufferSize = stats.size - filePosition;
          const buffer = Buffer.allocUnsafe(bufferSize);
          fs.readSync(fd, buffer, 0, bufferSize, filePosition);
          fs.closeSync(fd);

          filePosition = stats.size;
          const newContent = buffer.toString('utf8');
          const lines = newContent.split('\n').filter(Boolean);
          for (const line of lines) {
            formatAndPrintLogLine(line);
          }
        }
      } catch {
        // Ignore file access errors
      }
    }, 1000);

    await inquirer.prompt([{
      type: 'input',
      name: 'exit',
      message: 'Press Enter to stop monitoring...'
    }]);

    keepWatching = false;
    clearInterval(intervalId);
    console.log(chalk.cyan('  Stopped monitoring client logs.'));
  } catch (err) {
    console.log(chalk.red(`  Could not read client logs: ${err.message}`));
  }
}

async function viewHostLiveLogs() {
  const logFilePath = getSessionLogPath();
  if (!logFilePath || !fs.existsSync(logFilePath)) {
    console.log(chalk.red("  ❌ Error: Host session log is not active or doesn't exist yet."));
    return;
  }

  console.log('');
  console.log(chalk.bold.cyan(`  📊 Live Monitor: Host Session Activity`));
  console.log(chalk.dim('  ──────────────────────────────────────────────────'));
  console.log(chalk.dim('  Showing log stream. Press Enter to exit.'));
  console.log('');

  let filePosition = 0;
  let keepWatching = true;

  try {
    const stats = fs.statSync(logFilePath);
    filePosition = stats.size;
    const content = fs.readFileSync(logFilePath, 'utf8');
    const lines = content.split('\n').filter(Boolean);
    const lastLines = lines.slice(-10);
    for (const line of lastLines) {
      formatAndPrintLogLine(line);
    }

    const intervalId = setInterval(() => {
      if (!keepWatching) return;
      try {
        if (!fs.existsSync(logFilePath)) return;
        const stats = fs.statSync(logFilePath);
        if (stats.size > filePosition) {
          const fd = fs.openSync(logFilePath, 'r');
          const bufferSize = stats.size - filePosition;
          const buffer = Buffer.allocUnsafe(bufferSize);
          fs.readSync(fd, buffer, 0, bufferSize, filePosition);
          fs.closeSync(fd);

          filePosition = stats.size;
          const newContent = buffer.toString('utf8');
          const lines = newContent.split('\n').filter(Boolean);
          for (const line of lines) {
            formatAndPrintLogLine(line);
          }
        }
      } catch {
        // Ignore file access errors
      }
    }, 1000);

    await inquirer.prompt([{
      type: 'input',
      name: 'exit',
      message: 'Press Enter to stop monitoring...'
    }]);

    keepWatching = false;
    clearInterval(intervalId);
    console.log(chalk.cyan('  Stopped monitoring host logs.'));
  } catch (err) {
    console.log(chalk.red(`  Could not read host logs: ${err.message}`));
  }
}


// ─── Ephemeral SSH Key Management ────────────────────────────
async function generateEphemeralKey() {
  const tmpDir = os.tmpdir() || process.env.TMPDIR || process.env.TEMP || process.env.TMP;
  if (!tmpDir) {
    throw new Error('Could not resolve a temporary directory for SSH key generation');
  }
  const keyPath = path.join(tmpDir, `ipingyou_${Date.now()}`);

  await execa('ssh-keygen', ['-t', 'ed25519', '-C', 'ipingyou-ephemeral', '-f', keyPath, '-N', '']);

  const privKey = await fs.promises.readFile(keyPath, 'utf8');
  const pubKey = (await fs.promises.readFile(`${keyPath}.pub`, 'utf8')).trim();

  return { keyPath, privKey, pubKey };
}

function getCurrentSshUsername() {
  return os.userInfo().username || process.env.USER || process.env.USERNAME || '';
}

function getSshdBinaryCandidates() {
  return process.platform === 'win32'
    ? []
    : ['/usr/sbin/sshd', '/usr/local/sbin/sshd', '/opt/homebrew/sbin/sshd', 'sshd'];
}

async function findSshdBinary({ absoluteOnly = false } = {}) {
  for (const binary of getSshdBinaryCandidates()) {
    if (absoluteOnly && !path.isAbsolute(binary)) continue;
    const result = await execa(binary, ['-V'], {
      reject: false,
      stdio: ['ignore', 'ignore', 'pipe'],
      timeout: 3000,
    }).catch(() => null);
    // OpenSSH prints its version to stderr and exits 0 or 1 depending on build.
    if (result && result.exitCode !== 127) return binary;
  }
  return null;
}

function expandAuthorizedKeysPath(pattern, username, homedir) {
  const expanded = String(pattern || '')
    .replace(/%%/g, '\0PERCENT\0')
    .replace(/%h/g, homedir)
    .replace(/%u/g, username)
    .replace(/\0PERCENT\0/g, '%');
  return path.isAbsolute(expanded) ? expanded : path.join(homedir, expanded);
}

async function getSshdAuthorizedKeysPaths(username, homedir) {
  const defaults = ['.ssh/authorized_keys'];
  if (process.platform === 'win32') return defaults.map(item => path.join(homedir, item));

  const result = await getSshdEffectiveConfig(username);
  if (!result?.stdout) return defaults.map(item => path.join(homedir, item));

  const line = result.stdout.split('\n').find(value => value.toLowerCase().startsWith('authorizedkeysfile '));
  if (!line) return defaults.map(item => path.join(homedir, item));

  const patterns = line.trim().split(/\s+/).slice(1).filter(Boolean);
  if (patterns.length === 0) return defaults.map(item => path.join(homedir, item));

  return [...new Set(patterns.map(pattern => expandAuthorizedKeysPath(pattern, username, homedir)))];
}

async function getSshdEffectiveConfig(username) {
  for (const binary of getSshdBinaryCandidates()) {
    const result = await execa(binary, ['-T', '-C', `user=${username},host=localhost,addr=127.0.0.1`], {
      reject: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).catch(() => null);

    if (result?.exitCode !== 0 || !result?.stdout) continue;

    return result;
  }

  return null;
}

async function getAvailableLocalPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : null;
      server.close(() => {
        if (port) resolve(port);
        else reject(new Error('Could not allocate a local SSH port'));
      });
    });
  });
}

async function verifyHostAcceptsEphemeralKey(username, keyPath, port = 22) {
  const nullDevice = process.platform === 'win32' ? 'NUL' : '/dev/null';
  const target = process.platform === 'win32' ? '127.0.0.1' : 'localhost';
  const result = await execa('ssh', [
    '-i', keyPath,
    '-p', String(port),
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'IdentityAgent=none',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'StrictHostKeyChecking=no',
    '-o', `UserKnownHostsFile=${nullDevice}`,
    '-o', 'ConnectTimeout=8',
    `${username}@${target}`,
    'true',
  ], {
    reject: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 12000,
  });

  if (result.exitCode !== 0) {
    const reason = (result.stderr || result.stdout || `ssh exited with ${result.exitCode}`).trim();
    throw new Error(reason.split('\n').slice(-3).join(' ').slice(0, 700));
  }
}

function showPasswordlessHostHint() {
  console.log(chalk.dim('     Passwordless SSH was not advertised because local sshd rejected the injected key.'));
  console.log(chalk.dim('     Common host-side causes: Remote Login disabled, PubkeyAuthentication disabled,'));
  console.log(chalk.dim('     StrictModes rejecting ~/.ssh permissions, or this macOS user is not allowed for Remote Login.'));
}

async function showPasswordlessDiagnostics(username, homedir) {
  if (process.platform === 'win32') return;

  const result = await getSshdEffectiveConfig(username);
  if (result?.exitCode !== 0 || !result?.stdout) return;

  const config = new Map(result.stdout.split('\n').map(line => {
    const [key, ...rest] = line.trim().split(/\s+/);
    return [key, rest.join(' ')];
  }));
  const interesting = ['pubkeyauthentication', 'authorizedkeysfile', 'authorizedkeyscommand', 'strictmodes', 'passwordauthentication', 'kbdinteractiveauthentication'];

  console.log(chalk.dim('     sshd effective settings:'));
  for (const key of interesting) {
    if (config.has(key)) console.log(chalk.dim(`       ${key} ${config.get(key)}`));
  }
  if (config.get('pubkeyauthentication') === 'no') {
    console.log(chalk.yellow('     Enable PubkeyAuthentication in sshd_config, then restart SSH.'));
  }
  if (config.get('authorizedkeyscommand') && config.get('authorizedkeyscommand') !== 'none') {
    console.log(chalk.yellow('     This host uses AuthorizedKeysCommand; file-based key injection may be ignored.'));
  }
  const authPaths = await getSshdAuthorizedKeysPaths(username, homedir);
  console.log(chalk.dim(`     Checked key file(s): ${authPaths.join(', ')}`));
}

async function injectPublicKey(pubKey, username = getCurrentSshUsername()) {
  const homedir = os.homedir();
  if (!homedir) {
    throw new Error('Could not resolve the current user home directory for authorized_keys');
  }

  if (process.platform !== 'win32') {
    try {
      await fs.promises.chmod(homedir, 0o755);
    } catch {}
  }

  const authorizedKey = `no-agent-forwarding,no-X11-forwarding ${pubKey}`;
  const authKeysPaths = await getSshdAuthorizedKeysPaths(username, homedir);
  const injectedFiles = [];
  const skippedFiles = [];

  for (const authKeysPath of authKeysPaths) {
    try {
      const sshDir = path.dirname(authKeysPath);
      if (!path.resolve(authKeysPath).startsWith(path.resolve(homedir) + path.sep)) {
        skippedFiles.push(`${authKeysPath} (outside home)`);
        continue;
      }

      if (!fs.existsSync(sshDir)) {
        await fs.promises.mkdir(sshDir, { mode: 0o700, recursive: true });
      }
      try { await fs.promises.chmod(sshDir, 0o700); } catch {}

      const existing = await fs.promises.lstat(authKeysPath).catch(() => null);
      if (existing?.isSymbolicLink()) {
        skippedFiles.push(`${authKeysPath} (symlink)`);
        continue;
      }

      const current = await fs.promises.readFile(authKeysPath, 'utf8').catch(() => '');
      if (!current.includes(authorizedKey)) {
        await fs.promises.appendFile(authKeysPath, `${current.endsWith('\n') || current.length === 0 ? '' : '\n'}${authorizedKey}\n`, { mode: 0o600 });
      }
      try { await fs.promises.chmod(authKeysPath, 0o600); } catch {}
      injectedFiles.push(authKeysPath);
    } catch (err) {
      skippedFiles.push(`${authKeysPath} (${err.message})`);
    }
  }

  if (injectedFiles.length === 0) {
    throw new Error(`Could not write any sshd AuthorizedKeysFile path${skippedFiles.length ? `: ${skippedFiles.join('; ')}` : ''}`);
  }

  // Windows Administrators authorized keys handling
  let adminAuthKeysPath = null;
  if (process.platform === 'win32') {
    const programData = process.env.PROGRAMDATA || 'C:\\ProgramData';
    const adminKeysPath = path.join(programData, 'ssh', 'administrators_authorized_keys');
    try {
      if (fs.existsSync(path.dirname(adminKeysPath))) {
        await fs.promises.appendFile(adminKeysPath, `\n${authorizedKey}\n`, { mode: 0o600 });
        try {
          await execa('icacls', [adminKeysPath, '/inheritance:r', '/grant', '*S-1-5-32-544:F', '/grant', '*S-1-5-18:F']);
        } catch {}
        adminAuthKeysPath = adminKeysPath;
      }
    } catch {}
  }

  return { authKeysPath: injectedFiles[0], authKeysPaths: injectedFiles, adminAuthKeysPath, authorizedKey, skippedFiles };
}

async function removePublicKey(authKeysPath, authorizedKey, adminAuthKeysPath = null, authKeysPaths = null) {
  for (const keyPath of new Set((authKeysPaths || [authKeysPath]).filter(Boolean))) {
    if (fs.existsSync(keyPath)) {
      const stat = await fs.promises.lstat(keyPath);
      if (!stat.isSymbolicLink()) {
        let keys = await fs.promises.readFile(keyPath, 'utf8');
        keys = keys.replace(`${authorizedKey}\n`, '').replace(`\n${authorizedKey}`, '');
        await fs.promises.writeFile(keyPath, keys);
        try {
          await fs.promises.chmod(keyPath, 0o600);
        } catch {}
      }
    }
  }
  if (adminAuthKeysPath && fs.existsSync(adminAuthKeysPath)) {
    try {
      let keys = await fs.promises.readFile(adminAuthKeysPath, 'utf8');
      keys = keys.replace(`\n${authorizedKey}\n`, '');
      await fs.promises.writeFile(adminAuthKeysPath, keys);
    } catch {}
  }
}

async function startManagedSshd(username, clientPubKey, clientKeyPath) {
  if (process.platform === 'win32') {
    throw new Error('Managed fallback sshd is not available on Windows');
  }

  const sshdBinary = await findSshdBinary({ absoluteOnly: true });
  if (!sshdBinary) {
    throw new Error('Could not find an absolute sshd binary for managed SSH fallback');
  }

  const baseDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'ipingyou-sshd-'));
  const hostKeyPath = path.join(baseDir, 'ssh_host_ed25519_key');
  const authKeysPath = path.join(baseDir, 'authorized_keys');
  const configPath = path.join(baseDir, 'sshd_config');
  const pidPath = path.join(baseDir, 'sshd.pid');
  const logPath = path.join(baseDir, 'sshd.log');
  const port = await getAvailableLocalPort();
  const authorizedKey = `no-agent-forwarding,no-X11-forwarding ${clientPubKey}`;

  await execa('ssh-keygen', ['-t', 'ed25519', '-f', hostKeyPath, '-N', '', '-C', 'ipingyou-managed-sshd'], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  await fs.promises.writeFile(authKeysPath, `${authorizedKey}\n`, { mode: 0o600 });
  await fs.promises.chmod(baseDir, 0o700).catch(() => {});
  await fs.promises.chmod(authKeysPath, 0o600).catch(() => {});

  const config = [
    `Port ${port}`,
    'ListenAddress 127.0.0.1',
    `HostKey ${hostKeyPath}`,
    `PidFile ${pidPath}`,
    `AuthorizedKeysFile ${authKeysPath}`,
    `AllowUsers ${username}`,
    'PermitRootLogin yes',
    'PubkeyAuthentication yes',
    'PasswordAuthentication no',
    'KbdInteractiveAuthentication no',
    'ChallengeResponseAuthentication no',
    'UsePAM no',
    'StrictModes no',
    'PermitTTY yes',
    'AllowTcpForwarding yes',
    'X11Forwarding no',
    'PermitUserEnvironment no',
    'PrintMotd no',
    'LogLevel VERBOSE',
    'Subsystem sftp internal-sftp',
    '',
  ].join('\n');
  await fs.promises.writeFile(configPath, config, { mode: 0o600 });

  const child = execa(sshdBinary, ['-D', '-e', '-f', configPath], {
    reject: false,
    all: true,
    buffer: false,
  });
  trackPID(child.pid);

  const maxLogBytes = 64 * 1024;
  let output = Buffer.alloc(0);
  const appendOutput = async (chunk) => {
    const text = Buffer.from(chunk);
    const next = Buffer.concat([output, text]);
    output = next.length > maxLogBytes ? next.subarray(next.length - maxLogBytes) : next;
    await fs.promises.appendFile(logPath, text).catch(() => {});
  };
  child.all?.on('data', chunk => {
    appendOutput(chunk);
  });
  child.on('exit', () => untrackPID(child.pid));

  // Wait for sshd to be ready to accept connections
  await new Promise((resolve, reject) => {
    let attempts = 0;
    const maxAttempts = 30; // 3 seconds total
    const tryConnect = () => {
      const sock = net.connect({ port, host: '127.0.0.1' }, () => {
        sock.destroy();
        resolve();
      });
      sock.on('error', () => {
        attempts += 1;
        if (attempts >= maxAttempts) {
          reject(new Error(`Managed sshd did not start listening on port ${port} within 3s`));
        } else {
          setTimeout(tryConnect, 100);
        }
      });
      sock.setTimeout(500, () => {
        sock.destroy();
        attempts += 1;
        if (attempts >= maxAttempts) {
          reject(new Error(`Managed sshd did not start listening on port ${port} within 3s`));
        } else {
          setTimeout(tryConnect, 100);
        }
      });
    };
    tryConnect();
  });

  try {
    await verifyHostAcceptsEphemeralKey(username, clientKeyPath, port);
  } catch (err) {
    const detail = output.toString('utf8').trim();
    killProcessTree(child.pid).catch(() => {});
    await fs.promises.rm(baseDir, { recursive: true, force: true }).catch(() => {});
    throw new Error(`Managed sshd rejected the key: ${err.message}${detail ? ` | sshd: ${detail.split('\n').slice(-4).join(' ')}` : ''}`);
  }

  return {
    port,
    logPath,
    cleanup: async () => {
      try { await killProcessTree(child.pid); } catch {}
      await fs.promises.rm(baseDir, { recursive: true, force: true }).catch(() => {});
    },
  };
}

async function prepareSharedDropFolder(uid) {
  const dropPath = path.join(os.homedir(), `ipingyou-dropbox-${uid}`);
  await fs.promises.mkdir(dropPath, { recursive: true, mode: 0o700 });
  try { await fs.promises.chmod(dropPath, 0o700); } catch { }
  return dropPath;
}

async function cleanupSharedDropFolder(dropPath, uid) {
  if (!dropPath) return;
  const expectedPath = path.join(os.homedir(), `ipingyou-dropbox-${uid}`);
  if (path.resolve(dropPath) !== path.resolve(expectedPath)) {
    console.log(chalk.yellow('     Skipping drop folder cleanup (unexpected path).'));
    return;
  }
  try {
    const stat = await fs.promises.lstat(dropPath).catch(() => null);
    if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) return;
    console.log(chalk.dim('     Removing shared drop folder...'));
    await fs.promises.rm(dropPath, { recursive: true, force: true });
  } catch (err) {
    console.log(chalk.yellow(`     Could not remove drop folder: ${err.message}`));
  }
}

function showMacPrivacyPreflight(sharedDropPath) {
  if (process.platform !== 'darwin') return;

  console.log('');
  console.log(chalk.bold.cyan('  🔎 macOS SSH File Access Preflight'));
  console.log(chalk.dim('  ──────────────────────────────────────'));
  console.log(chalk.dim('  macOS may block SSH sessions from browsing Downloads, Desktop, or Documents.'));
  console.log(chalk.dim('  For reliable SCP transfers, use the session drop folder:'));
  console.log(chalk.green(`  ${sharedDropPath}`));
  console.log(chalk.dim('  To browse protected folders over SSH, grant Full Disk Access to sshd/Remote Login.'));
  console.log('');
}

async function promptOneTimeSharePath() {
  const { sharePath } = await inquirer.prompt([{
    type: 'input',
    name: 'sharePath',
    message: 'Local file/folder to share one time:',
    validate: value => {
      const trimmed = value.trim();
      if (!trimmed) return 'Required';
      const expanded = trimmed === '~' ? os.homedir() : trimmed.replace(/^~(?=\/)/, os.homedir());
      return fs.existsSync(expanded) || 'Path does not exist';
    },
  }]);
  return sharePath.trim() === '~' ? os.homedir() : sharePath.trim().replace(/^~(?=\/)/, os.homedir());
}

async function startLocalHostDashboard(uid, password, serviceConfig, sessionState) {
  const { default: express } = await import('express');
  const app = express();
  const startedAt = new Date().toISOString();
  const decryptedClientCache = new Map();
  const MAX_DECRYPTED_CLIENT_CACHE = 100;
  const activeEventStreams = new Set();
  const MAX_EVENT_STREAMS = 5;
  const dashboardUid = escapeDashboardHtml(uid);
  const dashboardService = escapeDashboardHtml(String(serviceConfig.type || '').toUpperCase());
  const dashboardPort = escapeDashboardHtml(serviceConfig.port);
  const dashboardDropPath = escapeDashboardHtml(serviceConfig.sharedDropPath || 'none');
  const dashboardSharePath = escapeDashboardHtml(serviceConfig.oneTimeSharePath || 'none');

  async function fetchDecryptedClients() {
    const brokerRes = await fetch(`${BROKER_URL}/clients/${uid}`, {
      headers: sessionState.hostToken ? { 'x-host-token': sessionState.hostToken } : {}
    });
    if (!brokerRes.ok) {
      const data = await brokerRes.json().catch(() => ({}));
      throw new Error(data.error || 'Failed to fetch clients');
    }
    const data = await brokerRes.json();
    const activeCacheKeys = new Set();
    const decryptedClients = await Promise.all((data.clients || []).map(async (clientBlob) => {
      const cacheKey = `${clientBlob.iv}:${clientBlob.salt}:${clientBlob.ciphertext}`;
      activeCacheKeys.add(cacheKey);
      const cached = decryptedClientCache.get(cacheKey);
      if (cached) return { ...cached, seenAt: clientBlob.seenAt || null };
      try {
        const decrypted = await decryptAsync(clientBlob.iv, clientBlob.ciphertext, password, clientBlob.salt);
        const t = JSON.parse(decrypted);
        decryptedClientCache.set(cacheKey, t);
        return { ...t, seenAt: clientBlob.seenAt || null };
      } catch {
        const failed = { error: 'decrypt_failed' };
        decryptedClientCache.set(cacheKey, failed);
        return { ...failed, seenAt: clientBlob.seenAt || null };
      }
    }));
    for (const key of decryptedClientCache.keys()) {
      if (!activeCacheKeys.has(key) || decryptedClientCache.size > MAX_DECRYPTED_CLIENT_CACHE) {
        decryptedClientCache.delete(key);
      }
    }
    return { clients: decryptedClients };
  }

  async function fetchDecryptedApprovals() {
    const data = await fetchApprovalRequests(BROKER_URL, uid, sessionState.hostToken);
    const decryptedApprovals = await Promise.all((data.approvals || []).map(async (a) => {
      const base = { id: a.id, status: a.status, createdAt: a.createdAt, decidedAt: a.decidedAt, ip: a.ip || 'unknown' };
      if (!a.iv || !a.ciphertext || !a.salt) return base;
      try {
        const decrypted = await decryptAsync(a.iv, a.ciphertext, password, a.salt);
        const details = JSON.parse(decrypted);
        return {
          ...base,
          username: details.username,
          hostname: details.hostname,
          os: details.os,
          intent: details.intent,
          localIp: details.localIp || 'unknown'
        };
      } catch {
        return base;
      }
    }));
    return { approvalRequired: data.approvalRequired, approvals: decryptedApprovals };
  }

  app.get('/api/status', (_req, res) => {
    res.json({
      uid,
      startedAt,
      service: serviceConfig.type,
      port: serviceConfig.port,
      approvalRequired: Boolean(serviceConfig.approvalRequired),
      sharedDropPath: serviceConfig.sharedDropPath || null,
      oneTimeSharePath: serviceConfig.oneTimeSharePath || null,
      chatUrl: serviceConfig.chatUrl ? '[configured]' : null,
    });
  });

  app.use(express.json());

  app.get('/api/approvals', async (_req, res) => {
    try {
      const data = await fetchDecryptedApprovals();
      res.json(data);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Server-Sent Events for live telemetry & approvals
  app.get('/api/events', async (req, res) => {
    if (activeEventStreams.size >= MAX_EVENT_STREAMS) {
      return res.status(503).json({ error: 'Too many dashboard event streams' });
    }
    activeEventStreams.add(res);
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.flushHeaders?.();

    let closed = false;
    let timer = null;
    let intervalMs = 5000;
    let unchangedCycles = 0;
    let lastApprovals = '';
    let lastClients = '';

    const writeEvent = (event, payload) => {
      if (closed) return;
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    };

    const scheduleNext = () => {
      if (closed) return;
      timer = setTimeout(pushLoop, intervalMs);
    };

    const pushLoop = async () => {
      if (closed) return;
      try {
        const [approvalData, clientData] = await Promise.all([
          fetchDecryptedApprovals().catch(() => ({ approvals: [] })),
          fetchDecryptedClients().catch(() => ({ clients: [] })),
        ]);

        const approvalsPayload = { approvals: approvalData.approvals || [] };
        const clientsPayload = { clients: clientData.clients || [] };
        const approvalsHash = JSON.stringify(approvalsPayload.approvals);
        const clientsHash = JSON.stringify(clientsPayload.clients);
        const changed = approvalsHash !== lastApprovals || clientsHash !== lastClients;

        if (approvalsHash !== lastApprovals) {
          writeEvent('approvals', approvalsPayload);
          lastApprovals = approvalsHash;
        }
        if (clientsHash !== lastClients) {
          writeEvent('clients', clientsPayload);
          lastClients = clientsHash;
        }

        if (changed) {
          unchangedCycles = 0;
          intervalMs = 5000;
        } else {
          unchangedCycles += 1;
          intervalMs = Math.min(20000, 5000 * (2 ** Math.min(2, unchangedCycles)));
        }
      } finally {
        scheduleNext();
      }
    };

    req.on('close', () => {
      closed = true;
      activeEventStreams.delete(res);
      if (timer) clearTimeout(timer);
    });

    writeEvent('ready', { ok: true });
    await pushLoop();
  });

  app.get('/api/clients', async (_req, res) => {
    try {
      const clients = await fetchDecryptedClients();
      res.json(clients);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // CSRF Protection Middleware for all mutating endpoints
  app.use((req, res, next) => {
    if (req.method !== 'POST') return next();
    
    // Express runs on localhost, ensure requests originate from the same host
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    
    // We expect origin to be http://127.0.0.1:<port>
    const isLocalOrigin = origin && (origin.startsWith('http://127.0.0.1:') || origin.startsWith('http://localhost:'));
    const isLocalReferer = referer && (referer.startsWith('http://127.0.0.1:') || referer.startsWith('http://localhost:'));
    
    if (!isLocalOrigin && !isLocalReferer) {
      console.warn(chalk.yellow(`\n  ⚠️  Blocked potential CSRF attack from origin: ${origin || referer || 'unknown'}`));
      return res.status(403).json({ error: 'CSRF validation failed' });
    }
    next();
  });

  app.post('/api/approval', async (req, res) => {
    const { requestId, decision } = req.body || {};
    if (!requestId || !decision) return res.status(400).json({ error: 'requestId and decision required' });
    try {
      let approvedPayload = null;
      if (decision === 'approved') {
        const data = await fetchApprovalRequests(BROKER_URL, uid, sessionState.hostToken);
        const request = (data.approvals || []).find(item => item.id === requestId);
        if (!request) return res.status(404).json({ error: 'Request not found' });
        
        let details = {};
        try {
          details = JSON.parse(await decryptAsync(request.iv, request.ciphertext, password, request.salt));
        } catch {}
        
        const clientKeySalt = [
          password,
          request.ip || 'unknown',
          details.username || 'unknown',
          details.hostname || 'unknown',
          details.os || 'unknown'
        ].join('|');
        const clientPwd = crypto.createHash('sha256').update(clientKeySalt).digest('hex');
        
        const payload = JSON.stringify({ url: sessionState.tunnelUrl, ...serviceConfig });
        approvedPayload = await encryptAsync(payload, clientPwd);
      }

      await decideApprovalRequest(BROKER_URL, uid, requestId, decision, sessionState.hostToken, approvedPayload);
      recordEvent('approval_decision', { uid, requestId, decision, via: 'dashboard' });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/revoke', async (_req, res) => {
    try {
      await revokeUID(BROKER_URL, uid, sessionState.hostToken);
      recordEvent('uid_revoked', { uid, via: 'dashboard' });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/', (_req, res) => {
    const scriptNonce = crypto.randomBytes(18).toString('base64');
    res.set('Content-Security-Policy', [
      "default-src 'self'",
      `script-src 'nonce-${scriptNonce}'`,
      "style-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
      "img-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join('; '));
    res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>iPingYou Host Dashboard</title>
<style>
:root{--bg:#0f172a;--panel:#1e293b;--border:#334155;--text:#f8fafc;--primary:#38bdf8;--accent:#818cf8;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--dim:#94a3b8}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:2rem}
h1{font-size:1.5rem;margin-bottom:0.5rem;display:flex;align-items:center;gap:0.5rem}
h2{font-size:1.1rem;color:var(--primary);margin-bottom:1rem;text-transform:uppercase;letter-spacing:0.05em}
.header{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1.5rem 2rem;margin-bottom:1.5rem;display:flex;justify-content:space-between;align-items:center}
.badge{background:var(--green);color:#000;padding:0.2rem 0.6rem;border-radius:999px;font-size:0.75rem;font-weight:700;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.6}}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1.5rem}
.info-row{display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--border)}
.info-row:last-child{border:none}
.info-label{color:var(--dim);font-size:0.85rem}
.info-value{font-weight:600;font-size:0.85rem}
code{background:var(--bg);padding:2px 8px;border-radius:4px;font-size:0.85rem}
.btn{border:none;padding:0.6rem 1.2rem;border-radius:8px;font-weight:700;cursor:pointer;font-size:0.85rem;transition:all 0.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,0.3)}
.btn:active{transform:scale(0.97)}
.btn-approve{background:var(--green);color:#000}.btn-deny{background:var(--red);color:white}
.btn-revoke{background:var(--red);color:white;padding:0.5rem 1rem}
.approval-item{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:0.75rem;animation:fadeIn 0.3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.approval-item .meta{font-size:0.8rem;color:var(--dim);margin-bottom:0.5rem}
.approval-item .actions{display:flex;gap:0.5rem;margin-top:0.75rem}
.status-badge{display:inline-block;padding:0.15rem 0.5rem;border-radius:999px;font-size:0.75rem;font-weight:600}
.status-pending{background:var(--yellow);color:#000}
.status-approved{background:var(--green);color:#000}
.status-denied{background:var(--red);color:white}
.empty{color:var(--dim);font-style:italic;font-size:0.9rem;padding:1rem 0}
.client-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:0.8rem 1rem;margin-bottom:0.5rem;font-size:0.85rem}
.client-card strong{color:var(--primary)}
#toast{position:fixed;bottom:2rem;right:2rem;background:var(--green);color:#000;padding:0.8rem 1.5rem;border-radius:8px;font-weight:700;opacity:0;transition:opacity 0.3s;pointer-events:none}
#toast.show{opacity:1}
</style></head>
<body>
<div class="header">
  <div><h1>🛡️ iPingYou Host Dashboard</h1><span style="color:var(--dim);font-size:0.85rem">UID: <code>${dashboardUid}</code></span></div>
  <div style="display:flex;gap:1rem;align-items:center">
    <span class="badge">● LIVE</span>
    <button id="revoke-session" class="btn btn-revoke" type="button">🚫 Revoke Session</button>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>📊 Session Info</h2>
    <div class="info-row"><span class="info-label">UID</span><span class="info-value"><code>${dashboardUid}</code></span></div>
    <div class="info-row"><span class="info-label">Password</span><span class="info-value"><code>[Hidden — see terminal]</code></span></div>
    <div class="info-row"><span class="info-label">Service</span><span class="info-value">${dashboardService} on port ${dashboardPort}</span></div>
    <div class="info-row"><span class="info-label">Approval Gate</span><span class="info-value">${serviceConfig.approvalRequired ? '<span style="color:var(--green)">✓ Enabled</span>' : '<span style="color:var(--dim)">Disabled</span>'}</span></div>
    <div class="info-row"><span class="info-label">Drop Folder</span><span class="info-value"><code>${dashboardDropPath}</code></span></div>
    <div class="info-row"><span class="info-label">One-Time Share</span><span class="info-value"><code>${dashboardSharePath}</code></span></div>
    <div class="info-row"><span class="info-label">Chat</span><span class="info-value">${serviceConfig.chatUrl ? '<span style="color:var(--green)">Active</span>' : '<span style="color:var(--dim)">Not started</span>'}</span></div>
    <div class="info-row"><span class="info-label">Uptime</span><span class="info-value" id="uptime">—</span></div>
  </div>

  <div class="card">
    <h2>✅ Pending Approvals <span id="approval-count" style="color:var(--dim);font-size:0.8rem"></span></h2>
    <div id="approvals"><p class="empty">No pending requests</p></div>
  </div>
</div>

<div class="card" style="margin-top:1.5rem">
  <h2>📡 Connected Clients <span id="client-count" style="color:var(--dim);font-size:0.8rem"></span></h2>
  <div id="clients"><p class="empty">No clients connected yet</p></div>
</div>

<div id="toast"></div>

<script nonce="${scriptNonce}">
const startedAt = new Date("${startedAt}");

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}
 
function appendEmptyState(container, text) {
  const message = document.createElement('p');
  message.className = 'empty';
  message.textContent = text;
  container.replaceChildren(message);
}

function updateUptime() {
  const diff = Math.floor((Date.now() - startedAt.getTime()) / 1000);
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;
  document.getElementById('uptime').textContent = h + 'h ' + m + 'm ' + s + 's';
}
setInterval(updateUptime, 1000);
updateUptime();

// SSE for live updates
const es = new EventSource('/api/events');
let fallbackTimer = null;
let fallbackDelay = 5000;

function scheduleFallbackPoll() {
  if (fallbackTimer) return;
  fallbackTimer = setTimeout(async function pollFallback() {
    fallbackTimer = null;
    try {
      const [approvalsRes, clientsRes] = await Promise.all([
        fetch('/api/approvals'),
        fetch('/api/clients')
      ]);
      if (approvalsRes.ok) renderApprovals((await approvalsRes.json()).approvals || []);
      if (clientsRes.ok) renderClients((await clientsRes.json()).clients || []);
    } catch {}
    fallbackDelay = Math.min(20000, fallbackDelay * 2);
    scheduleFallbackPoll();
  }, fallbackDelay);
}

es.addEventListener('open', () => {
  fallbackDelay = 5000;
  if (fallbackTimer) clearTimeout(fallbackTimer);
  fallbackTimer = null;
});
es.addEventListener('error', scheduleFallbackPoll);
es.addEventListener('approvals', (e) => {
  try {
    const data = JSON.parse(e.data);
    renderApprovals(data.approvals || []);
  } catch {}
});
es.addEventListener('clients', (e) => {
  try {
    const data = JSON.parse(e.data);
    renderClients(data.clients || []);
  } catch {}
});

function renderApprovals(approvals) {
  const container = document.getElementById('approvals');
  const pending = approvals.filter(a => a.status === 'pending');
  const decided = approvals.filter(a => a.status !== 'pending').slice(-5);
  document.getElementById('approval-count').textContent = pending.length > 0 ? '(' + pending.length + ' pending)' : '';

  if (approvals.length === 0) {
    appendEmptyState(container, 'No approval requests yet');
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const req of pending) {
    const item = document.createElement('div');
    item.className = 'approval-item';
    const heading = document.createElement('div');
    heading.style.cssText = 'display:flex;justify-content:space-between;align-items:center';
    const title = document.createElement('strong');
    title.textContent = 'Request ' + String(req.id || '');
    const badge = document.createElement('span');
    badge.className = 'status-badge status-pending';
    badge.textContent = 'PENDING';
    heading.append(title, badge);
    const details = document.createElement('div');
    details.className = 'meta';
    details.textContent = 'User: ' + String(req.username || 'unknown') + '  |  Host: ' + String(req.hostname || 'unknown') + '  |  OS: ' + String(req.os || 'unknown') + '  |  IP: ' + String(req.ip || 'unknown') + ' (Local: ' + String(req.localIp || 'unknown') + ')';
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = 'Submitted: ' + new Date(req.createdAt).toLocaleTimeString();
    const actions = document.createElement('div');
    actions.className = 'actions';
    for (const choice of [
      { decision: 'approved', label: '✅ Approve', className: 'btn btn-approve' },
      { decision: 'denied', label: '❌ Deny', className: 'btn btn-deny' }
    ]) {
      const button = document.createElement('button');
      button.className = choice.className;
      button.type = 'button';
      button.textContent = choice.label;
      button.addEventListener('click', function() {
        decide(String(req.id || ''), choice.decision);
      });
      actions.appendChild(button);
    }
    item.append(heading, details, meta, actions);
    fragment.appendChild(item);
  }
  for (const req of decided) {
    const status = req.status === 'approved' ? 'approved' : 'denied';
    const item = document.createElement('div');
    item.className = 'approval-item';
    item.style.opacity = '0.6';
    const heading = document.createElement('div');
    heading.style.cssText = 'display:flex;justify-content:space-between;align-items:center';
    const title = document.createElement('strong');
    title.textContent = 'Request ' + String(req.id || '');
    const badge = document.createElement('span');
    badge.className = 'status-badge status-' + status;
    badge.textContent = status.toUpperCase();
    heading.append(title, badge);
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = 'Decided: ' + (req.decidedAt ? new Date(req.decidedAt).toLocaleTimeString() : 'N/A');
    item.append(heading, meta);
    fragment.appendChild(item);
  }
  container.replaceChildren(fragment);
}

async function decide(requestId, decision) {
  try {
    const res = await fetch('/api/approval', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestId, decision })
    });
    if (res.ok) showToast(decision === 'approved' ? '✅ Approved!' : '❌ Denied!');
    else showToast('Failed: ' + (await res.json()).error);
  } catch (err) { showToast('Error: ' + err.message); }
}

async function revokeSession() {
  if (!confirm('Are you sure you want to revoke this session? All clients will lose access.')) return;
  try {
    const res = await fetch('/api/revoke', { method: 'POST' });
    if (res.ok) { showToast('🚫 Session revoked!'); document.querySelector('.badge').textContent = '● REVOKED'; document.querySelector('.badge').style.background = 'var(--red)'; }
    else showToast('Failed to revoke');
  } catch (err) { showToast('Error: ' + err.message); }
}
document.getElementById('revoke-session').addEventListener('click', revokeSession);

function renderClients(clients) {
  const container = document.getElementById('clients');
  if (!clients || clients.length === 0) {
    appendEmptyState(container, 'No clients connected yet');
    document.getElementById('client-count').textContent = '';
    return;
  }
 
  document.getElementById('client-count').textContent = '(' + clients.length + ' connected)';
  const fragment = document.createDocumentFragment();
  clients.forEach((c, idx) => {
    const card = document.createElement('div');
    card.className = 'client-card';
    if (c.error) {
      const title = document.createElement('strong');
      title.textContent = 'Client #' + (idx + 1);
      card.append(title, document.createTextNode(' — payload decryption failed'));
      fragment.appendChild(card);
      return;
    }
    const when = c.time || (c.seenAt ? new Date(c.seenAt).toLocaleTimeString() : 'Unknown');
    const title = document.createElement('strong');
    title.textContent = String(c.username || 'Unknown');
    card.append(title, document.createTextNode(' — ' + String(c.action || 'connected')), document.createElement('br'));
    for (const field of [
      ['IP', c.ip],
      ['OS', c.os],
      ['CPU', c.cpu],
      ['RAM', c.ram],
      ['Time', when]
    ]) {
      const meta = document.createElement('span');
      meta.className = 'meta';
      meta.textContent = field[0] + ': ' + String(field[1] || 'Unknown');
      card.appendChild(meta);
      if (field[0] !== 'Time') card.appendChild(document.createElement('br'));
    }
    fragment.appendChild(card);
  });
  container.replaceChildren(fragment);
}
 
</script>
</body></html>`);
 });

  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', async () => {
      const port = server.address().port;
      const url = `http://127.0.0.1:${port}`;
      console.log(chalk.green(`  ✓ Local dashboard: ${url}`));
      try { await openUrl(url); } catch { }
      resolve({ url, close: () => server.close() });
    });
  });
}

/**
 * Auto-spawn a Private Broker locally and wrap it in a Cloudflare tunnel.
 */
async function spawnPrivateBroker() {
  console.log(chalk.yellow('\n  ⚠️  Public Broker is unreachable. Spawning Private Broker...'));

  const serverEntrypoint = path.join(__dirname, '../server.js');
  const requireFromServer = createRequire(serverEntrypoint);
  const requiredBrokerPackages = ['express', 'express-rate-limit', 'helmet'];
  const missingPackages = requiredBrokerPackages.filter((pkg) => {
    try {
      requireFromServer.resolve(pkg);
      return false;
    } catch {
      return true;
    }
  });

  if (missingPackages.length > 0) {
    throw new Error(
      `Private broker dependencies are missing: ${missingPackages.join(', ')}. `
      + 'Reinstall iPingYou from its verified package before starting a private broker.'
    );
  }

  // 1. Spawn the broker server process
  const brokerProcess = execa('node', [serverEntrypoint], {
    env: { ...process.env, PORT: '4040' },
    reject: false,
    all: true,
    buffer: false,
  });
  trackPID(brokerProcess.pid);

  let brokerExited = false;
  const maxBrokerOutputBytes = 64 * 1024;
  let brokerOutput = Buffer.alloc(0);
  brokerProcess.all?.on('data', chunk => {
    const next = Buffer.concat([brokerOutput, Buffer.from(chunk)]);
    brokerOutput = next.length > maxBrokerOutputBytes
      ? next.subarray(next.length - maxBrokerOutputBytes)
      : next;
  });
  brokerProcess.on('exit', () => {
    brokerExited = true;
  });

  // 2. Wrap it in a cloudflare tunnel
  let brokerTunnelUrl = null;
  const privateBrokerTunnelProcess = await spawnTunnelSupervised('http://localhost:4040', (newUrl) => {
    brokerTunnelUrl = newUrl;
  });

  await waitForValue(() => {
    if (brokerExited) {
      const output = brokerOutput.toString('utf8').trim();
      throw new Error(`Private broker exited before tunnel was ready${output ? `: ${output}` : ''}`);
    }
    return brokerTunnelUrl;
  }, 30000, 'Private broker tunnel startup');

  console.log(chalk.green(`  ✅ Private Broker Active: ${chalk.bold.cyan(brokerTunnelUrl)}\n`));

  return {
    url: brokerTunnelUrl,
    kill: () => {
      privateBrokerTunnelProcess.kill();
      killProcessTree(brokerProcess.pid).finally(() => untrackPID(brokerProcess.pid));
    }
  };
}

// Monitor active connections removed (replaced by Telemetry)

/**
 * Display the host dashboard and handle user input.
 */
async function hostDashboard(uid, password, serviceConfig, tunnelProcess, sessionState) {
  let chatServerInstance = null;
  let chatTunnelProcess = null;
  let dashboardInstance = null;

  const renderDashboard = () => {
    const isPrivateBroker = Boolean(global.privateBrokerInstance);
    console.clear();
    console.log('');
    console.log(chalk.bold('  ╔════════════════════════════════════════════════════╗'));
    console.log(chalk.bold('  ║         🛡️  SecureLink — HOST MODE ACTIVE          ║'));
    console.log(chalk.bold('  ╠════════════════════════════════════════════════════╣'));
    console.log(`  ║  ${chalk.cyan('UID:')}        ${chalk.bold.white(uid.padEnd(30))}║`);
    console.log(`  ║  ${chalk.cyan('Password:')}   ${chalk.bold.white(secureSensitive(password).padEnd(30))}║`);
    console.log(`  ║  ${chalk.cyan('Service:')}    ${chalk.dim(serviceConfig.type.toUpperCase() + ' (Port ' + serviceConfig.port + ')').padEnd(30)}║`);
    if (isPrivateBroker) {
      console.log(`  ║  ${chalk.cyan('Tunnel:')}     ${chalk.dim(sessionState.tunnelUrl.substring(0, 40))}  ║`);
    }
    if (serviceConfig.chatUrl) {
      console.log(`  ║  ${chalk.cyan('Chat URL:')}   ${chalk.dim(serviceConfig.chatUrl.substring(0, 40))}  ║`);
    }
    if (serviceConfig.sharedDropPath) {
      console.log(`  ║  ${chalk.cyan('Drop Box:')}   ${chalk.dim(serviceConfig.sharedDropPath.substring(0, 40))}  ║`);
    }
    console.log(`  ║  ${chalk.cyan('Approval:')}   ${serviceConfig.approvalRequired ? chalk.green('Required').padEnd(39) : chalk.dim('Not required').padEnd(39)}║`);
    console.log(`  ║  ${chalk.cyan('Broker:')}     ${chalk.dim(BROKER_URL.substring(0, 40))}  ║`);
    console.log(`  ║  ${chalk.cyan('Crypto:')}     ${chalk.green('AES-256-CBC E2E (PBKDF2)')}             ║`);
    console.log(chalk.bold('  ╠════════════════════════════════════════════════════╣'));
    console.log(`  ║  ${chalk.yellow('Share the UID, Password & Broker URL with client ')}  ║`);
    console.log(`  ║  ${chalk.dim('Press Ctrl+C to terminate the session')}              ║`);
    console.log(chalk.bold('  ╚════════════════════════════════════════════════════╝'));
    console.log('');
    const logPath = getSessionLogPath();
    if (logPath) {
      console.log(chalk.dim(`  📜 Session log: ${logPath}`));
      console.log('');
    }
  };

  renderDashboard();
  await typeText(chalk.dim(`  Listening for incoming connections on port ${serviceConfig.port}...`), 30);
  console.log('');

  const waitForAction = async () => {
    try {
      const choices = [
        { name: '✅ Review pending client approvals', value: 'approvals' },
        { name: '📱 Display Connection QR Code & Quick Info', value: 'qr' },
        { name: '👢 Kick / Revoke Client Session', value: 'kick' },
        { name: '⏱️ Extend Session TTL (+15m / +60m)', value: 'extend' },
        { name: '📡 See detailed client telemetry', value: 'show' },
        { name: '📄 View live client activity logs', value: 'logs' },
        { name: '📄 View host session activity logs', value: 'host_logs' },
        { name: '🔄 Re-register with broker', value: 'reregister' }
      ];

      if (!chatServerInstance) {
        choices.push({ name: '💬 Start Real-time Chat Room', value: 'chat' });
      } else {
        choices.push({ name: '💬 Re-open Chat Room in Browser', value: 'reopen_chat' });
      }
      if (!dashboardInstance) {
        choices.push({ name: '🌐 Open Local Web Dashboard', value: 'dashboard' });
      } else {
        choices.push({ name: '🌐 Show Local Web Dashboard URL', value: 'dashboard_url' });
      }

      choices.push(
        { name: '🚫 Terminate all connections', value: 'terminate' },
        { name: '❌ Shut down session', value: 'exit' }
      );

      const { action } = await inquirer.prompt([
        {
          type: 'list',
          name: 'action',
          message: 'Host Controls:',
          choices,
        },
      ]);

      logSessionEvent('host_action_selected', { action });

      switch (action) {
        case 'qr': {
          generateTerminalQR(uid, password, BROKER_URL);
          return waitForAction();
        }

        case 'kick': {
          try {
            console.log(chalk.dim('\n  Fetching active clients...'));
            const data = await fetchApprovalRequests(BROKER_URL, uid, sessionState.hostToken);
            const approved = (data.approvals || []).filter(item => item.status === 'approved' || item.ip);
            if (approved.length === 0) {
              console.log(chalk.yellow('  No active client IP approvals found. Revoking entire session instead?'));
            }

            const clientChoices = approved.map(a => ({
              name: `Client IP: ${a.ip || 'unknown'} (ID: ${a.id})`,
              value: a.ip
            }));
            clientChoices.push({ name: '🚨 Revoke ENTIRE Session & Kick ALL Clients', value: '__ALL__' });
            clientChoices.push({ name: '🔙 Cancel', value: '__CANCEL__' });

            const { targetClient } = await inquirer.prompt([{
              type: 'list',
              name: 'targetClient',
              message: 'Select a client to kick:',
              choices: clientChoices
            }]);

            if (targetClient === '__CANCEL__') return waitForAction();

            const clientIpToKick = targetClient === '__ALL__' ? null : targetClient;
            await kickClient(BROKER_URL, uid, sessionState.hostToken, clientIpToKick);
            console.log(chalk.green(`  ✅ ${clientIpToKick ? `Kicked client IP ${clientIpToKick}` : 'All clients kicked & session revoked!'}`));
            logSessionEvent('host_client_kicked', { targetClient });
          } catch (err) {
            console.log(chalk.red(`  ❌ Failed to kick client: ${err.message}`));
          }
          return waitForAction();
        }

        case 'extend': {
          const { extendMins } = await inquirer.prompt([{
            type: 'list',
            name: 'extendMins',
            message: 'Select session extension duration:',
            choices: [
              { name: '⏱️ +15 Minutes', value: 15 },
              { name: '⏱️ +30 Minutes', value: 30 },
              { name: '⏱️ +60 Minutes (1 Hour)', value: 60 },
              { name: '⏱️ +120 Minutes (2 Hours)', value: 120 }
            ]
          }]);

          try {
            const result = await extendSession(BROKER_URL, uid, sessionState.hostToken, extendMins);
            console.log(chalk.green(`  ✅ Session extended by +${extendMins} minutes!`));
            if (result.ttlRemainingMs) {
              const minsLeft = Math.round(result.ttlRemainingMs / 60000);
              console.log(chalk.cyan(`  ⏱️  Total TTL Remaining: ~${minsLeft} minutes`));
            }
            logSessionEvent('host_session_extended', { minutes: extendMins });
          } catch (err) {
            console.log(chalk.red(`  ❌ Could not extend session: ${err.message}`));
          }
          return waitForAction();
        }

        case 'approvals': {
          try {
            const data = await fetchApprovalRequests(BROKER_URL, uid, sessionState.hostToken);
            const pending = (data.approvals || []).filter(item => item.status === 'pending');
            if (pending.length === 0) {
              console.log(chalk.yellow('  No pending approval requests.'));
              return waitForAction();
            }

            notifyDesktop('iPingYou Access Request', `Pending client approval request for UID ${uid}`);

            for (const request of pending) {
              let details = {};
              if (!request.iv || !request.ciphertext || !request.salt) {
                console.log(chalk.yellow('  ⚠️  Broker did not return encrypted client metadata.'));
                console.log(chalk.dim('     This usually means the broker is running an older version.'));
                console.log(chalk.dim('     Redeploy the broker with the latest server.js to fix this.'));
                details = { error: 'Broker returned no encrypted metadata' };
              } else {
                try {
                  details = JSON.parse(await decryptAsync(request.iv, request.ciphertext, password, request.salt));
                } catch (decErr) {
                  console.log(chalk.yellow(`  ⚠️  Could not decrypt client details: ${decErr.message}`));
                  details = { error: 'Decryption failed' };
                }
              }
              console.log('');
              console.log(chalk.bold.cyan(`  Approval Request ${request.id}`));
              console.log(`    User:   ${details.username || 'unknown'}`);
              console.log(`    Host:   ${details.hostname || 'unknown'}`);
              console.log(`    OS:     ${details.os || 'unknown'}`);
              console.log(`    Intent: ${details.intent || 'connect'}`);
              console.log(`    IP:     ${request.ip || 'unknown'} (Local: ${details.localIp || 'unknown'})`);

              const { decision } = await inquirer.prompt([{
                type: 'list',
                name: 'decision',
                message: 'Decision:',
                choices: [
                  { name: 'Approve', value: 'approved' },
                  { name: 'Deny', value: 'denied' },
                  { name: 'Skip', value: 'skip' },
                ],
              }]);
              if (decision !== 'skip') {
                let approvedPayload = null;
                if (decision === 'approved') {
                  // Key derivation uses ONLY values both sides reliably know:
                  // password + broker-observed IP. No decrypted client metadata
                  // (which may fail if broker is stale or encryption differs).
                  const clientKeySalt = [
                    password,
                    request.ip || 'unknown',
                    uid
                  ].join('|');
                  const clientPwd = crypto.createHash('sha256').update(clientKeySalt).digest('hex');
                  
                  const payload = JSON.stringify({ url: sessionState.tunnelUrl, ...serviceConfig });
                  approvedPayload = await encryptAsync(payload, clientPwd);
                }
                
                await decideApprovalRequest(BROKER_URL, uid, request.id, decision, sessionState.hostToken, approvedPayload);
                recordEvent('approval_decision', { uid, requestId: request.id, decision, username: details.username });
              }
            }
          } catch (err) {
            console.log(chalk.red(`  Could not review approvals: ${err.message}`));
            logSessionEvent('host_approvals_error', { error: err.message }, 'error');
          }
          return waitForAction();
        }

        case 'chat': {
          console.log(chalk.dim('\n  Starting chat server...'));
          chatServerInstance = await startChatServer(async () => {
            if (chatTunnelProcess) {
              chatTunnelProcess.kill();
              chatTunnelProcess = null;
              chatServerInstance = null;
              delete serviceConfig.chatUrl;
              const res = await registerWithBroker(BROKER_URL, uid, sessionState.tunnelUrl, password, serviceConfig);
              if (res.success && res.hostToken) sessionState.hostToken = res.hostToken;
              renderDashboard();
            }
          });

          addCleanupHook(() => {
            try {
              if (chatServerInstance && chatServerInstance.server) {
                chatServerInstance.server.close();
              }
            } catch {}
          });

          console.log(chalk.dim('  Provisioning Cloudflare tunnel for chat...'));
          chatTunnelProcess = await spawnTunnelSupervised(`http://localhost:${chatServerInstance.port}`, async (newUrl) => {
            serviceConfig.chatUrl = newUrl;
            const res = await registerWithBroker(BROKER_URL, uid, sessionState.tunnelUrl, password, serviceConfig);
            if (res.success && res.hostToken) sessionState.hostToken = res.hostToken;
            renderDashboard();
          });

          await waitForValue(() => serviceConfig.chatUrl, 30000, 'Chat tunnel startup');

          console.log(chalk.green('  ✅ Chat Room Live! Clients can now join.'));
          logSessionEvent('host_chat_started');
          await openLocalChatUI(chatServerInstance.port, password);
          return waitForAction();
        }

        case 'dashboard': {
          dashboardInstance = await startLocalHostDashboard(uid, password, serviceConfig, sessionState);
          addCleanupHook(() => {
            try { if (dashboardInstance) dashboardInstance.close(); } catch {}
          });
          logSessionEvent('host_dashboard_opened');
          return waitForAction();
        }

        case 'dashboard_url': {
          console.log(chalk.green(`  Dashboard: ${dashboardInstance.url}`));
          logSessionEvent('host_dashboard_url_shown');
          return waitForAction();
        }

        case 'reopen_chat': {
          if (chatServerInstance) await openLocalChatUI(chatServerInstance.port, password);
          logSessionEvent('host_chat_reopened');
          return waitForAction();
        }

        case 'logs': {
          await viewLiveClientLogs(serviceConfig.sharedDropPath);
          return waitForAction();
        }
        case 'host_logs': {
          await viewHostLiveLogs();
          return waitForAction();
        }

        case 'show': {
          await showDetailedClientTelemetry(uid, password, sessionState.hostToken);
          console.log('');
          return waitForAction();
        }

        case 'reregister':
          const res = await registerWithBroker(BROKER_URL, uid, sessionState.tunnelUrl, password, serviceConfig);
          if (res.success && res.hostToken) sessionState.hostToken = res.hostToken;
          logSessionEvent('host_broker_reregistered');
          return waitForAction();

        case 'terminate': {
          const spinner = createSpinner('Revoking session and closing its tunnel...', networkSpinner).start();
          try {
            await revokeUID(BROKER_URL, uid, sessionState.hostToken);
            tunnelProcess.kill();
            // No tmux server to terminate since mirroring was discarded
            spinner.succeed('Session revoked and iPingYou-owned connections terminated');
            logSessionEvent('host_sessions_terminated');
          } catch {
            spinner.warn('Could not terminate sessions (none active?)');
            logSessionEvent('host_sessions_terminate_failed', {}, 'warn');
          }
          return waitForAction();
        }

        case 'exit':
          if (dashboardInstance) dashboardInstance.close();
          if (chatServerInstance && chatServerInstance.server) {
            try { chatServerInstance.server.close(); } catch {}
          }
          if (chatTunnelProcess) chatTunnelProcess.kill();
          if (global.privateBrokerInstance) global.privateBrokerInstance.kill();
          if (tunnelProcess) tunnelProcess.kill();
          logSessionEvent('host_session_exit');
          await cleanupAll();
          return;
      }
    } catch (err) {
      throw err;
    }
  };

  await waitForAction();
}

/**
 * Main Host Mode entry point.
 */
export async function startHostMode(options = {}) {
  console.log('');
  console.log(chalk.bold.cyan('  🔒 HOST MODE — Allow Remote Access'));
  console.log(chalk.dim('  ─────────────────────────────────────'));
  if (options.readOnly || options.viewOnly) {
    console.log(chalk.yellow.bold('  🔒 Read-Only Shell Mode Enabled'));
  }
  console.log('');

  const sessionLogPath = initSessionLog('host');
  if (sessionLogPath) {
    console.log(chalk.dim(`  📜 Session log: ${sessionLogPath}`));
    addCleanupHook(() => cleanupSessionLog());
  }
  logSessionEvent('host_mode_started');

  const uid = generateUID();
  console.log(`  ${chalk.green('✓')} Session UID: ${chalk.bold.white(uid)}`);
  console.log('');
  logSessionEvent('host_uid_generated', { uid });

  const { pwdInput } = await inquirer.prompt([
    {
      type: 'input',
      name: 'pwdInput',
      message: 'Enter a session password to encrypt the tunnel (leave blank to auto-generate):',
    },
  ]);
  const password = pwdInput.trim() || generateUID();
  console.log(`  ${chalk.green('✓')} Password: ${chalk.bold.white(secureSensitive(password))}`);
  console.log('');

  // ─── Broker Selection ───
  if (!process.env.BROKER_URL) {
    const { brokerChoice } = await inquirer.prompt([
      {
        type: 'list',
        name: 'brokerChoice',
        message: 'Which Broker Server would you like to use?',
        choices: [
          { name: '🌍 Global Public Broker (Render)', value: 'global' },
          { name: '🛠️  Create a Private Broker (Local + Cloudflare)', value: 'create_private' }
        ]
      }
    ]);

    if (brokerChoice === 'create_private') {
      global.privateBrokerInstance = await spawnPrivateBroker();
      BROKER_URL = global.privateBrokerInstance.url;
    }
    logSessionEvent('host_broker_selected', { choice: brokerChoice, broker: BROKER_URL });
  }

  // Only ping if we haven't just created a private broker
  if (!global.privateBrokerInstance) {
    const spinner = createSpinner(`Checking broker status at ${BROKER_URL}...`, networkSpinner).start();
    const brokerOnline = await pingBroker(BROKER_URL);

    if (brokerOnline) {
      spinner.succeed(`Broker is online ${chalk.dim(`(${BROKER_URL})`)}`);
      logSessionEvent('host_broker_online', { broker: BROKER_URL });
    } else {
      spinner.warn(`Broker is unreachable ${chalk.dim(`(${BROKER_URL})`)}`);
      logSessionEvent('host_broker_unreachable', { broker: BROKER_URL }, 'warn');
      const { startPrivate } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'startPrivate',
          message: 'The broker is offline. Do you want to auto-spawn a Private Broker on this machine?',
          default: true
        }
      ]);
      if (startPrivate) {
        global.privateBrokerInstance = await spawnPrivateBroker();
        BROKER_URL = global.privateBrokerInstance.url;
        logSessionEvent('host_private_broker_spawned', { broker: BROKER_URL });
      } else {
        console.log(chalk.red('\n  ❌ FATAL: Cannot continue without a broker.'));
        logSessionEvent('host_broker_missing_exit', { broker: BROKER_URL }, 'error');
        process.exit(1);
      }
    }
  }

  console.log('');
  const { serviceType } = await inquirer.prompt([
    {
      type: 'list',
      name: 'serviceType',
      message: 'What service do you want to expose?',
      choices: [
        { name: '🖥️  SSH (Port 22)', value: 'ssh' },
        { name: '📦 One-Time File Share (SCP over SSH)', value: 'share' },
        { name: '🌐 Web/HTTP (Custom Port)', value: 'http' },
        { name: '🔌 Custom TCP Port (e.g. Database, RDP, VNC)', value: 'tcp' }
      ]
    }
  ]);

  let targetPort = 22;
  let protocol = 'ssh';

  if (serviceType === 'share') {
    targetPort = 22;
    protocol = 'ssh';
  } else if (serviceType === 'http') {
    const ans = await inquirer.prompt([{ name: 'port', message: 'Enter local HTTP port (e.g. 3000):', default: '3000' }]);
    targetPort = ans.port;
    protocol = 'http';
  } else if (serviceType === 'tcp') {
    const ans = await inquirer.prompt([{ name: 'port', message: 'Enter local TCP port (e.g. 3389 for RDP, 5432 for Postgres):' }]);
    targetPort = ans.port;
    protocol = 'tcp';
  }

  const serviceConfig = { type: serviceType === 'share' ? 'ssh' : serviceType, port: targetPort, protocol };
  let targetUrl = `${protocol}://localhost:${targetPort}`;
  logSessionEvent('host_service_selected', { serviceType, protocol, port: targetPort });

  if (serviceType === 'ssh' || serviceType === 'share') {
    await ensureSSHRunning();

    try {
      serviceConfig.sharedDropPath = await prepareSharedDropFolder(uid);
      console.log(chalk.green(`  ✓ Shared drop folder ready: ${serviceConfig.sharedDropPath}`));
      showMacPrivacyPreflight(serviceConfig.sharedDropPath);
      addCleanupHook(() => cleanupSharedDropFolder(serviceConfig.sharedDropPath, uid));
    } catch (err) {
      console.log(chalk.yellow(`  ⚠️  Could not prepare shared drop folder: ${err.message}`));
    }

    if (serviceType === 'share') {
      serviceConfig.oneTimeSharePath = await promptOneTimeSharePath();
      serviceConfig.oneTime = true;
      console.log(chalk.green(`  ✓ One-time share selected: ${serviceConfig.oneTimeSharePath}`));
      logSessionEvent('host_one_time_share_selected');
    }

    const { approvalRequired } = await inquirer.prompt([{
      type: 'confirm',
      name: 'approvalRequired',
      message: 'Require host approval before clients receive tunnel/key material?',
      default: serviceType !== 'share',
    }]);
    serviceConfig.approvalRequired = approvalRequired;
    logSessionEvent('host_approval_required', { approvalRequired });

    console.log(chalk.dim('  🔑 Generating ephemeral SSH key for passwordless entry...'));
    let ephemeralKey = null;
    let injectedKey = null;
    let managedSshd = null;
    const sshUsername = getCurrentSshUsername();
    try {
      ephemeralKey = await generateEphemeralKey();
      if (!sshUsername) {
        throw new Error('Could not resolve the current SSH username for passwordless entry');
      }
      injectedKey = await injectPublicKey(ephemeralKey.pubKey, sshUsername);
      const { authKeysPath, authKeysPaths, adminAuthKeysPath, authorizedKey } = injectedKey;
      await verifyHostAcceptsEphemeralKey(sshUsername, ephemeralKey.keyPath, targetPort);

      serviceConfig.privateKey = ephemeralKey.privKey;
      serviceConfig.sshUsername = sshUsername;

      addCleanupHook(async () => {
        console.log(chalk.dim('     Removing ephemeral public key...'));
        await removePublicKey(authKeysPath, authorizedKey, adminAuthKeysPath, authKeysPaths);
        try { await fs.promises.unlink(ephemeralKey.keyPath); } catch { }
        try { await fs.promises.unlink(`${ephemeralKey.keyPath}.pub`); } catch { }
      });
      console.log(chalk.green(`  ✓ Ephemeral key injected for ${sshUsername}. Client will connect without system password!`));
      logSessionEvent('host_ephemeral_key_ready');
    } catch (err) {
      if (injectedKey) {
        await removePublicKey(injectedKey.authKeysPath, injectedKey.authorizedKey, injectedKey.adminAuthKeysPath, injectedKey.authKeysPaths).catch(() => {});
      }
      console.log(chalk.yellow(`  ⚠️  Could not prepare ephemeral SSH key: ${err.message}`));
      showPasswordlessHostHint();
      await showPasswordlessDiagnostics(getCurrentSshUsername(), os.homedir()).catch(() => {});
      logSessionEvent('host_system_ephemeral_key_failed', { error: err.message }, 'warn');

      if (ephemeralKey && sshUsername) {
        try {
          console.log(chalk.dim('     Starting managed SSH fallback for passwordless entry...'));
          managedSshd = await startManagedSshd(sshUsername, ephemeralKey.pubKey, ephemeralKey.keyPath);
          targetPort = managedSshd.port;
          serviceConfig.port = targetPort;
          serviceConfig.privateKey = ephemeralKey.privKey;
          serviceConfig.sshUsername = sshUsername;
          serviceConfig.managedSshd = true;
          targetUrl = `${protocol}://localhost:${targetPort}`;

          addCleanupHook(async () => {
            console.log(chalk.dim('     Stopping managed SSH fallback...'));
            await managedSshd.cleanup();
            try { await fs.promises.unlink(ephemeralKey.keyPath); } catch { }
            try { await fs.promises.unlink(`${ephemeralKey.keyPath}.pub`); } catch { }
          });
          console.log(chalk.green(`  ✓ Managed SSH fallback active on localhost:${targetPort}. Client will connect without system password!`));
          console.log(chalk.dim(`     Managed sshd log: ${managedSshd.logPath}`));
          logSessionEvent('host_managed_sshd_ready', { port: targetPort });
        } catch (fallbackErr) {
          if (managedSshd) await managedSshd.cleanup().catch(() => {});
          try { await fs.promises.unlink(ephemeralKey.keyPath); } catch { }
          try { await fs.promises.unlink(`${ephemeralKey.keyPath}.pub`); } catch { }
          console.log(chalk.red(`  ❌ Managed SSH fallback failed: ${fallbackErr.message}`));
          console.log(chalk.dim('     Client will need to use a working OS SSH key or the host must fix sshd public-key auth.'));
          logSessionEvent('host_ephemeral_key_failed', { error: err.message, fallbackError: fallbackErr.message }, 'error');
        }
      } else {
        console.log(chalk.dim('     Client will need to use standard OS password.'));
        logSessionEvent('host_ephemeral_key_failed', { error: err.message }, 'warn');
      }
    }
  } else {
    console.log(chalk.dim(`  ℹ️  Ensure your ${protocol.toUpperCase()} service is running on port ${targetPort}.`));
  }

  const sessionState = { tunnelUrl: null, hostToken: null };
  const tunnelProcess = await spawnTunnelSupervised(targetUrl, async (newUrl) => {
    sessionState.tunnelUrl = newUrl;
    // Register or re-register with broker when tunnel is spawned/respawned
    const res = await registerWithBroker(BROKER_URL, uid, sessionState.tunnelUrl, password, serviceConfig);
    if (!res.success) {
      console.error(chalk.red(`\n  ❌ FATAL: Could not register with broker at ${BROKER_URL}`));
      logSessionEvent('host_broker_register_failed', { broker: BROKER_URL }, 'error');
      process.exit(1);
    }
    if (res.hostToken) sessionState.hostToken = res.hostToken;
  });

  // Wait for the tunnel AND broker registration to complete before showing dashboard
  await waitForValue(() => sessionState.hostToken, 30000, 'Cloudflare tunnel and Broker startup');

  setRevokeOnExit(uid, BROKER_URL, () => sessionState.hostToken);

  await hostDashboard(uid, password, serviceConfig, tunnelProcess, sessionState);
}
