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

import { execa, execaCommand } from 'execa';
import chalk from 'chalk';
import inquirer from 'inquirer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import { generateUID } from '../lib/uid.js';
import { decrypt } from '../lib/crypto.js';
import { cleanupAll, killProcessTree, trackPID, untrackPID, setRevokeOnExit, addCleanupHook } from '../lib/cleanup.js';
import { detectOS } from '../lib/platform.js';
import { createSpinner, networkSpinner, typeText } from '../lib/animations.js';
import { startChatServer, openLocalChatUI } from '../lib/chat.js';
import { spawnTunnelSupervised } from '../lib/tunnel.js';
import { decideApprovalRequest, fetchApprovalRequests, pingBroker, registerWithBroker, revokeUID } from '../lib/broker.js';
import { cleanupSessionLog, getSessionLogPath, initSessionLog, logSessionEvent, recordEvent } from '../lib/session-log.js';
import { TMUX_SESSION_NAME, TMUX_SESSION_PREFIX, tmuxSocketArgs } from '../lib/tmux.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

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

/**
 * Ensure the local SSH server is running.
 */
async function ensureSSHRunning() {
  const spinner = createSpinner('Checking SSH service...', networkSpinner).start();
  const osInfo = detectOS();

  try {
    if (osInfo.isLinux) {
      try {
        await execaCommand('systemctl is-active ssh', { reject: true });
        spinner.succeed('SSH service is active');
      } catch {
        spinner.text = 'Starting SSH service...';
        try {
          await execaCommand('sudo systemctl start ssh', { stdio: 'inherit' });
          spinner.succeed('SSH service started');
        } catch {
          await execaCommand('sudo systemctl start sshd', { stdio: 'inherit' });
          spinner.succeed('SSH service started (sshd)');
        }
      }
    } else if (osInfo.isMac) {
      try {
        const { stdout } = await execaCommand('sudo systemsetup -getremotelogin', { reject: false });
        if (stdout.toLowerCase().includes('off')) {
          spinner.text = 'Enabling Remote Login...';
          await execaCommand('sudo systemsetup -setremotelogin on', { stdio: 'inherit' });
          spinner.succeed('Remote Login enabled');
        } else {
          spinner.succeed('SSH (Remote Login) is active');
        }
      } catch {
        spinner.warn('Could not verify SSH status — ensure Remote Login is enabled in System Preferences');
      }
    } else if (osInfo.isWindows) {
      try {
        const { stdout } = await execaCommand('sc query sshd', { reject: false });
        if (stdout.includes('STOPPED')) {
          spinner.text = 'Starting OpenSSH Server...';
          await execaCommand('net start sshd', { stdio: 'inherit' });
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

/**
 * Ensure tmux is installed for terminal mirroring.
 */
async function ensureTmuxInstalled() {
  const osInfo = detectOS();
  if (osInfo.isWindows) return;

  const spinner = createSpinner('Checking tmux installation...', networkSpinner).start();
  try {
    try {
      await execaCommand('tmux -V', { reject: true });
      spinner.succeed('tmux is installed (Terminal Mirroring available)');
    } catch {
      spinner.text = 'tmux not found. Attempting to install...';
      if (osInfo.isLinux) {
        if (fs.existsSync('/usr/bin/apt') || fs.existsSync('/usr/bin/apt-get')) {
          await execaCommand('sudo apt-get update && sudo apt-get install -y tmux', { shell: true, stdio: 'inherit' });
        } else if (fs.existsSync('/usr/bin/dnf')) {
          await execaCommand('sudo dnf install -y tmux', { shell: true, stdio: 'inherit' });
        } else if (fs.existsSync('/usr/bin/yum')) {
          await execaCommand('sudo yum install -y tmux', { shell: true, stdio: 'inherit' });
        } else if (fs.existsSync('/usr/bin/pacman')) {
          await execaCommand('sudo pacman -S --noconfirm tmux', { shell: true, stdio: 'inherit' });
        } else if (fs.existsSync('/sbin/apk')) {
          await execaCommand('sudo apk add tmux', { shell: true, stdio: 'inherit' });
        } else {
          throw new Error('Unsupported Linux package manager');
        }
        spinner.succeed('tmux installed successfully (Terminal Mirroring available)');
      } else if (osInfo.isMac) {
        try {
          await execaCommand('brew install tmux', { shell: true, stdio: 'inherit' });
          spinner.succeed('tmux installed successfully (Terminal Mirroring available)');
        } catch {
          throw new Error('Homebrew is required to install tmux on macOS');
        }
      }

      function isSecureLinkSession(name) {
        return name === TMUX_SESSION_NAME || name.startsWith(TMUX_SESSION_PREFIX);
      }

      async function listTmuxSessions(socketArgs = []) {
        const result = await execa('tmux', [...socketArgs, 'list-sessions', '-F', '#{session_name}|#{session_created}'], { reject: false });
        if (result.exitCode !== 0) return [];
        return result.stdout
          .split(/\r?\n/)
          .filter(Boolean)
          .map(line => {
            const [name, createdAt] = line.split('|');
            return { name, createdAt: Number(createdAt) || null };
          });
      }

      async function getMirrorableSessions() {
        const sessions = [];
        const customSessions = await listTmuxSessions(tmuxSocketArgs());
        customSessions
          .filter(s => isSecureLinkSession(s.name))
          .forEach(s => sessions.push({ ...s, socketArgs: tmuxSocketArgs(), source: 'custom' }));

        const legacySessions = await listTmuxSessions();
        legacySessions
          .filter(s => isSecureLinkSession(s.name))
          .forEach(s => sessions.push({ ...s, socketArgs: [], source: 'legacy' }));

        return sessions;
      }
    }
  } catch (err) {
    spinner.fail(`tmux check/install failed: ${err.message}`);
    console.log(chalk.dim('  Terminal Mirroring feature will not be available.'));
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

async function injectPublicKey(pubKey) {
  const homedir = os.homedir();
  if (!homedir) {
    throw new Error('Could not resolve the current user home directory for authorized_keys');
  }

  const sshDir = path.join(homedir, '.ssh');

  if (!fs.existsSync(sshDir)) {
    await fs.promises.mkdir(sshDir, { mode: 0o700, recursive: true });
  }

  const authKeysPath = path.join(sshDir, 'authorized_keys');
  await fs.promises.appendFile(authKeysPath, `\n${pubKey}\n`);
  return authKeysPath;
}

async function removePublicKey(authKeysPath, pubKey) {
  if (fs.existsSync(authKeysPath)) {
    let keys = await fs.promises.readFile(authKeysPath, 'utf8');
    keys = keys.replace(`\n${pubKey}\n`, '');
    await fs.promises.writeFile(authKeysPath, keys);
  }
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
  const { default: open } = await import('open');
  const app = express();
  const startedAt = new Date().toISOString();

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

  // Server-Sent Events for live telemetry & approvals
  app.get('/api/events', async (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.flushHeaders?.();

    let closed = false;
    const push = async () => {
      if (closed) return;
      try {
        const data = await fetchApprovalRequests(BROKER_URL, uid, sessionState.hostToken).catch(() => ({ approvals: [] }));
        res.write(`event: approvals\n`);
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      } catch { }
    };

    const iv = setInterval(push, 5000);
    req.on('close', () => { clearInterval(iv); closed = true; });
    // send initial payload
    await push();
  });

  app.get('/api/clients', async (_req, res) => {
    try {
      const brokerRes = await fetch(`${BROKER_URL}/clients/${uid}`, {
        headers: sessionState.hostToken ? { 'x-host-token': sessionState.hostToken } : {}
      });
      if (!brokerRes.ok) {
        const data = await brokerRes.json().catch(() => ({}));
        return res.status(brokerRes.status).json({ error: data.error || 'Failed to fetch clients' });
      }
      const data = await brokerRes.json();
      const clients = (data.clients || []).map((clientBlob) => {
        try {
          const decrypted = decrypt(clientBlob.iv, clientBlob.ciphertext, password, clientBlob.salt);
          const t = JSON.parse(decrypted);
          return { ...t, seenAt: clientBlob.seenAt || null };
        } catch {
          return { error: 'decrypt_failed', seenAt: clientBlob.seenAt || null };
        }
      });
      res.json({ clients });
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
      await decideApprovalRequest(BROKER_URL, uid, requestId, decision, sessionState.hostToken);
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
  <div><h1>🛡️ iPingYou Host Dashboard</h1><span style="color:var(--dim);font-size:0.85rem">UID: <code>${uid}</code></span></div>
  <div style="display:flex;gap:1rem;align-items:center">
    <span class="badge">● LIVE</span>
    <button class="btn btn-revoke" onclick="revokeSession()">🚫 Revoke Session</button>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>📊 Session Info</h2>
    <div class="info-row"><span class="info-label">UID</span><span class="info-value"><code>${uid}</code></span></div>
    <div class="info-row"><span class="info-label">Password</span><span class="info-value"><code>[Hidden — see terminal]</code></span></div>
    <div class="info-row"><span class="info-label">Service</span><span class="info-value">${serviceConfig.type.toUpperCase()} on port ${serviceConfig.port}</span></div>
    <div class="info-row"><span class="info-label">Approval Gate</span><span class="info-value">${serviceConfig.approvalRequired ? '<span style="color:var(--green)">✓ Enabled</span>' : '<span style="color:var(--dim)">Disabled</span>'}</span></div>
    <div class="info-row"><span class="info-label">Drop Folder</span><span class="info-value"><code>${serviceConfig.sharedDropPath || 'none'}</code></span></div>
    <div class="info-row"><span class="info-label">One-Time Share</span><span class="info-value"><code>${serviceConfig.oneTimeSharePath || 'none'}</code></span></div>
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

<script>
const startedAt = new Date("${startedAt}");

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}
 
function escapeHtml(value) {
 return String(value || '').replace(/[&<>"']/g, (m) => ({
   '&': '&amp;',
   '<': '&lt;',
   '>': '&gt;',
   '"': '&quot;',
   "'": '&#39;',
 })[m]);
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
es.addEventListener('approvals', (e) => {
  try {
    const data = JSON.parse(e.data);
    renderApprovals(data.approvals || []);
  } catch {}
});

function renderApprovals(approvals) {
  const container = document.getElementById('approvals');
  const pending = approvals.filter(a => a.status === 'pending');
  const decided = approvals.filter(a => a.status !== 'pending').slice(-5);
  document.getElementById('approval-count').textContent = pending.length > 0 ? '(' + pending.length + ' pending)' : '';

  if (approvals.length === 0) {
    container.innerHTML = '<p class="empty">No approval requests yet</p>';
    return;
  }

  let html = '';
  for (const req of pending) {
    html += '<div class="approval-item">'
      + '<div style="display:flex;justify-content:space-between;align-items:center">'
      + '<strong>Request ' + req.id + '</strong>'
      + '<span class="status-badge status-pending">PENDING</span></div>'
      + '<div class="meta">Submitted: ' + new Date(req.createdAt).toLocaleTimeString() + '</div>'
      + '<div class="actions">'
      + '<button class="btn btn-approve" data-id="' + req.id + '" data-decision="approved">✅ Approve</button>'
      + '<button class="btn btn-deny" data-id="' + req.id + '" data-decision="denied">❌ Deny</button>'
      + '</div></div>';
  }
  for (const req of decided) {
    const cls = req.status === 'approved' ? 'status-approved' : 'status-denied';
    html += '<div class="approval-item" style="opacity:0.6">'
      + '<div style="display:flex;justify-content:space-between;align-items:center">'
      + '<strong>Request ' + req.id + '</strong>'
      + '<span class="status-badge ' + cls + '">' + req.status.toUpperCase() + '</span></div>'
      + '<div class="meta">Decided: ' + (req.decidedAt ? new Date(req.decidedAt).toLocaleTimeString() : 'N/A') + '</div>'
      + '</div>';
  }
  container.innerHTML = html;

  // Attach click handlers via event delegation (avoids inline quote escaping issues)
  container.querySelectorAll('[data-decision]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      decide(btn.getAttribute('data-id'), btn.getAttribute('data-decision'));
    });
  });
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

// Poll client telemetry (separate from SSE for simplicity)
async function pollClients() {
  try {
    const res = await fetch('/api/clients');
    if (!res.ok) return;
    const data = await res.json();
    renderClients(data.clients || []);
  } catch {}
}
 
function renderClients(clients) {
  const container = document.getElementById('clients');
  if (!clients || clients.length === 0) {
    container.innerHTML = '<p class="empty">No clients connected yet</p>';
    document.getElementById('client-count').textContent = '';
    return;
  }
 
  document.getElementById('client-count').textContent = '(' + clients.length + ' connected)';
  let html = '';
  clients.forEach((c, idx) => {
    if (c.error) {
      html += '<div class="client-card"><strong>Client #' + (idx + 1) + '</strong> — payload decryption failed</div>';
      return;
    }
    const when = c.time || (c.seenAt ? new Date(c.seenAt).toLocaleTimeString() : 'Unknown');
    html += '<div class="client-card">'
      + '<strong>' + escapeHtml(c.username || 'Unknown') + '</strong>'
      + ' — ' + escapeHtml(c.action || 'connected') + '<br>'
      + '<span class="meta">IP: ' + escapeHtml(c.ip || 'Unknown') + '</span><br>'
      + '<span class="meta">OS: ' + escapeHtml(c.os || 'Unknown') + '</span><br>'
      + '<span class="meta">CPU: ' + escapeHtml(c.cpu || 'Unknown') + '</span><br>'
      + '<span class="meta">RAM: ' + escapeHtml(c.ram || 'Unknown') + '</span><br>'
      + '<span class="meta">Time: ' + escapeHtml(when) + '</span>'
      + '</div>';
  });
  container.innerHTML = html;
}
 
setInterval(pollClients, 5000);
pollClients();
</script>
</body></html>`);
 });

  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', async () => {
      const port = server.address().port;
      const url = `http://127.0.0.1:${port}`;
      console.log(chalk.green(`  ✓ Local dashboard: ${url}`));
      try { await open(url); } catch { }
      resolve({ url, close: () => server.close() });
    });
  });
}

/**
 * Auto-spawn a Private Broker locally and wrap it in a Cloudflare tunnel.
 */
async function spawnPrivateBroker() {
  console.log(chalk.yellow('\n  ⚠️  Public Broker is unreachable. Spawning Private Broker...'));

  // 1. Spawn the broker server process
  const brokerProcess = execa('node', [path.join(__dirname, '../server.js')], {
    env: { ...process.env, PORT: '4040' },
    reject: false,
    all: true,
  });
  trackPID(brokerProcess.pid);

  let brokerExited = false;
  let brokerOutput = '';
  brokerProcess.all?.on('data', chunk => {
    brokerOutput += chunk.toString();
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
      throw new Error(`Private broker exited before tunnel was ready${brokerOutput ? `: ${brokerOutput.trim()}` : ''}`);
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
    console.clear();
    console.log('');
    console.log(chalk.bold('  ╔════════════════════════════════════════════════════╗'));
    console.log(chalk.bold('  ║         🛡️  SecureLink — HOST MODE ACTIVE          ║'));
    console.log(chalk.bold('  ╠════════════════════════════════════════════════════╣'));
    console.log(`  ║  ${chalk.cyan('UID:')}        ${chalk.bold.white(uid.padEnd(30))}║`);
    console.log(`  ║  ${chalk.cyan('Password:')}   ${chalk.bold.white(password.padEnd(30))}║`);
    console.log(`  ║  ${chalk.cyan('Service:')}    ${chalk.dim(serviceConfig.type.toUpperCase() + ' (Port ' + serviceConfig.port + ')').padEnd(30)}║`);
    console.log(`  ║  ${chalk.cyan('Tunnel:')}     ${chalk.dim(sessionState.tunnelUrl.substring(0, 40))}  ║`);
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
        { name: '📡 See detailed client telemetry', value: 'show' },
        { name: '📺 Mirror Client Terminal (requires tmux)', value: 'mirror' },
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
        case 'approvals': {
          try {
            const data = await fetchApprovalRequests(BROKER_URL, uid, sessionState.hostToken);
            const pending = (data.approvals || []).filter(item => item.status === 'pending');
            if (pending.length === 0) {
              console.log(chalk.yellow('  No pending approval requests.'));
              return waitForAction();
            }

            for (const request of pending) {
              let details = {};
              try {
                details = JSON.parse(decrypt(request.iv, request.ciphertext, password, request.salt));
              } catch {
                details = { error: 'Could not decrypt request metadata' };
              }
              console.log('');
              console.log(chalk.bold.cyan(`  Approval Request ${request.id}`));
              console.log(`    User:   ${details.username || 'unknown'}`);
              console.log(`    Host:   ${details.hostname || 'unknown'}`);
              console.log(`    OS:     ${details.os || 'unknown'}`);
              console.log(`    Intent: ${details.intent || 'connect'}`);

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
                await decideApprovalRequest(BROKER_URL, uid, request.id, decision, sessionState.hostToken);
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

        case 'mirror': {
          console.log('');
          console.log(chalk.bold.cyan('  📺 Terminal Mirroring'));
          console.log(chalk.dim('  ──────────────────────────────────────'));
          console.log(chalk.dim('  Attaching to the tmux session created by an interactive SSH client.'));
          console.log(chalk.dim('  Press Ctrl+b then d to detach gracefully.'));
          console.log('');

          try {
            await execaCommand('tmux -V', { reject: true });
            const sessions = await getMirrorableSessions();
            if (sessions.length === 0) {
              console.log(chalk.yellow('  ⚠️  No mirrored terminal session is active yet.'));
              console.log(chalk.dim('     A client must choose "Connect via SSH" first. SCP-only clients do not create a tmux session.'));
              console.log(chalk.dim('     tmux is needed on the host machine only; the client does not need tmux.'));
              logSessionEvent('host_mirror_missing_session', {}, 'warn');
              return waitForAction();
            }

            let target = sessions[0];
            if (sessions.length > 1) {
              const { sessionChoice } = await inquirer.prompt([{
                type: 'list',
                name: 'sessionChoice',
                message: 'Select an active client session to mirror:',
                choices: sessions.map((s, idx) => {
                  const created = s.createdAt ? new Date(s.createdAt * 1000).toLocaleTimeString() : 'Unknown';
                  const label = `${s.name} ${chalk.dim(`(started ${created})`)}`;
                  return { name: label, value: String(idx) };
                }),
              }]);
              target = sessions[parseInt(sessionChoice, 10)] || sessions[0];
            }

            await execa('tmux', [...target.socketArgs, 'attach', '-t', target.name, '-r'], { stdio: 'inherit', reject: false });
            logSessionEvent('host_mirror_attached', { session: target.name, source: target.source });
          } catch (err) {
            console.log(chalk.yellow('  ⚠️  Could not attach to tmux.'));
            console.log(chalk.dim(`     ${err.message}`));
            console.log(chalk.dim('     Terminal mirroring requires tmux on the host machine and an active interactive SSH client.'));
            logSessionEvent('host_mirror_error', { error: err.message }, 'warn');
          }
          return waitForAction();
        }

        case 'show': {
          const spinner = createSpinner('Fetching secure client telemetry...', networkSpinner).start();
          try {
            const res = await fetch(`${BROKER_URL}/clients/${uid}`, {
              headers: sessionState.hostToken ? { 'x-host-token': sessionState.hostToken } : {}
            });
            if (!res.ok) throw new Error('Failed to fetch from broker');
            const data = await res.json();

            if (!data.clients || data.clients.length === 0) {
              spinner.warn('No clients have successfully connected and sent telemetry yet.');
            } else {
              spinner.succeed(`Found ${data.clients.length} recent connection(s):`);

              data.clients.forEach((clientBlob, i) => {
                try {
                  // Decrypt using the unique salt the client generated for this payload
                  const decrypted = decrypt(clientBlob.iv, clientBlob.ciphertext, password, clientBlob.salt);
                  const t = JSON.parse(decrypted);

                  console.log(chalk.bold.blue(`\n  Client #${i + 1} (${t.username})`));
                  console.log(`    IP:       ${chalk.white(t.ip)}`);
                  console.log(`    OS:       ${chalk.dim(t.os)}`);
                  console.log(`    CPU:      ${chalk.dim(t.cpu)}`);
                  console.log(`    RAM:      ${chalk.dim(t.ram)}`);
                  console.log(`    Action:   ${chalk.yellow(t.action || 'connected')}`);
                  console.log(`    Time:     ${chalk.dim(t.time)}`);
                } catch (e) {
                  console.log(chalk.yellow(`\n  Client #${i + 1}: Payload decryption failed (wrong password or corrupted).`));
                  logSessionEvent('host_telemetry_decrypt_failed', { index: i + 1 }, 'warn');
                }
              });
            }
          } catch (e) {
            spinner.fail('Could not reach broker.');
            logSessionEvent('host_telemetry_fetch_failed', { error: e.message }, 'warn');
          }
          console.log('');
          return waitForAction();
        }

        case 'reregister':
          const res = await registerWithBroker(BROKER_URL, uid, sessionState.tunnelUrl, password, serviceConfig);
          if (res.success && res.hostToken) sessionState.hostToken = res.hostToken;
          logSessionEvent('host_broker_reregistered');
          return waitForAction();

        case 'terminate': {
          const spinner = createSpinner('Terminating active SSH sessions...', networkSpinner).start();
          try {
            if (process.platform === 'win32') {
              await execaCommand('powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"name = \'sshd.exe\'\\" | Where-Object { $_.CommandLine -match \'sshd:.*@\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"', { reject: false });
            } else {
              await execaCommand("pkill -f 'sshd:.*@'", { shell: true, reject: false });
              await execa('tmux', [...tmuxSocketArgs(), 'kill-server'], { reject: false });
              const legacySessions = await listTmuxSessions();
              for (const session of legacySessions) {
                if (isSecureLinkSession(session.name)) {
                  await execa('tmux', ['kill-session', '-t', session.name], { reject: false });
                }
              }
            }
            spinner.succeed('All client SSH sessions terminated');
            logSessionEvent('host_sessions_terminated');
          } catch {
            spinner.warn('Could not terminate sessions (none active?)');
            logSessionEvent('host_sessions_terminate_failed', {}, 'warn');
          }
          return waitForAction();
        }

        case 'exit':
          if (dashboardInstance) dashboardInstance.close();
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
export async function startHostMode() {
  console.log('');
  console.log(chalk.bold.cyan('  🔒 HOST MODE — Allow Remote Access'));
  console.log(chalk.dim('  ─────────────────────────────────────'));
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
  console.log(`  ${chalk.green('✓')} Password: ${chalk.bold.white(password)}`);
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
  const targetUrl = `${protocol}://localhost:${targetPort}`;
  logSessionEvent('host_service_selected', { serviceType, protocol, port: targetPort });

  if (serviceType === 'ssh' || serviceType === 'share') {
    await ensureSSHRunning();
    await ensureTmuxInstalled();

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
    try {
      const ephemeralKey = await generateEphemeralKey();
      const authKeysPath = await injectPublicKey(ephemeralKey.pubKey);

      serviceConfig.privateKey = ephemeralKey.privKey;

      addCleanupHook(async () => {
        console.log(chalk.dim('     Removing ephemeral public key...'));
        await removePublicKey(authKeysPath, ephemeralKey.pubKey);
        try { await fs.promises.unlink(ephemeralKey.keyPath); } catch { }
        try { await fs.promises.unlink(`${ephemeralKey.keyPath}.pub`); } catch { }
      });
      console.log(chalk.green('  ✓ Ephemeral key injected. Client will connect without system password!'));
      logSessionEvent('host_ephemeral_key_ready');
    } catch (err) {
      console.log(chalk.yellow(`  ⚠️  Could not prepare ephemeral SSH key: ${err.message}`));
      console.log(chalk.dim('     Client will need to use standard OS password.'));
      logSessionEvent('host_ephemeral_key_failed', { error: err.message }, 'warn');
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
