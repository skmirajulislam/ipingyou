/**
 * ============================================================
 *  Graceful Cleanup & Process Killer
 * ============================================================
 *  Tracks all spawned child processes (cloudflared, ssh, etc.)
 *  and kills them on SIGINT/exit using tree-kill to ensure
 *  no orphan processes linger.
 * ============================================================
 */

import treeKill from 'tree-kill';
import chalk from 'chalk';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execaCommand } from 'execa';

/** @type {Set<number>} — Active child PIDs we manage */
const trackedPIDs = new Set();

/** @type {string|null} — UID to revoke on shutdown */
let _revokeUID = null;

/** @type {string|null} — Broker URL for revocation */
let _brokerUrl = null;

/** @type {(() => string|null)|null} — Getter for host auth token */
let _getHostToken = null;

/** @type {Array<() => Promise<void>|void>} — Custom cleanup hooks */
const _cleanupHooks = [];
let cleanedUp = false;

/**
 * Register a custom cleanup hook to run on shutdown.
 * @param {() => Promise<void>|void} hook
 */
export function addCleanupHook(hook) {
  _cleanupHooks.push(hook);
}

/**
 * Register a spawned child PID for tracking.
 * @param {number} pid
 */
export function trackPID(pid) {
  if (pid) trackedPIDs.add(pid);
}

/**
 * Unregister a PID (after it exits naturally).
 * @param {number} pid
 */
export function untrackPID(pid) {
  trackedPIDs.delete(pid);
}

/**
 * Set UID + broker URL for automatic revocation on shutdown.
 * @param {string} uid
 * @param {string} brokerUrl
 * @param {() => string|null} [getHostToken]
 */
export function setRevokeOnExit(uid, brokerUrl, getHostToken = null) {
  _revokeUID = uid;
  _brokerUrl = brokerUrl;
  _getHostToken = getHostToken;
}

/**
 * Kill a single PID tree.
 * @param {number} pid
 * @returns {Promise<void>}
 */
export function killProcessTree(pid, signal = 'SIGTERM') {
  return new Promise((resolve) => {
    treeKill(pid, signal, (err) => {
      if (err) {
        treeKill(pid, 'SIGKILL', () => resolve());
      } else {
        resolve();
      }
    });
  });
}

/**
 * Kill all tracked PIDs and revoke UID from broker.
 */
export async function cleanupAll() {
  if (cleanedUp) return;
  cleanedUp = true;

  console.log('');
  console.log(chalk.yellow('  🧹 Cleaning up...'));

  // Kill all tracked processes
  const kills = [];
  for (const pid of trackedPIDs) {
    console.log(chalk.dim(`     Killing PID ${pid}...`));
    kills.push(killProcessTree(pid));
  }
  await Promise.allSettled(kills);
  trackedPIDs.clear();

  // Run custom cleanup hooks
  for (const hook of _cleanupHooks) {
    try {
      await hook();
    } catch (err) {
      console.error(chalk.red(`     Cleanup hook failed: ${err.message}`));
    }
  }

  // Revoke UID from broker
  if (_revokeUID && _brokerUrl) {
    try {
      const headers = {};
      const token = _getHostToken ? _getHostToken() : null;
      if (token) headers['x-host-token'] = token;
      
      const res = await fetch(`${_brokerUrl}/revoke/${_revokeUID}`, { 
        method: 'DELETE',
        headers 
      });
      if (res.ok) {
        console.log(chalk.dim(`     Revoked UID ${_revokeUID} from broker`));
      }
    } catch {
      // Best-effort — broker might be down
    }
  }

  console.log(chalk.green('  ✅ Cleanup complete. Goodbye!'));
  console.log('');
}

/**
 * Install SIGINT/SIGTERM handlers for graceful shutdown.
 */
export function installShutdownHandlers() {
  let shuttingDown = false;

  const handler = async (signal) => {
    if (shuttingDown) return; // Prevent double-cleanup
    shuttingDown = true;
    console.log('');
    console.log(chalk.yellow(`  ⚡ Received ${signal}`));
    await cleanupAll();
    process.exit(0);
  };

  process.on('SIGINT', () => handler('SIGINT'));
  process.on('SIGTERM', () => handler('SIGTERM'));

  // Also handle uncaught exceptions gracefully
  process.on('uncaughtException', async (err) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(chalk.red(`  💥 Uncaught exception: ${err.message}`));
    await cleanupAll();
    process.exit(1);
  });

  process.on('unhandledRejection', async (reason) => {
    if (shuttingDown) return;
    shuttingDown = true;
    const err = reason instanceof Error ? reason : new Error(String(reason));
    console.error(chalk.red(`  💥 Unhandled rejection: ${err.message}`));
    await cleanupAll();
    process.exit(1);
  });
}

/**
 * Get count of tracked PIDs.
 * @returns {number}
 */
/**
 * Execute Panic Mode (Self-Destruct)
 * Wipes all configs, keys, and forcefully kills associated processes.
 */
export async function executePanicMode() {
  console.log(chalk.bold.red('\n  🚨 INITIATING SECURELINK PANIC MODE 🚨\n'));
  
  // 1. Force kill all cloudflared & ipingyou processes
  console.log(chalk.dim('  [1/4] Terminating all tunnel and host processes...'));
  try {
    if (process.platform === 'win32') {
      await execaCommand('taskkill /F /IM cloudflared.exe', { reject: false });
    } else {
      await execaCommand('pkill -9 -f cloudflared', { reject: false });
      await execaCommand('pkill -9 -f "sshd:.*@"', { reject: false });
      await execaCommand('tmux kill-session -t SecureLink_Session', { reject: false });
    }
  } catch {}

  // 2. Delete configuration and aliases
  console.log(chalk.dim('  [2/4] Wiping configuration files...'));
  const configPath = path.join(os.homedir(), '.ipingyou', 'config.json');
  try {
    if (fs.existsSync(configPath)) {
      fs.unlinkSync(configPath);
    }
    const configDir = path.join(os.homedir(), '.ipingyou');
    if (fs.existsSync(configDir)) {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
  } catch {}

  // 3. Delete ephemeral keys and temp files
  console.log(chalk.dim('  [3/4] Purging ephemeral keys and temporary files...'));
  try {
    const tmpDir = os.tmpdir();
    const files = fs.readdirSync(tmpDir);
    for (const file of files) {
      if (file.startsWith('ipingyou_') || file.startsWith('ipingyou-')) {
        fs.unlinkSync(path.join(tmpDir, file));
      }
    }
  } catch {}

  console.log(chalk.dim('  [4/4] Scrubbing injected SSH keys...'));
  try {
    const authKeysPath = path.join(os.homedir(), '.ssh', 'authorized_keys');
    if (fs.existsSync(authKeysPath)) {
      const current = fs.readFileSync(authKeysPath, 'utf8');
      const cleaned = current
        .split(/\r?\n/)
        .filter(line => !line.includes('ipingyou-ephemeral'))
        .join('\n')
        .replace(/\n{3,}/g, '\n\n');
      if (cleaned !== current) fs.writeFileSync(authKeysPath, cleaned);
    }
  } catch {}

  console.log(chalk.bold.green('\n  ✅ Panic Mode Complete. All traces removed.\n'));
  process.exit(0);
}
