/**
 * ============================================================
 *  Graceful Cleanup & Process Killer
 * ============================================================
 *  Tracks all spawned child processes (cloudflared, ssh, etc.)
 *  and kills them on SIGINT/exit to ensure
 *  no orphan processes linger.
 * ============================================================
 */

import chalk from 'chalk';
import { execa } from 'execa';

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
  return killProcessTreeSafely(pid, signal);
}

async function killProcessTreeSafely(pid, signal = 'SIGKILL') {
  const rootPid = Number.parseInt(pid, 10);
  if (!Number.isSafeInteger(rootPid) || rootPid <= 0 || rootPid === process.pid) {
    return;
  }

  if (process.platform === 'win32') {
    await execa('taskkill', ['/PID', String(rootPid), '/T', '/F'], {
      reject: false,
      timeout: 1000,
      maxBuffer: 64 * 1024,
    }).catch(() => {});
    return;
  }

  // Instant POSIX process group termination
  try { process.kill(-rootPid, 'SIGKILL'); } catch {}
  try { process.kill(rootPid, 'SIGKILL'); } catch {}
}

/**
 * Kill all tracked PIDs and revoke UID from broker.
 */
export async function cleanupAll() {
  if (cleanedUp) return;
  cleanedUp = true;

  console.log('');
  console.log(chalk.yellow('  🧹 Cleaning up...'));

  // Kill all tracked processes in parallel
  const kills = [];
  for (const pid of trackedPIDs) {
    console.log(chalk.dim(`     Releasing network ports & killing PID ${pid}...`));
    kills.push(killProcessTree(pid));
  }
  await Promise.allSettled(kills);
  trackedPIDs.clear();

  // Run custom cleanup hooks
  for (const hook of _cleanupHooks) {
    try {
      await hook();
    } catch {}
  }

  // Revoke UID from broker with strict 400ms network timeout
  if (_revokeUID && _brokerUrl) {
    try {
      const headers = {};
      const token = _getHostToken ? _getHostToken() : null;
      if (token) headers['x-host-token'] = token;
      
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 400);

      const res = await fetch(`${_brokerUrl}/revoke/${_revokeUID}`, { 
        method: 'DELETE',
        headers,
        signal: controller.signal
      }).catch(() => null);
      clearTimeout(timeout);

      if (res && res.ok) {
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

import { performPanicWipe } from './panic-wipe.js';

/**
 * Execute a complete emergency self-destruct & trace wipe.
 * Kills all active session processes, revokes broker UID, and wipes
 * all associated ipingyou system files, logs, caches, dropboxes, and SSH keys,
 * while preserving cloudflared and ssh binaries.
 */
export async function executePanicMode() {
  console.log(chalk.bold.red('\n  🚨 INITIATING EMERGENCY SHUTDOWN & TRACE WIPE 🚨\n'));
  await cleanupAll();
  await performPanicWipe();
  console.log(chalk.bold.green('  ✅ iPingYou session stopped and all system traces wiped safely.\n'));
}

