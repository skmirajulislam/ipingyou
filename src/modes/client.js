/**
 * ============================================================
 *  Client Mode — "Access a Remote Machine"
 * ============================================================
 *  1. Prompt for the remote host's UID
 *  2. Resolve UID → ENCRYPTED blob from the Broker
 *  3. DECRYPT tunnel URL locally using shared key
 *  4. Execute SSH/SCP through the Cloudflare tunnel proxy
 *
 *  Security: The broker only returns { iv, ciphertext }.
 *  Decryption happens ONLY on this machine.
 * ============================================================
 */

import { execa } from 'execa';
import chalk from 'chalk';
import inquirer from 'inquirer';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { cleanupAll, trackPID, untrackPID, addCleanupHook } from '../lib/mod/cleanup.js';
import { createSpinner, sshSpinner, networkSpinner, fileTransferSpinner, showConnectionTrace, simulateTransferProgress } from '../lib/mod/animations.js';
import { getConfig, saveAlias } from '../lib/mod/config.js';
import { validateUID } from '../lib/mod/uid.js';
import { pushTelemetry, requestHostApproval, resolveUID, revokeUID, waitForApproval, checkUidStatus } from '../lib/client/broker.js';
import { calculateChecksum } from '../lib/mod/checksum.js';
import { promptLocalPath, promptRemotePath } from '../lib/client/path-browser.js';
import { buildProxyCommandOption, buildSshArgs, extractHostname, formatScpRemotePath, getKeyOnlyAuthOptions, getKnownHostsOptions, getSshControlOptions, quoteRemoteShell } from '../lib/services/ssh.js';
import { openUrl } from '../lib/mod/open-url.js';
import { secureSensitiveUrl } from '../lib/mod/secure-print.js';
import { cleanupSessionLog, initSessionLog, logSessionEvent, recordEvent } from '../lib/mod/session-log.js';

let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

function startLiveLogSync(username, hostname, privateKeyPath, remoteDropPath, localLogPath, persistKnownHosts = true) {
  if (!remoteDropPath || !localLogPath) return;

  let lastSize = -1;
  let lastMtime = 0;
  let isSyncing = false;
  let consecutiveFailures = 0;
  let warnedOnce = false;
  const interval = setInterval(async () => {
    if (isSyncing) return;
    isSyncing = true;
    try {
      if (!fs.existsSync(localLogPath)) return;
      const stats = fs.statSync(localLogPath);
      if (stats.size === lastSize && stats.mtimeMs === lastMtime) return;

      const scpArgs = [
        '-O',
        ...buildProxyCommandOption(hostname),
        ...getKnownHostsOptions(persistKnownHosts),
        '-o', 'IdentitiesOnly=yes',
        ...getSshControlOptions(hostname)
      ];
      if (privateKeyPath) {
        scpArgs.push('-i', privateKeyPath, '-o', 'IdentityAgent=none', ...getKeyOnlyAuthOptions());
      }

      const clientName = `${os.userInfo().username}-${os.hostname()}`;
      const remoteFilePath = `${remoteDropPath}/client-${clientName}.log`;

      scpArgs.push(localLogPath, `${username}@${hostname}:${formatScpRemotePath(remoteFilePath)}`);

      const result = await execa('scp', scpArgs, { reject: false });
      if (result.exitCode === 0) {
        lastSize = stats.size;
        lastMtime = stats.mtimeMs;
        consecutiveFailures = 0;
      } else {
        consecutiveFailures++;
        if (consecutiveFailures >= 5 && !warnedOnce) {
          warnedOnce = true;
          logSessionEvent('client_log_sync_failing', { failures: consecutiveFailures, stderr: (result.stderr || '').slice(0, 200) }, 'warn');
        }
      }
    } catch {
      consecutiveFailures++;
    } finally {
      isSyncing = false;
    }
  }, 3000);

  addCleanupHook(() => clearInterval(interval));
}

async function promptUsername() {
  const { username } = await inquirer.prompt([
    {
      type: 'input',
      name: 'username',
      message: 'SSH username on the remote machine:',
      default: process.env.USER || process.env.USERNAME || 'root',
      validate: (v) => v.trim().length > 0 || 'Username is required',
    },
  ]);
  return username.trim();
}

async function resolveSshUsername(payload, targetUsername) {
  const keyUsername = String(payload?.sshUsername || '').trim();

  if (payload?.privateKey && keyUsername) {
    if (targetUsername && targetUsername !== keyUsername) {
      console.log(chalk.yellow(`  ⚠️  Saved alias username "${targetUsername}" does not match the host-provided key user "${keyUsername}".`));
      console.log(chalk.dim(`     Using "${keyUsername}" so passwordless SSH can work.`));
      logSessionEvent('client_alias_username_overridden_for_key', { aliasUsername: targetUsername, keyUsername }, 'warn');
    } else {
      console.log(chalk.dim(`  🔑 Using host-provided SSH username for passwordless entry: ${keyUsername}`));
    }
    return keyUsername;
  }

  if (targetUsername) return targetUsername;
  return promptUsername();
}

function normalizePrivateKey(privateKey) {
  const normalized = String(privateKey || '').replace(/\\n/g, '\n').replace(/\r\n/g, '\n');
  return normalized.endsWith('\n') ? normalized : `${normalized}\n`;
}

async function writeEphemeralPrivateKey(privateKey) {
  const keyPath = path.join(os.tmpdir(), `ipingyou_client_${crypto.randomBytes(8).toString('hex')}`);
  fs.writeFileSync(keyPath, normalizePrivateKey(privateKey), { mode: 0o600 });
  addCleanupHook(() => {
    try { fs.unlinkSync(keyPath); } catch {}
  });

  // On Windows, NTFS ignores POSIX mode bits — fix ACLs with icacls
  if (process.platform === 'win32') {
    const currentUser = os.userInfo().username;
    // Remove all inherited permissions first
    await execa('icacls', [keyPath, '/inheritance:r'], { reject: false });
    // Grant only the current user full control
    await execa('icacls', [keyPath, '/grant:r', `${currentUser}:(F)`], { reject: false });
  }

  const result = await execa('ssh-keygen', ['-y', '-f', keyPath], {
    reject: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (result.exitCode !== 0) {
    try { fs.unlinkSync(keyPath); } catch { }
    throw new Error(result.stderr.trim() || 'OpenSSH could not parse the host-provided private key');
  }

  return keyPath;
}

async function verifyEphemeralKeyAccess(username, hostname, privateKeyPath, persistKnownHosts = true) {
  if (!privateKeyPath) return;

  const sshArgs = buildSshArgs(hostname, privateKeyPath, [
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    `${username}@${hostname}`,
    'true',
  ], { persistKnownHosts, keyOnly: true, controlMaster: false });

  const result = await execa('ssh', sshArgs, {
    reject: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (result.exitCode !== 0) {
    const reason = (result.stderr || result.stdout || 'SSH server rejected the ephemeral key').trim();
    throw new Error(reason.split('\n').slice(-2).join(' ').slice(0, 500));
  }
}

/**
 * Start SSH connection through the Cloudflare tunnel.
 */
async function connectSSH(username, hostname, privateKeyPath, persistKnownHosts = true) {
  console.log('');
  console.log(chalk.bold('  🔗 Establishing SSH Connection'));
  console.log(chalk.dim('  ─────────────────────────────────'));

  await showConnectionTrace('Local', 'Remote SSH');

  let spinner = null;
  try {
    spinner = createSpinner(privateKeyPath ? 'Verifying passwordless key...' : 'Handshaking...', sshSpinner).start();
    if (privateKeyPath) {
      await verifyEphemeralKeyAccess(username, hostname, privateKeyPath, persistKnownHosts);
    } else {
      await new Promise(r => setTimeout(r, 800));
    }
    spinner.succeed('Connection established! Handing over to terminal...');
    console.log('');

    const authOptions = privateKeyPath ? getKeyOnlyAuthOptions() : [];
    const sshArgs = buildSshArgs(hostname, privateKeyPath, [
      ...authOptions,
      '-o', 'ServerAliveInterval=30',
      '-o', 'ServerAliveCountMax=3',
      '-t'
    ], { persistKnownHosts });

    sshArgs.push(`${username}@${hostname}`);

    const child = execa('ssh', sshArgs, {
      stdio: 'inherit',
      reject: false,
    });

    trackPID(child.pid);
    let result;
    try {
      result = await child;
    } finally {
      untrackPID(child.pid);
    }

    if (result.exitCode === 0) {
      console.log('');
      console.log(chalk.green('  ✅ SSH session ended cleanly'));
      recordEvent('ssh_session_ended', { hostname, exitCode: 0 });
    } else if (result.exitCode === 255) {
      console.log('');
      console.error(chalk.yellow('  ⚡ SSH connection dropped unexpectedly (network glitch).'));
      recordEvent('ssh_session_interrupted', { hostname, exitCode: 255 });

      const { autoRetry } = await inquirer.prompt([{
        type: 'confirm',
        name: 'autoRetry',
        message: 'Re-establish connection automatically (Auto-Reconnect window)?',
        default: true,
      }]);

      if (autoRetry) {
        console.log(chalk.cyan('  🔄 Retrying SSH connection...'));
        await new Promise(r => setTimeout(r, 2000));
        return connectSSH(username, hostname, privateKeyPath, persistKnownHosts);
      }
    } else {
      console.log('');
      console.error(chalk.red(`  ❌ SSH exited with code ${result.exitCode}`));
      recordEvent('ssh_session_ended', { hostname, exitCode: result.exitCode });
    }
  } catch (err) {
    if (spinner) spinner.fail(privateKeyPath ? 'Passwordless key verification failed' : 'SSH handshake failed');
    console.error(chalk.red(`  ❌ SSH error: ${err.message}`));
    if (privateKeyPath) {
      console.log('');
      console.log(chalk.yellow('  ⚠️ Ephemeral key authentication failed before opening the interactive shell.'));
      const { fallbackPassword } = await inquirer.prompt([{
        type: 'confirm',
        name: 'fallbackPassword',
        message: 'Would you like to fall back to password authentication?',
        default: true,
      }]);

      if (fallbackPassword) {
        const { altUsername } = await inquirer.prompt([{
          type: 'input',
          name: 'altUsername',
          message: 'Enter SSH Username:',
          default: username || os.userInfo().username,
        }]);
        return connectSSH(altUsername, hostname, null, persistKnownHosts);
      } else {
        console.log(chalk.red('  ❌ Connection aborted. Direct unauthenticated access is denied.'));
        recordEvent('ssh_key_auth_declined_fallback', { hostname });
        return;
      }
    }
  }
}

/**
 * Perform an SCP file transfer through the Cloudflare tunnel.
 */
async function chooseRemoteTransferPath(username, hostname, privateKeyPath, direction, sharedDropPath, persistKnownHosts = true) {
  if (!sharedDropPath) {
    return promptRemotePath(username, hostname, privateKeyPath, direction === 'upload' ? 'destination' : 'source', '~', { persistKnownHosts });
  }

  const { dropChoice } = await inquirer.prompt([{
    type: 'list',
    name: 'dropChoice',
    message: direction === 'upload'
      ? 'Where should the file/folder go on the host?'
      : 'Where should browsing start on the host?',
    choices: direction === 'upload'
      ? [
        { name: `📥 Use host shared drop folder (${sharedDropPath})`, value: 'drop' },
        { name: '🔍 Browse host folders', value: 'browse' },
        { name: '⌨️  Type host destination path manually', value: 'manual' }
      ]
      : [
        { name: `📥 Start in host shared drop folder (${sharedDropPath})`, value: 'drop_browse' },
        { name: '🔍 Browse from host home folder', value: 'browse' },
        { name: '⌨️  Type host file/folder path manually', value: 'manual' }
      ]
  }]);

  if (dropChoice === 'drop') return sharedDropPath;
  if (dropChoice === 'drop_browse') {
    return promptRemotePath(username, hostname, privateKeyPath, 'source', sharedDropPath, { persistKnownHosts });
  }
  if (dropChoice === 'manual') {
    const { remotePath } = await inquirer.prompt([{
      type: 'input',
      name: 'remotePath',
      message: direction === 'upload' ? 'Host destination path:' : 'Host file/folder path:',
      validate: v => v.trim().length > 0 || 'Required',
    }]);
    return remotePath.trim();
  }

  return promptRemotePath(username, hostname, privateKeyPath, direction === 'upload' ? 'destination' : 'source', '~', { persistKnownHosts });
}

async function performSCP(username, hostname, direction, privateKeyPath, sharedDropPath = null, persistKnownHosts = true) {
  console.log('');
  console.log(chalk.bold(`  📦 SCP Transfer (${direction})`));
  console.log(chalk.dim('  ─────────────────────────────────'));

  let localPath;
  let remotePath;

  if (direction === 'upload') {
    remotePath = await chooseRemoteTransferPath(username, hostname, privateKeyPath, direction, sharedDropPath, persistKnownHosts);
    localPath = await promptLocalPath('client file/folder to upload');
  } else {
    localPath = await promptLocalPath('client destination');
    remotePath = await chooseRemoteTransferPath(username, hostname, privateKeyPath, direction, sharedDropPath, persistKnownHosts);
  }

  await showConnectionTrace('Local', 'Remote SCP');

  // Construct SCP args
  const scpArgs = [
    '-r', // recursive just in case
    '-O', // Force legacy SCP protocol so that shell quoting in formatScpRemotePath works correctly
    ...buildProxyCommandOption(hostname),
    ...getKnownHostsOptions(persistKnownHosts),
    '-o', 'IdentitiesOnly=yes',
    ...getSshControlOptions(hostname)
  ];

  if (privateKeyPath) {
    scpArgs.push('-i', privateKeyPath, '-o', 'IdentityAgent=none', ...getKeyOnlyAuthOptions());
  }

  const remoteSpec = `${username}@${hostname}:${formatScpRemotePath(remotePath)}`;
  if (direction === 'upload') {
    scpArgs.push(localPath, remoteSpec);
  } else {
    // Download: remote source FIRST, then local destination
    scpArgs.push(remoteSpec, localPath);
  }

  let localHash = null;
  if (direction === 'upload') {
    console.log(chalk.dim('  🔍 Calculating local SHA-256 checksum...'));
    localHash = await calculateChecksum(localPath);
    if (localHash) console.log(chalk.dim(`     Hash: ${localHash.substring(0, 16)}...`));
  }

  try {
    const transferSpinner = createSpinner(`Transferring via SCP...`, fileTransferSpinner).start();

    const child = execa('scp', scpArgs, {
      stdio: ['inherit', 'pipe', 'pipe'],
      reject: false,
      buffer: false,
    });
    const maxDiagnosticBytes = 64 * 1024;
    let stderrOutput = Buffer.alloc(0);
    child.stdout?.resume();
    child.stderr?.on('data', (chunk) => {
      const next = Buffer.concat([stderrOutput, Buffer.from(chunk)]);
      stderrOutput = next.length > maxDiagnosticBytes
        ? next.subarray(next.length - maxDiagnosticBytes)
        : next;
    });

    trackPID(child.pid);
    let result;
    try {
      result = await child;
    } finally {
      untrackPID(child.pid);
    }

    transferSpinner.stop();

    if (result.exitCode === 0) {
      await simulateTransferProgress(direction === 'upload' ? localPath : remotePath, direction, 1500);

      // Verify Checksum
      if (direction === 'upload' && localHash) {
        console.log(chalk.dim('  🔍 Verifying remote SHA-256 checksum...'));
        try {
          const remoteChecksumPath = joinRemotePath(remotePath, path.basename(localPath));
          const sshArgs = buildSshArgs(hostname, privateKeyPath, [], { persistKnownHosts, keyOnly: Boolean(privateKeyPath) });
          sshArgs.push(`${username}@${hostname}`, `shasum -a 256 ${quoteRemoteShell(remoteChecksumPath)} 2>/dev/null || sha256sum ${quoteRemoteShell(remoteChecksumPath)} 2>/dev/null || shasum -a 256 ${quoteRemoteShell(remotePath)} 2>/dev/null || sha256sum ${quoteRemoteShell(remotePath)}`);

          const { stdout } = await execa('ssh', sshArgs, { reject: false });
          const remoteHash = stdout.split(' ')[0].trim();

          if (remoteHash === localHash) {
            console.log(chalk.green(`  ✅ Zero-Trust File Integrity: Hash match (${remoteHash.substring(0, 16)}...)`));
          } else {
            console.log(chalk.yellow(`  ⚠️ Warning: Remote checksum could not be verified automatically.`));
          }
        } catch {
          console.log(chalk.dim('     Could not run remote checksum validation.'));
        }
      } else if (direction === 'download') {
        console.log(chalk.dim('  🔍 Calculating downloaded SHA-256 checksum...'));
        const dlHash = await calculateChecksum(localPath);
        if (dlHash) console.log(chalk.green(`  ✅ File Intact. Hash: ${dlHash.substring(0, 16)}...`));
      }

      console.log(chalk.green(`  ✅ Transfer completed successfully!`));
      recordEvent('scp_transfer_success', { direction, localPath, remotePath, hostname });
    } else {
      const stderr = stderrOutput.toString('utf8');
      console.error(chalk.red('  ❌ SCP transfer failed'));
      if (stderr) console.error(chalk.dim(`     ${stderr.trim()}`));
      recordEvent('scp_transfer_failed', { direction, localPath, remotePath, hostname, error: stderr });
    }
  } catch (err) {
    console.error(chalk.red(`  ❌ SCP error: ${err.message}`));
  }
}

async function downloadSpecificRemotePath(username, hostname, privateKeyPath, remotePath, localPath, persistKnownHosts = true) {
  await showConnectionTrace('Local', 'Remote SCP');
  const scpArgs = [
    '-r',
    '-O', // Force legacy SCP protocol
    ...buildProxyCommandOption(hostname),
    ...getKnownHostsOptions(persistKnownHosts),
    '-o', 'IdentitiesOnly=yes',
    ...getSshControlOptions(hostname),
  ];
  if (privateKeyPath) scpArgs.push('-i', privateKeyPath, '-o', 'IdentityAgent=none', ...getKeyOnlyAuthOptions());
  scpArgs.push(`${username}@${hostname}:${formatScpRemotePath(remotePath)}`, localPath);
  const child = execa('scp', scpArgs, { stdio: 'inherit', reject: false });
  trackPID(child.pid);
  let result;
  try {
    result = await child;
  } finally {
    untrackPID(child.pid);
  }
  return result.exitCode === 0;
}

function joinRemotePath(parent, child) {
  const cleanParent = String(parent || '').replace(/\/+$/, '');
  if (!cleanParent) return child;
  if (cleanParent === '/') return `/${child}`;
  return `${cleanParent}/${child}`;
}

/**
 * Main Client Mode entry point.
 */
export async function startClientMode(options = {}) {
  console.log('');
  console.log(chalk.bold.cyan('  🌐 CLIENT MODE — Access a Remote Machine'));
  console.log(chalk.dim('  ──────────────────────────────────────────'));
  console.log('');

  const sessionLogPath = initSessionLog('client');
  if (sessionLogPath) {
    console.log(chalk.dim(`  📜 Session log: ${sessionLogPath}`));
    addCleanupHook(() => cleanupSessionLog());
  }
  logSessionEvent('client_mode_started');

  // Allow setting a custom broker URL if process.env isn't overridden by CLI
  if (process.env.BROKER_URL) {
    BROKER_URL = process.env.BROKER_URL;
  } else {
    const { brokerChoice } = await inquirer.prompt([
      {
        type: 'list',
        name: 'brokerChoice',
        message: 'Which Broker Server is the Host using?',
        choices: [
          { name: '🌍 Global Public Broker (Render) [Default]', value: 'global' },
          { name: '🔗 Custom Private Broker (URL)', value: 'custom' }
        ]
      }
    ]);
    if (brokerChoice === 'custom') {
      const { customBroker } = await inquirer.prompt([
        {
          type: 'input',
          name: 'customBroker',
          message: 'Enter the Private Broker URL provided by the host:',
          validate: v => v.trim().startsWith('http') || 'Must be a valid URL starting with http/https'
        }
      ]);
      BROKER_URL = customBroker.trim();
      process.env.BROKER_URL = BROKER_URL; // Update for consistency
    }
    logSessionEvent('client_broker_selected', { choice: brokerChoice, broker: BROKER_URL });
  }

  const config = getConfig();
  const aliasKeys = Object.keys(config.aliases || {});

  let targetUid = null;
  let targetPassword = null;
  let targetUsername = null;
  let persistKnownHosts = false;

  if (aliasKeys.length > 0) {
    const { useAlias } = await inquirer.prompt([
      {
        type: 'list',
        name: 'useAlias',
        message: 'Select a saved connection or enter manually:',
        choices: [
          ...aliasKeys.map(k => ({ name: `🔖 ${k} (${config.aliases[k].uid})`, value: k })),
          { name: '✍️  Enter UID manually', value: 'manual' }
        ]
      }
    ]);

    if (useAlias !== 'manual') {
      const aliasData = config.aliases[useAlias];
      targetUid = aliasData.uid;
      targetPassword = aliasData.password;
      targetUsername = aliasData.username;
      persistKnownHosts = true;
      logSessionEvent('client_alias_selected', { alias: useAlias, uid: targetUid });
    }
  }

  if (!targetUid && options.uid) {
    const uidCheck = validateUID(options.uid);
    if (uidCheck !== true) {
      console.log(chalk.red(`  ❌ Invalid UID: ${uidCheck}`));
      return;
    }
    targetUid = options.uid.trim();
    if (options.password) {
      targetPassword = String(options.password).trim();
    } else {
      const { password } = await inquirer.prompt([{
        type: 'password',
        name: 'password',
        message: 'Enter the session password:',
        validate: (v) => v.trim().length > 0 || 'Password is required to decrypt',
      }]);
      targetPassword = password.trim();
    }
    logSessionEvent('client_uid_provided', { uid: targetUid });
  }

  if (!targetUid) {
    const answer = await inquirer.prompt([
      {
        type: 'input',
        name: 'uid',
        message: 'Enter the remote host\'s UID:',
        validate: (v) => {
          return validateUID(v);
        },
      },
      {
        type: 'password',
        name: 'password',
        message: 'Enter the session password:',
        validate: (v) => v.trim().length > 0 || 'Password is required to decrypt',
      }
    ]);
    targetUid = answer.uid.trim();
    targetPassword = answer.password.trim();
    logSessionEvent('client_uid_provided', { uid: targetUid });
  }

  let payload = await resolveUID(BROKER_URL, targetUid, targetPassword);

  // ─── Approval Flow ──────────────────────────────────────────
  if (payload && payload.needsApproval) {
    console.log('');
    console.log(chalk.bold.yellow('  🔐 Host Approval Required'));
    console.log(chalk.dim('  ──────────────────────────────────────'));
    console.log(chalk.dim('  The host has enabled approval gating. Submitting your access request...'));

    try {
      let localIp = '127.0.0.1';
      try {
        const interfaces = os.networkInterfaces();
        for (const devName in interfaces) {
          const iface = interfaces[devName];
          for (const alias of iface) {
            if (alias.family === 'IPv4' && !alias.internal) {
              localIp = alias.address;
              break;
            }
          }
        }
      } catch {}

      const approvalDetails = {
        username: os.userInfo().username,
        hostname: os.hostname(),
        os: `${os.type()} ${os.release()} (${os.arch()})`,
        intent: 'connect',
        time: new Date().toISOString(),
        localIp,
      };

      const { requestId, status: reqStatus, approvalRequired } = await requestHostApproval(
        BROKER_URL, targetUid, targetPassword, approvalDetails
      );

      logSessionEvent('client_approval_submitted', { uid: targetUid, requestId });

      if (!approvalRequired || reqStatus === 'approved') {
        console.log(chalk.green('  ✅ Access auto-approved (host does not require manual approval for this session).'));
        payload = await resolveUID(BROKER_URL, targetUid, targetPassword, false, requestId);
      } else {
        console.log(chalk.yellow(`  ⏳ Waiting for host to approve your request (ID: ${requestId})...`));
        console.log(chalk.dim('     This may take a few minutes. Press Ctrl+C to cancel.'));
        console.log('');

        const approvalResult = await waitForApproval(BROKER_URL, targetUid, requestId, 300000);

        if (approvalResult && approvalResult.approved) {
          console.log(chalk.green('  ✅ Host approved your access request!'));
          logSessionEvent('client_approval_granted', { uid: targetUid, requestId });
          payload = await resolveUID(BROKER_URL, targetUid, targetPassword, false, requestId);
        } else {
          console.log(chalk.red('  ❌ Host denied your access request.'));
          logSessionEvent('client_approval_denied', { uid: targetUid, requestId });
          process.exit(1);
        }
      }
    } catch (err) {
      console.log(chalk.red(`  ❌ Approval flow failed: ${err.message}`));
      logSessionEvent('client_approval_error', { uid: targetUid, error: err.message }, 'error');
      process.exit(1);
    }
  }

  if (!payload || payload.needsApproval) {
    process.exit(1);
  }

  if (payload.type === 'http') {
    console.log('');
    console.log(chalk.bold('  🌐 HTTP Service Exposed'));
    console.log(chalk.dim('  ─────────────────────────────────'));
    console.log(chalk.green(`  Opening in browser: ${chalk.bold.cyan(payload.url)}`));
    console.log('');
    logSessionEvent('client_http_mode', { uid: targetUid, port: payload.port || null });
    try {
      await openUrl(payload.url);
    } catch {
      console.log(chalk.dim(`  Could not auto-open. Please visit: ${payload.url}`));
    }
    console.log(chalk.dim('  Press Ctrl+C to exit.'));
    // Keep process alive so cleanup handlers work
    await new Promise(() => {});
  }

  if (payload.type === 'tcp') {
    console.log('');
    console.log(chalk.bold('  🔌 Custom TCP Port Exposed'));
    console.log(chalk.dim('  ─────────────────────────────────'));
    console.log(`  The host is exposing a generic TCP service on port ${payload.port}.`);

    const hostname = extractHostname(payload.url);
    const localPort = payload.port;

    console.log(chalk.dim(`  Starting local cloudflared proxy to ${hostname}...`));
    console.log('');

    try {
      const { execa: execaFn } = await import('execa');
      const child = execaFn('cloudflared', ['access', 'tcp', '--hostname', hostname, '--url', `127.0.0.1:${localPort}`], {
        stdio: 'inherit',
        reject: false,
      });

      trackPID(child.pid);
      console.log(chalk.green(`  ✅ Local proxy active! Connect your client to ${chalk.bold('127.0.0.1:' + localPort)}`));
      console.log(chalk.dim('  Press Ctrl+C to terminate the tunnel.'));
      logSessionEvent('client_tcp_mode', { uid: targetUid, port: localPort, hostname });

      let result;
      try {
        result = await child;
      } finally {
        untrackPID(child.pid);
      }

      if (result.exitCode !== 0) {
        console.log(chalk.red(`  ❌ Cloudflared exited with code ${result.exitCode}`));
      }
    } catch (err) {
      console.log(chalk.red(`  ❌ Could not start cloudflared proxy: ${err.message}`));
      console.log(chalk.dim('  Fallback: run manually in another terminal:'));
      console.log(chalk.cyan(`  cloudflared access tcp --hostname ${hostname} --url 127.0.0.1:${localPort}`));
      console.log('');
      console.log(`  Then connect your local client to ${chalk.green('127.0.0.1:' + localPort)}`);
    }
    await cleanupAll();
    return;
  }

  const tunnelUrl = payload.url;
  const username = await resolveSshUsername(payload, targetUsername);
  const hostname = extractHostname(tunnelUrl);

  // Setup Ephemeral Key if provided
  let privateKeyPath = null;
  if (payload.privateKey) {
    console.log(chalk.green('  🔑 Host provided an ephemeral SSH key for passwordless entry!'));
    try {
      privateKeyPath = await writeEphemeralPrivateKey(payload.privateKey);
      addCleanupHook(() => {
        try { fs.unlinkSync(privateKeyPath); } catch { }
      });
      logSessionEvent('client_ephemeral_key_ready');
    } catch (err) {
      console.log(chalk.yellow(`  ⚠️  Could not use ephemeral SSH key: ${err.message}`));
      console.log(chalk.dim('     Falling back to standard OS password.'));
      logSessionEvent('client_ephemeral_key_failed', { error: err.message }, 'warn');
      privateKeyPath = null;
    }
  }

  // Push telemetry immediately so host can see the client in "See detailed client telemetry"
  // even before the user picks an action (SSH/SCP/etc.)
  await pushTelemetry(BROKER_URL, targetUid, targetPassword, username, 'connected');

  // Register cleanup hook to send 'disconnected' telemetry when the client exits
  addCleanupHook(async () => {
    try {
      await pushTelemetry(BROKER_URL, targetUid, targetPassword, username, 'disconnected');
    } catch {}
  });

  // Background polling to detect if the host has terminated the session
  const hostCheckInterval = setInterval(async () => {
    const isAlive = await checkUidStatus(BROKER_URL, targetUid);
    if (!isAlive) {
      console.log('');
      console.log(chalk.bold.bgRed.white('\n ⚠️  HOST DISCONNECTED '));
      console.log(chalk.red(' The host has terminated the session. Your connection is no longer active.'));
      console.log('');
      process.exit(1);
    }
  }, 5000);
  hostCheckInterval.unref?.();
  addCleanupHook(() => clearInterval(hostCheckInterval));

  // Start background E2E client log sync if sharedDropPath is configured
  if (payload.sharedDropPath && sessionLogPath) {
    startLiveLogSync(username, hostname, privateKeyPath, payload.sharedDropPath, sessionLogPath, persistKnownHosts);
  }

  // ─── One-Time File Share Auto-Download ────────────────────
  if (payload.oneTime && payload.oneTimeSharePath) {
    console.log('');
    console.log(chalk.bold.magenta('  📦 One-Time File Share'));
    console.log(chalk.dim('  ──────────────────────────────────────'));
    console.log(chalk.dim(`  Host is sharing: ${chalk.cyan(payload.oneTimeSharePath)}`));
    console.log(chalk.dim('  This is a one-time transfer — the session will be revoked after download.'));
    console.log('');

    const localDest = await promptLocalPath('download destination');

    await pushTelemetry(BROKER_URL, targetUid, targetPassword, username, 'one-time-download');
    logSessionEvent('client_one_time_download_start', { uid: targetUid, remotePath: payload.oneTimeSharePath });

    const success = await downloadSpecificRemotePath(username, hostname, privateKeyPath, payload.oneTimeSharePath, localDest, persistKnownHosts);

    if (success) {
      console.log(chalk.green('  ✅ One-time file transfer completed successfully!'));

      // Verify download checksum
      const dlHash = await calculateChecksum(localDest);
      if (dlHash) console.log(chalk.green(`  🔍 File Intact. SHA-256: ${dlHash.substring(0, 16)}...`));

      // Auto-revoke the UID from broker
      console.log(chalk.dim('  Revoking session from broker...'));
      await revokeUID(BROKER_URL, targetUid);
      console.log(chalk.green('  🔒 Session revoked. No further access is possible.'));

      logSessionEvent('client_one_time_download_complete', { uid: targetUid });
      recordEvent('one_time_transfer_complete', { uid: targetUid, localDest });
    } else {
      console.log(chalk.red('  ❌ One-time file transfer failed.'));
      logSessionEvent('client_one_time_download_failed', { uid: targetUid }, 'error');
    }

    await cleanupAll();
    return;
  }

  // Ask to save alias if we entered manually
  if (!targetUsername) {
    const { saveIt } = await inquirer.prompt([{
      type: 'confirm',
      name: 'saveIt',
      message: 'Save this connection as an alias for quick access later?',
      default: false
    }]);

    if (saveIt) {
      const { aliasName } = await inquirer.prompt([{
        type: 'input',
        name: 'aliasName',
        message: 'Enter alias name (e.g. my-server):',
        validate: v => v.trim().length > 0 || 'Required'
      }]);
      saveAlias(aliasName.trim(), { uid: targetUid, password: targetPassword, username });
      console.log(chalk.green(`  ✓ Saved as alias: ${chalk.bold(aliasName.trim())}\n`));
      logSessionEvent('client_alias_saved', { alias: aliasName.trim(), uid: targetUid });
      persistKnownHosts = true;
    }
  }

  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { name: '🖥️  Connect via SSH (Interactive Shell)', value: 'ssh' },
        { name: '📤 Upload file/folder via SCP', value: 'upload' },
        { name: '📥 Download file/folder via SCP', value: 'download' },
        { name: '🔄 Expose local port to Host (Reverse Tunnel)', value: 'reverse' },
        { name: '💬 Join Host Chat Room', value: 'chat' }
      ]
    }
  ]);

  await pushTelemetry(BROKER_URL, targetUid, targetPassword, username, action);
  logSessionEvent('client_action_selected', { action });

  if (action === 'chat') {
    await handleClientChat(targetUid, targetPassword, payload.chatUrl);
  } else if (action === 'ssh') {
    await connectSSH(username, hostname, privateKeyPath, persistKnownHosts);
  } else if (action === 'reverse') {
    await performReverseForward(username, hostname, privateKeyPath, persistKnownHosts);
  } else {
    await performSCP(username, hostname, action, privateKeyPath, payload.sharedDropPath, persistKnownHosts);
  }

  console.log('');
  const { reconnect } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'reconnect',
      message: 'Perform another action with the same host?',
      default: false,
    },
  ]);

  if (reconnect) {
    await handleSubsequentActions(username, hostname, privateKeyPath, targetUid, targetPassword, payload.sharedDropPath, persistKnownHosts);
  }

  logSessionEvent('client_session_exit');
  await cleanupAll();
}

/**
 * Perform a non-interactive SCP transfer (used by AI Transfer Assistant).
 * params: { brokerUrl, uid, password, username, direction, localPath, remotePath }
 */
export async function performSCPNonInteractive(params = {}) {
  const { brokerUrl, uid, password, username, direction, localPath, remotePath, persistKnownHosts = true } = params;
  if (!brokerUrl || !uid || !password) throw new Error('Missing broker connection info');

  const payload = await resolveUID(brokerUrl, uid, password);
  if (!payload) throw new Error('Could not resolve UID/payload');

  const tunnelUrl = payload.url;
  const hostname = extractHostname(tunnelUrl);
  const privateKeyPath = payload.privateKey ? await writeEphemeralPrivateKey(payload.privateKey) : null;

  // Build scp args similar to performSCP
  const scpArgs = ['-r', '-O', ...buildProxyCommandOption(hostname), ...getKnownHostsOptions(persistKnownHosts), '-o', 'IdentitiesOnly=yes', ...getSshControlOptions(hostname)];
  if (privateKeyPath) scpArgs.push('-i', privateKeyPath, '-o', 'IdentityAgent=none', ...getKeyOnlyAuthOptions());

  const remoteSpec = `${username}@${hostname}:${formatScpRemotePath(remotePath)}`;
  if (direction === 'upload') {
    scpArgs.push(localPath, remoteSpec);
  } else {
    scpArgs.push(remoteSpec, localPath);
  }

  try {
    const child = execa('scp', scpArgs, { stdio: 'inherit', reject: false });
    trackPID(child.pid);
    let result;
    try {
      result = await child;
      untrackPID(child.pid);
    } catch (err) {
      if (child?.pid) untrackPID(child.pid);
      throw err;
    }
    if (result.exitCode === 0) {
      recordEvent('scp_transfer_success', { direction, localPath, remotePath, hostname, automated: true });
      return true;
    }
    recordEvent('scp_transfer_failed', { direction, localPath, remotePath, hostname, error: result.stderr, automated: true });
    return false;
  } finally {
    try { if (privateKeyPath) fs.unlinkSync(privateKeyPath); } catch { }
  }
}

async function handleClientChat(uid, password, cachedChatUrl) {
  let chatUrl = cachedChatUrl;
  const spinner = createSpinner('Checking for active chat room...', networkSpinner).start();

  const payload = await resolveUID(BROKER_URL, uid, password, true); // true = silent if possible, or just re-resolve
  if (payload && payload.chatUrl) {
    chatUrl = payload.chatUrl;
  }

  if (chatUrl) {
    spinner.succeed('Chat Room found! Opening browser...');
    try {
      const fullUrl = `${chatUrl}#${password}`;
      await openUrl(fullUrl);
    } catch {
      console.log(chalk.cyan(`  👉 Please open: ${secureSensitiveUrl(chatUrl, password)}`));
    }
  } else {
    spinner.warn('The host has not started a chat room yet.');
  }
}

async function handleSubsequentActions(username, hostname, privateKeyPath, targetUid, targetPassword, sharedDropPath = null, persistKnownHosts = true) {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do next?',
      choices: [
        { name: '🖥️  Connect via SSH', value: 'ssh' },
        { name: '📤 Upload file/folder via SCP', value: 'upload' },
        { name: '📥 Download file/folder via SCP', value: 'download' },
        { name: '🔄 Expose local port to Host (Reverse Tunnel)', value: 'reverse' },
        { name: '💬 Join Host Chat Room', value: 'chat' },
        { name: '❌ Exit', value: 'exit' }
      ]
    }
  ]);

  if (action === 'exit') return;

  await pushTelemetry(BROKER_URL, targetUid, targetPassword, username, action);
  logSessionEvent('client_action_selected', { action });

  if (action === 'chat') {
    await handleClientChat(targetUid, targetPassword, null);
  } else if (action === 'ssh') {
    await connectSSH(username, hostname, privateKeyPath, persistKnownHosts);
  } else if (action === 'reverse') {
    await performReverseForward(username, hostname, privateKeyPath, persistKnownHosts);
  } else {
    await performSCP(username, hostname, action, privateKeyPath, sharedDropPath, persistKnownHosts);
  }

  const { reconnect } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'reconnect',
      message: 'Perform another action?',
      default: false,
    },
  ]);

  if (reconnect) {
    await handleSubsequentActions(username, hostname, privateKeyPath, targetUid, targetPassword, sharedDropPath, persistKnownHosts);
  }
}

async function performReverseForward(username, hostname, privateKeyPath, persistKnownHosts = true) {
  console.log('');
  console.log(chalk.bold.cyan('  🔄 Reverse Port Forwarding'));
  console.log(chalk.dim('  ──────────────────────────────────────'));
  console.log(chalk.dim('  Expose a local port on your machine so the Host can access it.'));
  console.log('');

  const { localPort, remotePort } = await inquirer.prompt([
    {
      type: 'input',
      name: 'localPort',
      message: 'Enter your local port to expose (e.g., 3000):',
      validate: (v) => !isNaN(parseInt(v)) || 'Must be a number',
    },
    {
      type: 'input',
      name: 'remotePort',
      message: 'Enter the port to bind on the Host (e.g., 8080):',
      default: '8080',
      validate: (v) => !isNaN(parseInt(v)) || 'Must be a number',
    }
  ]);

  const portMap = `${remotePort}:localhost:${localPort}`;

  const sshArgs = buildSshArgs(hostname, privateKeyPath, [
    '-N',
    '-R', portMap,
    '-o', 'ExitOnForwardFailure=yes',
  ], { persistKnownHosts, keyOnly: Boolean(privateKeyPath) });
  sshArgs.push(`${username}@${hostname}`);

  console.log('');
  const spinner = createSpinner(`Forwarding Host:${remotePort} ➔ Localhost:${localPort}...`, networkSpinner).start();

  let child = null;
  try {
    child = execa('ssh', sshArgs, { stdio: 'inherit', reject: false });
    trackPID(child.pid);
    spinner.succeed(`Reverse tunnel active! Host can access your app at ${chalk.bold.green('localhost:' + remotePort)}`);
    console.log(chalk.dim('  Press Ctrl+C to terminate the reverse tunnel.'));

    recordEvent('reverse_forward_started', { localPort, remotePort, hostname });
    let result;
    try {
      result = await child;
    } finally {
      untrackPID(child.pid);
    }
    if (result.exitCode === 0) {
      recordEvent('reverse_forward_ended', { localPort, remotePort, hostname, exitCode: 0 });
    } else {
      console.log(chalk.red(`\n  ❌ Reverse tunnel exited with code ${result.exitCode}`));
      recordEvent('reverse_forward_failed', { localPort, remotePort, hostname, exitCode: result.exitCode });
    }
  } catch (err) {
    if (err.isCanceled) return;
    if (err.killed) return;
    spinner.fail('Reverse tunnel failed to start');
    console.log(chalk.red(`\n  ❌ Tunnel disconnected: ${err.message}`));
  } finally {
    if (child?.pid) untrackPID(child.pid);
  }
}
