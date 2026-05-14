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
import { decrypt } from '../lib/crypto.js';
import { trackPID, untrackPID } from '../lib/cleanup.js';
import { createSpinner, sshSpinner, networkSpinner, fileTransferSpinner, showConnectionTrace, animatedSteps, simulateTransferProgress } from '../lib/animations.js';

const BROKER_URL = process.env.BROKER_URL || 'http://localhost:4000';

/**
 * Resolve a UID to a tunnel URL via the broker.
 * The broker returns an encrypted blob; we decrypt locally.
 *
 * @param {string} uid
 * @returns {Promise<string|null>}  The decrypted tunnel URL, or null on failure
 */
async function resolveUID(uid) {
  const spinner = createSpinner(`Resolving UID ${chalk.cyan(uid)}...`, networkSpinner).start();

  try {
    const res = await fetch(`${BROKER_URL}/resolve/${uid}`);

    if (res.status === 404) {
      spinner.fail('UID not found — the host may not be online or the session expired');
      return null;
    }
    if (res.status === 410) {
      spinner.fail('UID has expired — ask the host for a new session');
      return null;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!data.iv || !data.ciphertext) {
      spinner.fail('Broker returned invalid response — missing encrypted data');
      return null;
    }

    spinner.text = `Decrypting tunnel URL locally...`;

    // Simulate decryption delay for effect
    await new Promise(r => setTimeout(r, 600));

    // Decrypt locally
    let tunnelUrl;
    try {
      tunnelUrl = decrypt(data.iv, data.ciphertext);
    } catch (decryptErr) {
      spinner.fail('Decryption failed — SECRET_KEY mismatch');
      console.error(chalk.red('  ❌ Error: Could not decrypt tunnel URL'));
      console.log(chalk.dim('     Make sure your SECRET_KEY matches the host\'s key.'));
      return null;
    }

    if (!tunnelUrl.startsWith('https://')) {
      spinner.fail('Decrypted data is not a valid tunnel URL');
      return null;
    }

    spinner.succeed(`Resolved: ${chalk.dim(tunnelUrl)} ${chalk.green('[decrypted locally]')}`);
    return tunnelUrl;
  } catch (err) {
    spinner.fail(`Broker lookup failed: ${err.message}`);
    return null;
  }
}

function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url.replace(/^https?:\/\//, '').replace(/\/$/, '');
  }
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

/**
 * Start SSH connection through the Cloudflare tunnel.
 */
async function connectSSH(username, hostname) {
  console.log('');
  console.log(chalk.bold('  🔗 Establishing SSH Connection'));
  console.log(chalk.dim('  ─────────────────────────────────'));

  await showConnectionTrace('Local', 'Remote SSH');

  const proxyCommand = `cloudflared access tcp --hostname ${hostname}`;

  try {
    const spinner = createSpinner('Handshaking...', sshSpinner).start();
    await new Promise(r => setTimeout(r, 800));
    spinner.succeed('Connection established! Handing over to terminal...');
    console.log('');

    const child = execa('ssh', [
      '-o', `ProxyCommand=${proxyCommand}`,
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ServerAliveInterval=30',
      '-o', 'ServerAliveCountMax=3',
      `${username}@${hostname}`,
    ], {
      stdio: 'inherit',
      reject: false,
    });

    trackPID(child.pid);
    const result = await child;
    untrackPID(child.pid);

    if (result.exitCode === 0) {
      console.log('');
      console.log(chalk.green('  ✅ SSH session ended cleanly'));
    } else if (result.exitCode === 255) {
      console.log('');
      console.error(chalk.red('  ❌ SSH connection failed (exit code 255)'));
    } else {
      console.log('');
      console.error(chalk.red(`  ❌ SSH exited with code ${result.exitCode}`));
    }
  } catch (err) {
    console.error(chalk.red(`  ❌ SSH error: ${err.message}`));
  }
}

/**
 * Perform an SCP file transfer through the Cloudflare tunnel.
 */
async function performSCP(username, hostname, direction) {
  console.log('');
  console.log(chalk.bold(`  📦 SCP Transfer (${direction})`));
  console.log(chalk.dim('  ─────────────────────────────────'));

  const { localPath, remotePath } = await inquirer.prompt([
    {
      type: 'input',
      name: 'localPath',
      message: `Local file/folder path:`,
      validate: v => v.trim().length > 0 || 'Required',
    },
    {
      type: 'input',
      name: 'remotePath',
      message: `Remote path (relative to ${username}'s home or absolute):`,
      validate: v => v.trim().length > 0 || 'Required',
    }
  ]);

  await showConnectionTrace('Local', 'Remote SCP');

  const proxyCommand = `cloudflared access tcp --hostname ${hostname}`;

  // Construct SCP args
  const scpArgs = [
    '-r', // recursive just in case
    '-o', `ProxyCommand=${proxyCommand}`,
    '-o', 'StrictHostKeyChecking=accept-new'
  ];

  if (direction === 'upload') {
    scpArgs.push(localPath, `${username}@${hostname}:${remotePath}`);
  } else {
    scpArgs.push(`${username}@${hostname}:${remotePath}`, localPath);
  }

  try {
    const transferSpinner = createSpinner(`Transferring via SCP...`, fileTransferSpinner).start();

    const child = execa('scp', scpArgs, {
      stdio: ['inherit', 'pipe', 'pipe'],
      reject: false,
    });

    trackPID(child.pid);
    const result = await child;
    untrackPID(child.pid);

    transferSpinner.stop();

    if (result.exitCode === 0) {
      await simulateTransferProgress(direction === 'upload' ? localPath : remotePath, direction, 1500);
      console.log(chalk.green(`  ✅ Transfer completed successfully!`));
    } else {
      console.error(chalk.red('  ❌ SCP transfer failed'));
      if (result.stderr) console.error(chalk.dim(`     ${result.stderr.trim()}`));
    }
  } catch (err) {
    console.error(chalk.red(`  ❌ SCP error: ${err.message}`));
  }
}

/**
 * Main Client Mode entry point.
 */
export async function startClientMode() {
  console.log('');
  console.log(chalk.bold.cyan('  🌐 CLIENT MODE — Access a Remote Machine'));
  console.log(chalk.dim('  ──────────────────────────────────────────'));
  console.log('');

  const answer = await inquirer.prompt([
    {
      type: 'input',
      name: 'uid',
      message: 'Enter the remote host\'s UID:',
      validate: (v) => {
        const trimmed = v.trim();
        if (trimmed.length < 6 || trimmed.length > 16) return 'UID must be 6-16 characters';
        if (!/^[a-z0-9]+$/.test(trimmed)) return 'UID should be lowercase alphanumeric';
        return true;
      },
    },
  ]);
  const uid = answer.uid.trim();

  const tunnelUrl = await resolveUID(uid);
  if (!tunnelUrl) {
    process.exit(1);
  }

  const username = await promptUsername();
  const hostname = extractHostname(tunnelUrl);

  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { name: '🖥️  Connect via SSH (Interactive Shell)', value: 'ssh' },
        { name: '📤 Upload file/folder via SCP', value: 'upload' },
        { name: '📥 Download file/folder via SCP', value: 'download' }
      ]
    }
  ]);

  if (action === 'ssh') {
    await connectSSH(username, hostname);
  } else {
    await performSCP(username, hostname, action);
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
    await handleSubsequentActions(username, hostname);
  }
}

async function handleSubsequentActions(username, hostname) {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do next?',
      choices: [
        { name: '🖥️  Connect via SSH', value: 'ssh' },
        { name: '📤 Upload file/folder via SCP', value: 'upload' },
        { name: '📥 Download file/folder via SCP', value: 'download' },
        { name: '❌ Exit', value: 'exit' }
      ]
    }
  ]);

  if (action === 'exit') return;

  if (action === 'ssh') {
    await connectSSH(username, hostname);
  } else {
    await performSCP(username, hostname, action);
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
    await handleSubsequentActions(username, hostname);
  }
}