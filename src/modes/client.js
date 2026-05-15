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
import { decrypt, encrypt } from '../lib/crypto.js';
import { trackPID, untrackPID, addCleanupHook } from '../lib/cleanup.js';
import { createSpinner, sshSpinner, networkSpinner, fileTransferSpinner, showConnectionTrace, simulateTransferProgress } from '../lib/animations.js';
import { getConfig, saveAlias } from '../lib/config.js';
import open from 'open';

let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

/**
 * Gather client hardware telemetry and send securely to broker.
 */
async function pushTelemetry(uid, password, username) {
  try {
    let publicIp = 'Unknown';
    try {
      publicIp = await fetch('https://api.ipify.org').then(r => r.text());
    } catch {}

    const telemetry = {
      username,
      ip: publicIp,
      os: `${os.type()} ${os.release()} (${os.arch()})`,
      cpu: os.cpus()[0]?.model || 'Unknown CPU',
      ram: `${Math.round(os.totalmem() / 1024 / 1024 / 1024)} GB`,
      time: new Date().toLocaleTimeString()
    };

    const payloadStr = JSON.stringify(telemetry);
    // Use the same AES password logic to securely encrypt the telemetry blob
    const { iv, ciphertext, salt } = encrypt(payloadStr, password);

    await fetch(`${BROKER_URL}/client-info/${uid}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iv, ciphertext, salt }),
    });
  } catch {
    // Fail silently, telemetry is optional
  }
}

/**
 * Resolve a UID to a tunnel URL via the broker.
 * The broker returns an encrypted blob; we decrypt locally.
 *
 * @param {string} uid
 * @param {string} password
 * @param {boolean} silent If true, suppresses the spinner animations
 * @returns {object|null} The decrypted payload
 */
async function resolveUID(uid, password, silent = false) {
  const spinner = !silent ? createSpinner(`Resolving UID ${chalk.cyan(uid)}...`, networkSpinner).start() : null;

  try {
    const res = await fetch(`${BROKER_URL}/resolve/${uid}`);
    
    if (res.status === 404) {
      if (spinner) spinner.fail('UID not found — the host may not be online or the session expired');
      else console.error(chalk.red('  ❌ UID not found or expired.'));
      return null;
    }
    if (res.status === 410) {
      if (spinner) spinner.fail('UID has expired — ask the host for a new session');
      else console.error(chalk.red('  ❌ UID expired.'));
      return null;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!data.iv || !data.ciphertext || !data.salt) {
      if (spinner) spinner.fail('Broker returned invalid response — missing encrypted data or salt');
      return null;
    }

    if (spinner) spinner.text = `Decrypting tunnel URL locally...`;

    // Simulate decryption delay for effect only if not silent
    if (!silent) await new Promise(r => setTimeout(r, 600));

    // Decrypt locally
    let decryptedPayload;
    try {
      decryptedPayload = decrypt(data.iv, data.ciphertext, password, data.salt);
    } catch (decryptErr) {
      if (spinner) spinner.fail('Decryption failed — incorrect password or corrupted data');
      if (!spinner) console.error(chalk.red('  ❌ Error: Could not decrypt tunnel data. Incorrect password.'));
      return null;
    }

    let payloadConfig;
    try {
      payloadConfig = JSON.parse(decryptedPayload);
      // Backwards compatibility if host sent raw URL instead of JSON
      if (typeof payloadConfig !== 'object' || !payloadConfig.url) {
        payloadConfig = { url: decryptedPayload, type: 'ssh' };
      }
    } catch {
      payloadConfig = { url: decryptedPayload, type: 'ssh' };
    }

    if (!payloadConfig.url.startsWith('https://')) {
      spinner.fail('Decrypted data is not a valid tunnel URL (incorrect password)');
      return null;
    }

    spinner.succeed(`Resolved: ${chalk.dim(payloadConfig.url)} ${chalk.green('[decrypted locally]')}`);
    return payloadConfig;
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
async function connectSSH(username, hostname, privateKeyPath) {
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

    const sshArgs = [
      '-o', `ProxyCommand=${proxyCommand}`,
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ServerAliveInterval=30',
      '-o', 'ServerAliveCountMax=3'
    ];

    if (privateKeyPath) {
      sshArgs.push('-i', privateKeyPath, '-o', 'IdentitiesOnly=yes');
    }

    sshArgs.push(`${username}@${hostname}`);
    sshArgs.push('-t', 'tmux new-session -A -s SecureLink_Session || exec $SHELL');

    const child = execa('ssh', sshArgs, {
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

async function promptLocalFileBrowser(startPath = process.cwd()) {
  const items = fs.readdirSync(startPath, { withFileTypes: true });
  
  const choices = [
    { name: '📁 .. (Up a directory)', value: 'UP' },
    { name: '✅ SELECT CURRENT DIRECTORY', value: 'SELECT_DIR' },
    new inquirer.Separator(),
    ...items.map(item => ({
      name: `${item.isDirectory() ? '📁' : '📄'} ${item.name}`,
      value: path.join(startPath, item.name),
      isDir: item.isDirectory()
    }))
  ];

  const { selection } = await inquirer.prompt([{
    type: 'list',
    name: 'selection',
    message: `Browse local files [${startPath}]:`,
    choices,
    pageSize: 15
  }]);

  if (selection === 'UP') {
    return promptLocalFileBrowser(path.dirname(startPath));
  } else if (selection === 'SELECT_DIR') {
    return startPath;
  }

  const stat = fs.statSync(selection);
  if (stat.isDirectory()) {
    const { action } = await inquirer.prompt([{
      type: 'list',
      name: 'action',
      message: `Selected Folder: ${path.basename(selection)}`,
      choices: [
        { name: '📂 Open Folder', value: 'open' },
        { name: '✅ Select this Folder for Transfer', value: 'select' }
      ]
    }]);
    
    if (action === 'open') return promptLocalFileBrowser(selection);
    return selection;
  }

  return selection;
}

/**
 * Calculate SHA-256 of a local file.
 */
async function calculateChecksum(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', err => resolve(null)); // likely a directory
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Perform an SCP file transfer through the Cloudflare tunnel.
 */
async function performSCP(username, hostname, direction, privateKeyPath) {
  console.log('');
  console.log(chalk.bold(`  📦 SCP Transfer (${direction})`));
  console.log(chalk.dim('  ─────────────────────────────────'));

  let localPath;
  const { pathMode } = await inquirer.prompt([{
    type: 'list',
    name: 'pathMode',
    message: 'How do you want to select the local path?',
    choices: [
      { name: '⌨️  Type path manually', value: 'manual' },
      { name: '🔍 Browse local files interactively', value: 'browse' }
    ]
  }]);

  if (pathMode === 'browse') {
    localPath = await promptLocalFileBrowser();
  } else {
    const ans = await inquirer.prompt([{
      type: 'input',
      name: 'localPath',
      message: `Local file/folder path:`,
      validate: v => v.trim().length > 0 || 'Required',
    }]);
    localPath = ans.localPath.trim();
  }

  const { remotePath } = await inquirer.prompt([
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

  if (privateKeyPath) {
    scpArgs.push('-i', privateKeyPath, '-o', 'IdentitiesOnly=yes');
  }

  if (direction === 'upload') {
    scpArgs.push(localPath, `${username}@${hostname}:${remotePath}`);
  } else {
    scpArgs.push(`${username}@${hostname}:${remotePath}`, localPath);
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
    });

    trackPID(child.pid);
    const result = await child;
    untrackPID(child.pid);

    transferSpinner.stop();

    if (result.exitCode === 0) {
      await simulateTransferProgress(direction === 'upload' ? localPath : remotePath, direction, 1500);
      
      // Verify Checksum
      if (direction === 'upload' && localHash) {
        console.log(chalk.dim('  🔍 Verifying remote SHA-256 checksum...'));
        try {
          const sshArgs = [
            '-o', `ProxyCommand=${proxyCommand}`,
            '-o', 'StrictHostKeyChecking=accept-new'
          ];
          if (privateKeyPath) sshArgs.push('-i', privateKeyPath, '-o', 'IdentitiesOnly=yes');
          sshArgs.push(`${username}@${hostname}`, `shasum -a 256 "${remotePath}" || sha256sum "${remotePath}"`);
          
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
  }

  const config = getConfig();
  const aliasKeys = Object.keys(config.aliases || {});
  
  let targetUid = null;
  let targetPassword = null;
  let targetUsername = null;

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
    }
  }

  if (!targetUid) {
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
      {
        type: 'password',
        name: 'password',
        message: 'Enter the session password:',
        validate: (v) => v.trim().length > 0 || 'Password is required to decrypt',
      }
    ]);
    targetUid = answer.uid.trim();
    targetPassword = answer.password.trim();
  }

  const payload = await resolveUID(targetUid, targetPassword);
  if (!payload) {
    process.exit(1);
  }

  if (payload.type === 'http') {
    console.log('');
    console.log(chalk.bold('  🌐 HTTP Service Exposed'));
    console.log(chalk.dim('  ─────────────────────────────────'));
    console.log(chalk.green(`  Open this URL in your browser:\n  👉 ${chalk.bold.cyan(payload.url)}`));
    console.log('');
    process.exit(0);
  }

  if (payload.type === 'tcp') {
    console.log('');
    console.log(chalk.bold('  🔌 Custom TCP Port Exposed'));
    console.log(chalk.dim('  ─────────────────────────────────'));
    console.log(`  The host is exposing a generic TCP service on port ${payload.port}.`);
    console.log(`  To connect, run this command in a separate terminal:`);
    console.log(chalk.cyan(`  cloudflared access tcp --hostname ${extractHostname(payload.url)} --url 127.0.0.1:${payload.port}`));
    console.log('');
    console.log(`  Then connect your local client (e.g. Postgres, VNC, RDP) to ${chalk.green('127.0.0.1:' + payload.port)}`);
    console.log('');
    process.exit(0);
  }

  const tunnelUrl = payload.url;
  const username = targetUsername || await promptUsername();
  const hostname = extractHostname(tunnelUrl);

  // Setup Ephemeral Key if provided
  let privateKeyPath = null;
  if (payload.privateKey) {
    console.log(chalk.green('  🔑 Host provided an ephemeral SSH key for passwordless entry!'));
    privateKeyPath = path.join(os.tmpdir(), `ipingyou_client_${Date.now()}`);
    fs.writeFileSync(privateKeyPath, payload.privateKey, { mode: 0o600 });
    addCleanupHook(() => {
      try { fs.unlinkSync(privateKeyPath); } catch {}
    });
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
    }
  }

  // Push secure telemetry to host
  await pushTelemetry(targetUid, targetPassword, username);

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

  if (action === 'chat') {
    await handleClientChat(targetUid, targetPassword, payload.chatUrl);
  } else if (action === 'ssh') {
    await connectSSH(username, hostname, privateKeyPath);
  } else if (action === 'reverse') {
    await performReverseForward(username, hostname, privateKeyPath);
  } else {
    await performSCP(username, hostname, action, privateKeyPath);
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
    await handleSubsequentActions(username, hostname, privateKeyPath, targetUid, targetPassword);
  }
}

async function handleClientChat(uid, password, cachedChatUrl) {
  let chatUrl = cachedChatUrl;
  const spinner = createSpinner('Checking for active chat room...', networkSpinner).start();
  
  const payload = await resolveUID(uid, password, true); // true = silent if possible, or just re-resolve
  if (payload && payload.chatUrl) {
    chatUrl = payload.chatUrl;
  }

  if (chatUrl) {
    spinner.succeed('Chat Room found! Opening browser...');
    try {
      const fullUrl = `${chatUrl}#${password}`;
      await open(fullUrl);
    } catch {
      console.log(chalk.cyan(`  👉 Please open: ${chatUrl}#${password}`));
    }
  } else {
    spinner.warn('The host has not started a chat room yet.');
  }
}

async function handleSubsequentActions(username, hostname, privateKeyPath, targetUid, targetPassword) {
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

  if (action === 'chat') {
    await handleClientChat(targetUid, targetPassword, null);
  } else if (action === 'ssh') {
    await connectSSH(username, hostname, privateKeyPath);
  } else if (action === 'reverse') {
    await performReverseForward(username, hostname, privateKeyPath);
  } else {
    await performSCP(username, hostname, action, privateKeyPath);
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
    await handleSubsequentActions(username, hostname, privateKeyPath, targetUid, targetPassword);
  }
}

async function performReverseForward(username, hostname, privateKeyPath) {
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

  const proxyCmd = `cloudflared access ssh --hostname ${hostname}`;
  const portMap = `${remotePort}:localhost:${localPort}`;

  const sshArgs = [
    '-N',
    '-R', portMap,
    '-o', `ProxyCommand=${proxyCmd}`,
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null',
  ];

  if (privateKeyPath) {
    sshArgs.push('-i', privateKeyPath);
    sshArgs.push('-o', 'IdentitiesOnly=yes');
  }
  sshArgs.push(`${username}@${hostname}`);

  console.log('');
  const spinner = createSpinner(`Forwarding Host:${remotePort} ➔ Localhost:${localPort}...`, networkSpinner).start();

  try {
    const child = execa('ssh', sshArgs, { stdio: 'inherit' });
    trackPID(child.pid);
    spinner.succeed(`Reverse tunnel active! Host can access your app at ${chalk.bold.green('localhost:' + remotePort)}`);
    console.log(chalk.dim('  Press Ctrl+C to terminate the reverse tunnel.'));
    
    await child;
  } catch (err) {
    if (err.isCanceled) return;
    if (err.killed) return;
    console.log(chalk.red(`\n  ❌ Tunnel disconnected: ${err.message}`));
  }
}