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
import { pingBroker, registerWithBroker } from '../lib/broker.js';

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
async function hostDashboard(uid, tunnelUrl, password, serviceConfig, tunnelProcess) {
  let chatServerInstance = null;
  let chatTunnelProcess = null;

  const renderDashboard = () => {
    console.clear();
    console.log('');
    console.log(chalk.bold('  ╔════════════════════════════════════════════════════╗'));
    console.log(chalk.bold('  ║         🛡️  SecureLink — HOST MODE ACTIVE          ║'));
    console.log(chalk.bold('  ╠════════════════════════════════════════════════════╣'));
    console.log(`  ║  ${chalk.cyan('UID:')}        ${chalk.bold.white(uid.padEnd(30))}║`);
    console.log(`  ║  ${chalk.cyan('Password:')}   ${chalk.bold.white(password.padEnd(30))}║`);
    console.log(`  ║  ${chalk.cyan('Service:')}    ${chalk.dim(serviceConfig.type.toUpperCase() + ' (Port ' + serviceConfig.port + ')').padEnd(30)}║`);
    console.log(`  ║  ${chalk.cyan('Tunnel:')}     ${chalk.dim(tunnelUrl.substring(0, 40))}  ║`);
    if (serviceConfig.chatUrl) {
      console.log(`  ║  ${chalk.cyan('Chat URL:')}   ${chalk.dim(serviceConfig.chatUrl.substring(0, 40))}  ║`);
    }
    console.log(`  ║  ${chalk.cyan('Broker:')}     ${chalk.dim(BROKER_URL.substring(0, 40))}  ║`);
    console.log(`  ║  ${chalk.cyan('Crypto:')}     ${chalk.green('AES-256-CBC E2E (PBKDF2)')}             ║`);
    console.log(chalk.bold('  ╠════════════════════════════════════════════════════╣'));
    console.log(`  ║  ${chalk.yellow('Share the UID, Password & Broker URL with client ')}  ║`);
    console.log(`  ║  ${chalk.dim('Press Ctrl+C to terminate the session')}              ║`);
    console.log(chalk.bold('  ╚════════════════════════════════════════════════════╝'));
    console.log('');
  };

  renderDashboard();
  await typeText(chalk.dim(`  Listening for incoming connections on port ${serviceConfig.port}...`), 30);
  console.log('');

  const waitForAction = async () => {
    try {
      const choices = [
        { name: '📡 See detailed client telemetry', value: 'show' },
        { name: '📺 Mirror Client Terminal (requires tmux)', value: 'mirror' },
        { name: '🔄 Re-register with broker', value: 'reregister' }
      ];

      if (!chatServerInstance) {
        choices.push({ name: '💬 Start Real-time Chat Room', value: 'chat' });
      } else {
        choices.push({ name: '💬 Re-open Chat Room in Browser', value: 'reopen_chat' });
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

      switch (action) {
        case 'chat': {
          console.log(chalk.dim('\n  Starting chat server...'));
          chatServerInstance = await startChatServer(async () => {
             if (chatTunnelProcess) {
               chatTunnelProcess.kill();
               chatTunnelProcess = null;
               chatServerInstance = null;
               delete serviceConfig.chatUrl;
               await registerWithBroker(BROKER_URL, uid, tunnelUrl, password, serviceConfig);
               renderDashboard();
             }
          });

          console.log(chalk.dim('  Provisioning Cloudflare tunnel for chat...'));
          chatTunnelProcess = await spawnTunnelSupervised(`http://localhost:${chatServerInstance.port}`, async (newUrl) => {
            serviceConfig.chatUrl = newUrl;
            await registerWithBroker(BROKER_URL, uid, tunnelUrl, password, serviceConfig);
            renderDashboard();
          });

          await waitForValue(() => serviceConfig.chatUrl, 30000, 'Chat tunnel startup');

          console.log(chalk.green('  ✅ Chat Room Live! Clients can now join.'));
          await openLocalChatUI(chatServerInstance.port, password);
          return waitForAction();
        }

        case 'reopen_chat': {
          if (chatServerInstance) await openLocalChatUI(chatServerInstance.port, password);
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
            const sessionCheck = await execa('tmux', ['has-session', '-t', 'SecureLink_Session'], { reject: false });
            if (sessionCheck.exitCode !== 0) {
              console.log(chalk.yellow('  ⚠️  No mirrored terminal session is active yet.'));
              console.log(chalk.dim('     A client must choose "Connect via SSH" first. SCP-only clients do not create a tmux session.'));
              console.log(chalk.dim('     tmux is needed on the host machine only; the client does not need tmux.'));
              return waitForAction();
            }
            await execaCommand('tmux attach -t SecureLink_Session -r', { stdio: 'inherit' });
          } catch (err) {
            console.log(chalk.yellow('  ⚠️  Could not attach to tmux.'));
            console.log(chalk.dim(`     ${err.message}`));
            console.log(chalk.dim('     Terminal mirroring requires tmux on the host machine and an active interactive SSH client.'));
          }
          return waitForAction();
        }

        case 'show': {
          const spinner = createSpinner('Fetching secure client telemetry...', networkSpinner).start();
          try {
            const res = await fetch(`${BROKER_URL}/clients/${uid}`);
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
                  
                  console.log(chalk.bold.blue(`\n  Client #${i+1} (${t.username})`));
                  console.log(`    IP:       ${chalk.white(t.ip)}`);
                  console.log(`    OS:       ${chalk.dim(t.os)}`);
                  console.log(`    CPU:      ${chalk.dim(t.cpu)}`);
                  console.log(`    RAM:      ${chalk.dim(t.ram)}`);
                  console.log(`    Time:     ${chalk.dim(t.time)}`);
                } catch (e) {
                  console.log(chalk.yellow(`\n  Client #${i+1}: Payload decryption failed (wrong password or corrupted).`));
                }
              });
            }
          } catch (e) {
             spinner.fail('Could not reach broker.');
          }
          console.log('');
          return waitForAction();
        }

        case 'reregister':
          await registerWithBroker(BROKER_URL, uid, tunnelUrl, password, serviceConfig);
          return waitForAction();

        case 'terminate': {
          const spinner = createSpinner('Terminating active SSH sessions...', networkSpinner).start();
          try {
            if (process.platform === 'win32') {
              await execaCommand('powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"name = \'sshd.exe\'\\" | Where-Object { $_.CommandLine -match \'sshd:.*@\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"', { reject: false });
            } else {
              await execaCommand("pkill -f 'sshd:.*@'", { shell: true, reject: false });
              await execaCommand('tmux kill-session -t SecureLink_Session', { reject: false });
            }
            spinner.succeed('All client SSH sessions terminated');
          } catch {
            spinner.warn('Could not terminate sessions (none active?)');
          }
          return waitForAction();
        }

        case 'exit':
          if (chatTunnelProcess) chatTunnelProcess.kill();
          if (global.privateBrokerInstance) global.privateBrokerInstance.kill();
          if (tunnelProcess) tunnelProcess.kill();
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

  const uid = generateUID();
  console.log(`  ${chalk.green('✓')} Session UID: ${chalk.bold.white(uid)}`);
  console.log('');

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
  }

  // Only ping if we haven't just created a private broker
  if (!global.privateBrokerInstance) {
    const spinner = createSpinner(`Checking broker status at ${BROKER_URL}...`, networkSpinner).start();
    const brokerOnline = await pingBroker(BROKER_URL);
    
    if (brokerOnline) {
      spinner.succeed(`Broker is online ${chalk.dim(`(${BROKER_URL})`)}`);
    } else {
      spinner.warn(`Broker is unreachable ${chalk.dim(`(${BROKER_URL})`)}`);
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
      } else {
        console.log(chalk.red('\n  ❌ FATAL: Cannot continue without a broker.'));
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
        { name: '🌐 Web/HTTP (Custom Port)', value: 'http' },
        { name: '🔌 Custom TCP Port (e.g. Database, RDP, VNC)', value: 'tcp' }
      ]
    }
  ]);

  let targetPort = 22;
  let protocol = 'ssh';

  if (serviceType === 'http') {
    const ans = await inquirer.prompt([{ name: 'port', message: 'Enter local HTTP port (e.g. 3000):', default: '3000' }]);
    targetPort = ans.port;
    protocol = 'http';
  } else if (serviceType === 'tcp') {
    const ans = await inquirer.prompt([{ name: 'port', message: 'Enter local TCP port (e.g. 3389 for RDP, 5432 for Postgres):' }]);
    targetPort = ans.port;
    protocol = 'tcp';
  }

  const serviceConfig = { type: serviceType, port: targetPort, protocol };
  const targetUrl = `${protocol}://localhost:${targetPort}`;

  if (serviceType === 'ssh') {
    await ensureSSHRunning();
    await ensureTmuxInstalled();
    console.log(chalk.dim('  🔑 Generating ephemeral SSH key for passwordless entry...'));
    try {
      const ephemeralKey = await generateEphemeralKey();
      const authKeysPath = await injectPublicKey(ephemeralKey.pubKey);
      
      serviceConfig.privateKey = ephemeralKey.privKey;
      
      addCleanupHook(async () => {
        console.log(chalk.dim('     Removing ephemeral public key...'));
        await removePublicKey(authKeysPath, ephemeralKey.pubKey);
        try { await fs.promises.unlink(ephemeralKey.keyPath); } catch {}
        try { await fs.promises.unlink(`${ephemeralKey.keyPath}.pub`); } catch {}
      });
      console.log(chalk.green('  ✓ Ephemeral key injected. Client will connect without system password!'));
    } catch (err) {
      console.log(chalk.yellow(`  ⚠️  Could not prepare ephemeral SSH key: ${err.message}`));
      console.log(chalk.dim('     Client will need to use standard OS password.'));
    }
  } else {
    console.log(chalk.dim(`  ℹ️  Ensure your ${protocol.toUpperCase()} service is running on port ${targetPort}.`));
  }

  let tunnelUrl = null;
  const tunnelProcess = await spawnTunnelSupervised(targetUrl, async (newUrl) => {
    tunnelUrl = newUrl;
    // Register or re-register with broker when tunnel is spawned/respawned
    const registered = await registerWithBroker(BROKER_URL, uid, tunnelUrl, password, serviceConfig);
    if (!registered) {
      console.error(chalk.red(`\n  ❌ FATAL: Could not register with broker at ${BROKER_URL}`));
      process.exit(1);
    }
  });

  // Wait for the first URL to be generated before showing the dashboard
  await waitForValue(() => tunnelUrl, 30000, 'Cloudflare tunnel startup');

  setRevokeOnExit(uid, BROKER_URL);

  await hostDashboard(uid, tunnelUrl, password, serviceConfig, tunnelProcess);
}
