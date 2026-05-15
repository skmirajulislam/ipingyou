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
import { generateUID } from '../lib/uid.js';
import { encrypt, decrypt } from '../lib/crypto.js';
import { trackPID, untrackPID, setRevokeOnExit, addCleanupHook } from '../lib/cleanup.js';
import { detectOS } from '../lib/platform.js';
import { createSpinner, cryptoSpinner, tunnelSpinner, networkSpinner, typeText } from '../lib/animations.js';
import { startChatServer, openLocalChatUI } from '../lib/chat.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

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
 * Supervise cloudflared tunnel, restarting it if it crashes.
 */
async function spawnTunnelSupervised(targetUrl, onUrlGenerated) {
  let isShuttingDown = false;
  let activeChild = null;

  const loop = async () => {
    while (!isShuttingDown) {
      const spinner = createSpinner('Starting Cloudflare tunnel...', tunnelSpinner).start();
      
      await new Promise((resolve) => {
        activeChild = execa('cloudflared', ['tunnel', '--url', targetUrl], {
          reject: false,
          all: true,
        });

        trackPID(activeChild.pid);
        let tunnelUrl = null;
        let resolved = false;

        activeChild.all.on('data', (chunk) => {
          const text = chunk.toString();
          const match = text.match(/https:\/\/[-0-9a-z]+\.trycloudflare\.com/);
          if (match && !resolved) {
            tunnelUrl = match[0];
            resolved = true;
            spinner.succeed(`Tunnel active: ${chalk.cyan(tunnelUrl)}`);
            onUrlGenerated(tunnelUrl);
          }
        });

        activeChild.on('exit', (code) => {
          untrackPID(activeChild.pid);
          if (!resolved) {
            spinner.fail('Cloudflare tunnel exited before generating URL');
          } else if (!isShuttingDown) {
            console.log(chalk.yellow(`\n  ⚠️  Tunnel disconnected (code ${code}). Restarting...`));
          }
          resolve(); // Let the loop continue to restart
        });

        activeChild.on('error', (err) => {
          untrackPID(activeChild.pid);
          spinner.fail(`Tunnel error: ${err.message}`);
          resolve();
        });
      });

      if (!isShuttingDown) {
        // Wait a bit before restarting to avoid tight loop
        await new Promise(r => setTimeout(r, 2000));
      }
    }
  };

  loop(); // Fire and forget the supervisor loop

  return {
    kill: () => {
      isShuttingDown = true;
      if (activeChild) {
        untrackPID(activeChild.pid);
        try { process.kill(activeChild.pid); } catch { /* ignore */ }
      }
    }
  };
}

// ─── Ephemeral SSH Key Management ────────────────────────────
async function generateEphemeralKey() {
  const tmpDir = os.tmpdir();
  const keyPath = path.join(tmpDir, `ipingyou_${Date.now()}`);
  
  await execa('ssh-keygen', ['-t', 'ed25519', '-C', 'ipingyou-ephemeral', '-f', keyPath, '-N', '']);
  
  const privKey = (await fs.promises.readFile(keyPath, 'utf8')).trim();
  const pubKey = (await fs.promises.readFile(`${keyPath}.pub`, 'utf8')).trim();
  
  return { keyPath, privKey, pubKey };
}

async function injectPublicKey(pubKey) {
  const osInfo = detectOS();
  const sshDir = path.join(osInfo.homedir, '.ssh');
  
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
 * Ping the broker to see if it's online.
 */
async function pingBroker(url) {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${url}/health`, { signal: controller.signal });
    clearTimeout(id);
    return res.ok;
  } catch {
    return false;
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
    reject: false
  });
  trackPID(brokerProcess.pid);

  // 2. Wrap it in a cloudflare tunnel
  let brokerTunnelUrl = null;
  const privateBrokerTunnelProcess = await spawnTunnelSupervised('http://localhost:4040', (newUrl) => {
    brokerTunnelUrl = newUrl;
  });

  while (!brokerTunnelUrl) {
    await new Promise(r => setTimeout(r, 100));
  }

  console.log(chalk.green(`  ✅ Private Broker Active: ${chalk.bold.cyan(brokerTunnelUrl)}\n`));
  
  return {
    url: brokerTunnelUrl,
    kill: () => {
      privateBrokerTunnelProcess.kill();
      untrackPID(brokerProcess.pid);
      try { process.kill(brokerProcess.pid); } catch { /* ignore */ }
    }
  };
}

/**
 * Encrypt tunnel details and register with the Central Broker.
 */
async function registerWithBroker(uid, tunnelUrl, password, serviceConfig) {
  const spinner = createSpinner('Encrypting session data...', cryptoSpinner).start();

  try {
    // Encrypt the JSON payload LOCALLY before sending
    await new Promise(r => setTimeout(r, 600)); // animation effect
    const payload = JSON.stringify({ url: tunnelUrl, ...serviceConfig });
    const encrypted = encrypt(payload, password);

    spinner.text = 'Registering with broker...';

    const res = await fetch(`${BROKER_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        uid,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        salt: encrypted.salt,
      }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    spinner.succeed(`Registered with broker ${chalk.dim(`(${BROKER_URL})`)} ${chalk.green('[E2E encrypted]')}`);
    return true;
  } catch (err) {
    spinner.fail(`Broker registration failed: ${err.message}`);
    console.error(chalk.red(`  ❌ Error: ${err.message}`));
    console.log(chalk.yellow('  ⚠️  Remote clients won\'t be able to find you without the broker.'));
    console.log(chalk.dim('     Share the tunnel URL directly if needed.'));
    return false;
  }
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
               await registerWithBroker(uid, tunnelUrl, password, serviceConfig);
               renderDashboard();
             }
          });

          console.log(chalk.dim('  Provisioning Cloudflare tunnel for chat...'));
          chatTunnelProcess = await spawnTunnelSupervised(`http://localhost:${chatServerInstance.port}`, async (newUrl) => {
            serviceConfig.chatUrl = newUrl;
            await registerWithBroker(uid, tunnelUrl, password, serviceConfig);
            renderDashboard();
          });

          while (!serviceConfig.chatUrl) {
            await new Promise(r => setTimeout(r, 100));
          }

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
          console.log(chalk.dim('  Attaching to client session. Press Ctrl+b then d to detach gracefully!'));
          console.log(chalk.dim('  If no client has connected yet or tmux is missing, this will fail.'));
          console.log('');
          
          try {
            await execaCommand('tmux attach -t SecureLink_Session -r', { stdio: 'inherit' });
          } catch {
            console.log(chalk.yellow('  ⚠️  Could not attach. Ensure a client is connected and tmux is installed.'));
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
          await registerWithBroker(uid, tunnelUrl, password, serviceConfig);
          return waitForAction();

        case 'terminate': {
          const spinner = createSpinner('Terminating active SSH sessions...', networkSpinner).start();
          try {
            if (process.platform === 'win32') {
              await execaCommand('taskkill /F /IM sshd.exe', { reject: false });
            } else {
              await execaCommand("pkill -f 'sshd:.*@'", { shell: true, reject: false });
            }
            spinner.succeed('All client SSH sessions terminated');
          } catch {
            spinner.warn('Could not terminate sessions (none active?)');
          }
          return waitForAction();
        }

        case 'exit':
          clearInterval(monitorInterval);
          if (tunnelProcess) tunnelProcess.kill();
          if (chatTunnelProcess) chatTunnelProcess.kill();
          if (global.privateBrokerInstance) global.privateBrokerInstance.kill();
          return;
      }
    } catch (err) {
      clearInterval(monitorInterval);
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
      console.log(chalk.yellow(`  ⚠️  Could not generate ephemeral key: ${err.message}`));
      console.log(chalk.dim('     Client will need to use standard OS password.'));
    }
  } else {
    console.log(chalk.dim(`  ℹ️  Ensure your ${protocol.toUpperCase()} service is running on port ${targetPort}.`));
  }

  let tunnelUrl = null;
  const tunnelProcess = await spawnTunnelSupervised(targetUrl, async (newUrl) => {
    tunnelUrl = newUrl;
    // Register or re-register with broker when tunnel is spawned/respawned
    const registered = await registerWithBroker(uid, tunnelUrl, password, serviceConfig);
    if (!registered) {
      console.error(chalk.red(`\n  ❌ FATAL: Could not register with broker at ${BROKER_URL}`));
      process.exit(1);
    }
  });

  // Wait for the first URL to be generated before showing the dashboard
  while (!tunnelUrl) {
    await new Promise(r => setTimeout(r, 100));
  }

  setRevokeOnExit(uid, BROKER_URL);

  await hostDashboard(uid, tunnelUrl, password, serviceConfig, tunnelProcess);
}