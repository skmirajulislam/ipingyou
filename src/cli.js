#!/usr/bin/env node

/**
 * ============================================================
 *  SecureLink-CLI  (ipingyou)
 * ============================================================
 *  Secure peer-to-peer remote access via SSH & Cloudflare
 *  Tunnels.  Designed to run via npx or as a global install.
 *
 *  Usage:
 *    npx ipingyou              — Interactive mode
 *    npx ipingyou host         — Start as host directly
 *    npx ipingyou connect      — Start as client directly
 *
 *  Security:
 *    All tunnel URLs are AES-256-CBC encrypted on the CLI side.
 *    The broker is a zero-knowledge relay — it NEVER sees plaintext.
 * ============================================================
 */

import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

import { detectOS, checkDependencies } from './lib/services/platform.js';
import { cleanupAll, installShutdownHandlers, executePanicMode } from './lib/mod/cleanup.js';
import { cleanupSessionLog } from './lib/mod/session-log.js';
import { getSocketFirewallStatus, runProtectedNpmInstall } from './lib/mod/socket-firewall.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));

// ─── ASCII Banner ────────────────────────────────────────────
const wolfAscii = [
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠁⠸⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠃⠀⠀⢸⠸⠀⡠⣄⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠃⠀⠀⢠⣞⣀⡿⠀⠀⣧⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⡖⠁⠀⠀⠀⢸⠈⢈⡇⠀⢀⡏⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠩⢠⡴⠀⠀⠀⠀⠀⠈⡶⠉⠀⠀⡸⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⢀⠎⢠⣇⠏⠀⠀⠀⠀⠀⠀⠀⠁⠀⢀⠄⡇⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⢠⠏⠀⢸⣿⣴⠀⠀⠀⠀⠀⠀⣆⣀⢾⢟⠴⡇⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⢀⣿⠀⠠⣄⠸⢹⣦⠀⠀⡄⠀⠀⢋⡟⠀⠀⠁⣇⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⢀⡾⠁⢠⠀⣿⠃⠘⢹⣦⢠⣼⠀⠀⠉⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀",
  "⠀⠀⢀⣴⠫⠤⣶⣿⢀⡏⠀⠀⠘⢸⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀",
  "⠐⠿⢿⣿⣤⣴⣿⣣⢾⡄⠀⠀⠀⠀⠳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀",
  "⠀⠀⠀⣨⣟⡍⠉⠚⠹⣇⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠀⢀⡀⣾⡇⠀⠀",
  "⠀⠀⢠⠟⣹⣧⠃⠀⠀⢿⢻⡀⢄⠀⠀⠀⠀⠐⣦⡀⣸⣆⠀⣾⣧⣯⢻⠀⠀",
  "⠀⠀⠘⣰⣿⣿⡄⡆⠀⠀⠀⠳⣼⢦⡘⣄⠀⠀⡟⡷⠃⠘⢶⣿⡎⠻⣆⠀⠀",
  "⠀⠀⠀⡟⡿⢿⡿⠀⠀⠀⠀⠀⠙⠀⠻⢯⢷⣼⠁⠁⠀⠀⠀⠙⢿⡄⡈⢆⠀",
  "⠀⠀⠀⠀⡇⣿⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠦⠀⠀⠀⠀⠀⠀⡇⢹⢿⡀",
  "⠀⠀⠀⠀⠁⠛⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠼⠇⠁"
];

const titleAscii = [
  "   ___  ____   ___  _   _   ____        _   _  ",
  "  |_ _||  _ \\ |_ _|| \\ | | / ___|      | | | | ",
  "   | | | |_) | | | |  \\| || |  _  ____ | | | | ",
  "   | | |  __/  | | | |\\  || |_| ||____|| |_| | ",
  "  |___||_|    |___||_| \\_| \\____|       \\___/  "
];

function showBanner() {
  console.log('');
  
  const darkBlueGray = chalk.hex('#4B5563').bold;
  const pink = chalk.hex('#FF69B4').bold;
  const titleStartLine = 6;
  
  wolfAscii.forEach((line, index) => {
    let out = chalk.dim(line);
    if (index >= titleStartLine && index < titleStartLine + titleAscii.length) {
       const titleLine = titleAscii[index - titleStartLine];
       const ipingPart = titleLine.substring(0, 36);
       const uPart = titleLine.substring(36);
       out += darkBlueGray(ipingPart) + pink(uPart);
    }
    console.log('  ' + out);
  });
  
  console.log('');
  console.log(chalk.cyan.bold('  ╔═══════════════════════════════════════════╗'));
  console.log(chalk.cyan.bold('  ║                                           ║'));
  console.log(chalk.cyan.bold('  ║') + chalk.white.bold('     🔗  iPingYou  —  SecureLink CLI  ') + chalk.cyan.bold('     ║'));
  console.log(chalk.cyan.bold('  ║') + chalk.yellow.bold('           by SK MIRAJUL ISLAM         ') + chalk.cyan.bold('    ║'));
  console.log(chalk.cyan.bold('  ║                                           ║'));
  console.log(chalk.cyan.bold('  ║') + chalk.dim('   Secure P2P Remote Access via SSH +  ') + chalk.cyan.bold('    ║'));
  console.log(chalk.cyan.bold('  ║') + chalk.dim('   Cloudflare Tunnels  |  AES-256-GCM ') + chalk.cyan.bold('    ║'));
  console.log(chalk.cyan.bold('  ║                                           ║'));
  console.log(chalk.cyan.bold('  ╚═══════════════════════════════════════════╝'));
  console.log('');
}

function showSystemInfo() {
  const osInfo = detectOS();
  const platform = osInfo.isLinux ? '🐧 Linux' : osInfo.isMac ? '🍎 macOS' : '🪟 Windows';
  console.log(chalk.dim(`  ${platform}  |  ${osInfo.arch}  |  ${osInfo.hostname}  |  Node ${process.version}  |  v${packageJson.version}`));
  console.log('');
}

function showRichHelp() {
  console.log(chalk.bold.yellow('  ✨ Welcome to iPingYou SecureLink CLI! ✨'));
  console.log(chalk.dim('  ───────────────────────────────────────────────────────'));
  console.log(chalk.cyan('  A zero-knowledge peer-to-peer remote access tool.'));
  console.log(chalk.cyan('  Securely share your local SSH terminal with anyone over the internet.'));
  console.log('');
  
  console.log(chalk.bold.white('  🚀 Usage Modes:'));
  console.log(`    ${chalk.green('host')}    : Generates a secure session UID and exposes your local machine.`);
  console.log(`    ${chalk.blue('connect')} : Prompts for a UID to connect to a remote host.`);
  console.log(`              ${chalk.dim('Supports Interactive SSH Shell & SCP File Transfers')}`);
  console.log(`    ${chalk.magenta('ai')}      : Groq-powered task assistant with guarded local/remote tools.`);
  console.log(`    ${chalk.yellow('doctor')}  : Run diagnostics for dependencies, SSH, broker, SCP, AI, and tests.`);
  console.log('');
  
  console.log(chalk.bold.white('  🔒 Security Architecture:'));
  console.log(`    • Cloudflare Tunnels punch through NAT/Firewalls securely.`);
  console.log(`    • ${chalk.green('End-to-End Encryption')}: Tunnel URLs are AES-256 encrypted locally.`);
  console.log(`    • The Broker never sees your plaintext URL, only ciphertext.`);
  console.log(`    • ${chalk.green('Host Auth Token')}: Host-only token gates approvals & telemetry access.`);
  console.log(`    • ${chalk.green('Approval Gate')}: Clients submit encrypted metadata; Host approves/denies.`);
  console.log('');

  console.log(chalk.bold.white('  🔥 Advanced Features:'));
  console.log(`    • ${chalk.green('Terminal Mirroring')}   : Host can spectate connected SSH clients in real-time.`);
  console.log(`    • ${chalk.green('Reverse Forwarding')} : Clients can expose their local localhost ports back to the Host.`);
  console.log(`    • ${chalk.green('E2E Chat Room')}      : Real-time Web Crypto AES-GCM secure chat UI for Host & Clients.`);
  console.log(`    • ${chalk.green('Daemonization')}      : Run Host mode as a background service via PM2.`);
  console.log(`    • ${chalk.green('Panic Kill-Switch')}  : Instantly purge all processes, configurations, and traces.`);
  console.log(`    • ${chalk.green('Shared Drop Folder')} : Session dropbox auto-removed on exit.`);
  console.log(`    • ${chalk.green('Live Session Logs')}  : Host/client/broker events written per session.`);
  console.log('');

  console.log(chalk.bold.white('  💡 Examples:'));
  console.log(`    $ npx ipingyou                  ${chalk.dim('# Interactive wizard (Recommended)')}`);
  console.log(`    $ npx ipingyou host             ${chalk.dim('# Quick start as Host')}`);
  console.log(`    $ npx ipingyou connect          ${chalk.dim('# Quick start as Client')}`);
  console.log(`    $ npx ipingyou ai               ${chalk.dim('# Start AI task assistant')}`);
  console.log(`    $ npx ipingyou doctor           ${chalk.dim('# Diagnose local setup')}`);
  console.log(`    $ npx ipingyou panic            ${chalk.dim('# Self-destruct and wipe memory/traces')}`);
  console.log(`    $ npx ipingyou service install  ${chalk.dim('# Install Host mode as a background daemon')}`);
  console.log(`    $ npx ipingyou allowlist        ${chalk.dim('# Manage AI command allowlist')}`);
  console.log(`    $ npx ipingyou history          ${chalk.dim('# View session event logs')}`);
  console.log('');
}

/**
 * Fatal error handler — logs and exits with code 1.
 * @param {string} context  — which command/mode failed
 * @param {Error}  err      — the error object
 */
function fatal(context, err) {
  console.error('');
  console.error(chalk.red(`  ❌ FATAL [${context}]`));
  console.error(chalk.red(`     ${err.message}`));
  if (err.stack) {
    const stackLines = err.stack.split('\n').slice(1, 4);
    stackLines.forEach(line => console.error(chalk.dim(`     ${line.trim()}`)));
  }
  console.error('');
  cleanupSessionLog();
  cleanupAll().finally(() => process.exit(1));
}

// ─── Interactive Mode Selection ──────────────────────────────
async function interactiveMode() {
  showBanner();
  showSystemInfo();

  // Check dependencies first
  const deps = await checkDependencies();

  if (!deps.ssh || !deps.cloudflared) {
    const { proceed } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'proceed',
        message: 'Some dependencies are missing. Continue anyway?',
        default: false,
      },
    ]);
    if (!proceed) {
      console.log(chalk.dim('  Install the missing tools and try again.'));
      process.exit(0);
    }
  }

  // Mode selection
  const { mode } = await inquirer.prompt([
    {
      type: 'list',
      name: 'mode',
      message: 'What would you like to do?',
      choices: [
        {
          name: `${chalk.green('🛡️  Allow Remote Access')}  ${chalk.dim('— Let someone connect to this machine')}`,
          value: 'host',
        },
        {
          name: `${chalk.blue('🌐 Access a Remote Machine')}  ${chalk.dim('— Connect to a host via their UID (SSH/SCP)')}`,
          value: 'client',
        },
        {
          name: `${chalk.magenta('🤖 AI Task Assistant')}  ${chalk.dim('— Use Groq LLMs with guarded local/remote tools')}`,
          value: 'ai',
        },
        {
          name: `${chalk.yellow('🩺 Run Doctor')}  ${chalk.dim('— Diagnose setup and project health')}`,
          value: 'doctor',
        },
        new inquirer.Separator(),
        {
          name: `${chalk.magenta('📖 Help / Information')}   ${chalk.dim('— Learn how iPingYou works')}`,
          value: 'help',
        },
      ],
    },
  ]);

  switch (mode) {
    case 'host': {
      const { startHostMode } = await import('./modes/host.js');
      await startHostMode();
      break;
    }
    case 'client': {
      const { startClientMode } = await import('./modes/client.js');
      await startClientMode();
      break;
    }
    case 'ai': {
      const { startAIMode } = await import('./modes/ai.js');
      await startAIMode();
      break;
    }
    case 'doctor': {
      const { startDoctorMode } = await import('./modes/doctor.js');
      await startDoctorMode();
      break;
    }
    case 'help':
      showRichHelp();
      break;
  }
}

// ─── Commander Setup ─────────────────────────────────────────
const program = new Command();

program
  .name('ipingyou')
  .description('SecureLink-CLI — Secure P2P remote access via SSH & Cloudflare Tunnels')
  .version(packageJson.version)
  .option('-b, --broker <url>', 'Override the central broker URL')
  .addHelpText('beforeAll', () => {
    showBanner();
    showRichHelp();
    return '';
  });

program
  .command('host')
  .description('Start host mode — allow remote access to this machine')
  .option('-q, --qr', 'Display ANSI connection QR Code on startup')
  .option('-r, --read-only', 'Enable Read-Only Shell Mode for guests')
  .option('--record', 'Record interactive SSH session to .cast file')
  .option('--enable-web', 'Start mobile control center Web UI')
  .option('--deny <patterns>', 'Deny dangerous command patterns (e.g. "rm -rf,sudo")')
  .action(async (commandOptions) => {
    try {
      const opts = program.opts();
      if (opts.broker) process.env.BROKER_URL = opts.broker;

      showBanner();
      showSystemInfo();
      installShutdownHandlers();
      await checkDependencies();
      const { startHostMode } = await import('./modes/host.js');
      await startHostMode(commandOptions);
    } catch (err) {
      fatal('host', err);
    }
  });

program
  .command('connect')
  .description('Connect to a remote machine via its UID (SSH or SCP)')
  .option('-u, --uid <uid>', 'The remote host UID')
  .option('-p, --password <password>', 'The session decryption password')
  .option('-l, --limit <speed>', 'Limit SCP transfer speed in Kbit/s')
  .action(async (commandOptions) => {
    try {
      const opts = program.opts();
      if (opts.broker) process.env.BROKER_URL = opts.broker;

      if (commandOptions.uid) {
        const { validateUID } = await import('./lib/mod/uid.js');
        const uidCheck = validateUID(commandOptions.uid);
        if (uidCheck !== true) {
          console.error(`\x1b[31m  ❌ Invalid UID: ${uidCheck}\x1b[0m`);
          process.exit(1);
        }
      }

      showBanner();
      showSystemInfo();
      installShutdownHandlers();
      await checkDependencies();
      const { startClientMode } = await import('./modes/client.js');
      await startClientMode(commandOptions);
    } catch (err) {
      fatal('connect', err);
    }
  });

program
  .command('ai')
  .description('Start AI mode — Groq-powered local/remote task assistant with guarded tools')
  .action(async () => {
    try {
      const opts = program.opts();
      if (opts.broker) process.env.BROKER_URL = opts.broker;

      showBanner();
      showSystemInfo();
      installShutdownHandlers();
      const { startAIMode } = await import('./modes/ai.js');
      await startAIMode();
    } catch (err) {
      fatal('ai', err);
    }
  });

program
  .command('doctor')
  .description('Run non-invasive diagnostics for dependencies, SSH, broker, SCP, AI, and tests')
  .option('--full', 'Run full diagnostics, including broker integration if a local broker is running')
  .action(async (commandOptions) => {
    try {
      const opts = program.opts();
      if (opts.broker) process.env.BROKER_URL = opts.broker;

      showBanner();
      showSystemInfo();
      const { startDoctorMode } = await import('./modes/doctor.js');
      await startDoctorMode({ full: commandOptions.full });
    } catch (err) {
      fatal('doctor', err);
    }
  });

program
  .command('panic')
  .description('🚨 Stop resources and wipe all ipingyou files, logs, caches & keys (preserves cloudflared & ssh)')
  .action(async () => {
    try {
      showBanner();
      const { confirmation } = await inquirer.prompt([{
        type: 'input',
        name: 'confirmation',
        message: 'Type STOP CURRENT SESSION to confirm:',
      }]);
      if (confirmation !== 'STOP CURRENT SESSION') {
        console.log(chalk.yellow('  Emergency shutdown cancelled.'));
        return;
      }
      await executePanicMode();
    } catch (err) {
      fatal('panic', err);
    }
  });

program
  .command('service <action>')
  .description('👻 Manage background daemon (actions: install, stop, status)')
  .action(async (action) => {
    try {
      showBanner();
      console.log(chalk.bold.cyan('  👻 Background Service Manager'));
      console.log(chalk.dim('  ──────────────────────────────────────'));
      
      const { execa } = await import('execa');
      
      if (action === 'install') {
        console.log(chalk.dim('  Scanning and installing PM2 through Socket Firewall...'));
        await runProtectedNpmInstall(['-g', 'pm2'], { stdio: 'inherit' });
        await execa('pm2', ['start', 'ipingyou', '--name', 'ipingyou-host', '--', 'host'], { stdio: 'inherit' });
        await execa('pm2', ['save'], { stdio: 'inherit' });
        await execa('pm2', ['startup'], { stdio: 'inherit' });
        console.log(chalk.green('\n  ✅ Service installed and running in the background.'));
      } else if (action === 'stop') {
        await execa('pm2', ['stop', 'ipingyou-host'], { stdio: 'inherit' });
        await execa('pm2', ['delete', 'ipingyou-host'], { stdio: 'inherit' });
        await execa('pm2', ['save'], { stdio: 'inherit' });
        console.log(chalk.green('\n  ✅ Service stopped and removed.'));
      } else if (action === 'status') {
        await execa('pm2', ['status', 'ipingyou-host'], { stdio: 'inherit' });
      } else {
        console.log(chalk.red(`  ❌ Unknown action: ${action}. Use install, stop, or status.`));
      }
    } catch (err) {
      fatal('service', err);
    }
  });

program
  .command('security-status')
  .description('Check Socket Firewall protection for future npm installations')
  .action(async () => {
    try {
      showBanner();
      const status = await getSocketFirewallStatus();
      if (!status.available) {
        console.log(chalk.yellow('  ⚠️  Socket Firewall is not available.'));
        console.log(chalk.dim('     Install it with: npm install -g sfw'));
        process.exitCode = 1;
        return;
      }
      console.log(chalk.green(`  ✅ Socket Firewall active${status.version ? ` (${status.version})` : ''}`));
      console.log(chalk.dim('     In-app npm installations are routed through: sfw npm install'));
    } catch (err) {
      fatal('security-status', err);
    }
  });

program
  .command('allowlist')
  .description('Manage AI command allowlist — add, remove, or list safe regex patterns')
  .argument('[action]', 'Action: list, add, remove', 'list')
  .argument('[pattern]', 'Regex pattern to add or remove')
  .action(async (action, pattern) => {
    try {
      showBanner();
      const fs = await import('node:fs');
      const os = await import('node:os');
      const path = await import('node:path');
      const { ensureAllowlistFile, getAllowlistRegexes } = await import('./lib/mod/allowlist.js');

      const allowlistPath = ensureAllowlistFile();

      if (action === 'list' || !action) {
        const patterns = getAllowlistRegexes();
        console.log(chalk.bold.cyan('  📋 AI Command Allowlist'));
        console.log(chalk.dim('  ─────────────────────────────────────'));
        console.log(chalk.dim(`  File: ${allowlistPath}`));
        console.log('');
        if (patterns.length === 0) {
          console.log(chalk.dim('  No patterns configured.'));
        } else {
          try {
            const raw = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
            raw.forEach((p, i) => {
              console.log(`  ${chalk.green(i + 1)}. ${chalk.white(p)}`);
            });
          } catch (e) {
            console.log(chalk.red('  ❌ Allowlist file is corrupted.'));
          }
        }
        console.log('');
        console.log(chalk.dim('  Usage: ipingyou allowlist add "^my-safe-command"'));
        console.log(chalk.dim('         ipingyou allowlist remove "^my-safe-command"'));
      } else if (action === 'add') {
        if (!pattern) {
          console.log(chalk.red('  ❌ Missing pattern. Usage: ipingyou allowlist add "^my-command"'));
          process.exit(1);
        }
        // Validate regex
        try { new RegExp(pattern); } catch (err) {
          console.log(chalk.red(`  ❌ Invalid regex: ${err.message}`));
          process.exit(1);
        }
        let raw = [];
        try { raw = JSON.parse(fs.readFileSync(allowlistPath, 'utf8')); } catch {}
        if (raw.includes(pattern)) {
          console.log(chalk.yellow(`  ⚠️  Pattern already exists: ${pattern}`));
        } else {
          raw.push(pattern);
          fs.writeFileSync(allowlistPath, JSON.stringify(raw, null, 2), { mode: 0o600 });
          console.log(chalk.green(`  ✅ Added: ${chalk.white(pattern)}`));
        }
      } else if (action === 'remove') {
        if (!pattern) {
          console.log(chalk.red('  ❌ Missing pattern. Usage: ipingyou allowlist remove "^my-command"'));
          process.exit(1);
        }
        let raw = [];
        try { raw = JSON.parse(fs.readFileSync(allowlistPath, 'utf8')); } catch {}
        const idx = raw.indexOf(pattern);
        if (idx === -1) {
          console.log(chalk.yellow(`  ⚠️  Pattern not found: ${pattern}`));
        } else {
          raw.splice(idx, 1);
          fs.writeFileSync(allowlistPath, JSON.stringify(raw, null, 2), { mode: 0o600 });
          console.log(chalk.green(`  ✅ Removed: ${chalk.white(pattern)}`));
        }
      } else {
        console.log(chalk.red(`  ❌ Unknown action: ${action}. Use list, add, or remove.`));
      }
    } catch (err) {
      fatal('allowlist', err);
    }
  });

program
  .command('history')
  .description('View session event logs from ~/.ipingyou/logs')
  .option('-n, --lines <count>', 'Number of recent events to show', '25')
  .option('--type <type>', 'Filter by event type (e.g. ssh, scp, ai)')
  .option('--json', 'Output raw JSON lines')
  .option('--ai-summary', 'Generate Groq AI post-session executive summary')
  .option('--export <format>', 'Export signed audit log (json or csv)')
  .option('--verify <file>', 'Verify cryptographic signature of audit file')
  .action(async (commandOptions) => {
    try {
      showBanner();

      if (commandOptions.aiSummary) {
        const { generateAiSessionSummary } = await import('./lib/services/aisummary.js');
        await generateAiSessionSummary();
        return;
      }

      if (commandOptions.export) {
        const { exportSignedAuditLog } = await import('./lib/services/auditSigner.js');
        exportSignedAuditLog(commandOptions.export);
        return;
      }

      if (commandOptions.verify) {
        const { verifySignedAuditLog } = await import('./lib/services/auditSigner.js');
        verifySignedAuditLog(commandOptions.verify);
        return;
      }

      const fs = await import('node:fs');
      const os = await import('node:os');
      const pathMod = await import('node:path');

      const logFile = pathMod.default.join(os.default.homedir(), '.ipingyou', 'logs', 'session-events.jsonl');

      console.log(chalk.bold.cyan('  📜 Session Event History'));
      console.log(chalk.dim('  ─────────────────────────────────────'));

      if (!fs.existsSync(logFile)) {
        console.log(chalk.dim('  No session history found yet.'));
        console.log(chalk.dim(`  Events are recorded to: ${logFile}`));
        return;
      }

      const parsedCount = Number.parseInt(commandOptions.lines, 10);
      const count = Number.isFinite(parsedCount) ? Math.max(1, Math.min(parsedCount, 10000)) : 25;
      const filter = commandOptions.type?.toLowerCase();
      const events = [];
      let totalEvents = 0;
      const lines = readline.createInterface({
        input: fs.createReadStream(logFile, { encoding: 'utf8' }),
        crlfDelay: Infinity,
      });
      for await (const line of lines) {
        if (!line.trim()) continue;
        totalEvents += 1;
        try {
          const event = JSON.parse(line);
          if (filter && !(event.type || '').toLowerCase().includes(filter)) continue;
          events.push(event);
          if (events.length > count) events.shift();
        } catch {
          // Ignore incomplete or invalid log lines.
        }
      }

      if (events.length === 0) {
        console.log(chalk.dim('  No matching events found.'));
        return;
      }

      console.log(chalk.dim(`  Showing last ${events.length} event(s)${commandOptions.type ? ` matching "${commandOptions.type}"` : ''}:`));
      console.log('');

      if (commandOptions.json) {
        events.forEach(e => console.log(JSON.stringify(e)));
      } else {
        const levelColors = {
          info: chalk.blue,
          warn: chalk.yellow,
          error: chalk.red,
        };

        events.forEach(e => {
          const time = e.time ? new Date(e.time).toLocaleString() : '?';
          const level = (e.level || 'info').toUpperCase().padEnd(5);
          const colorFn = levelColors[e.level] || chalk.white;
          const type = chalk.cyan((e.type || 'unknown').padEnd(35));
          const details = e.details && Object.keys(e.details).length > 0
            ? chalk.dim(JSON.stringify(e.details))
            : '';

          console.log(`  ${chalk.dim(time)}  ${colorFn(level)}  ${type}  ${details}`);
        });
      }

      console.log('');
      console.log(chalk.dim(`  Log file: ${logFile}`));
      console.log(chalk.dim(`  Total events in file: ${totalEvents}`));
    } catch (err) {
      fatal('history', err);
    }
  });

// ─── Default: interactive mode ──────────────────────────────
program.action(async () => {
  try {
    const opts = program.opts();
    if (opts.broker) process.env.BROKER_URL = opts.broker;

    installShutdownHandlers();
    await interactiveMode();
  } catch (err) {
    fatal('interactive', err);
  }
});

program.parse();
