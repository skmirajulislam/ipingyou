/**
 * Doctor Mode — non-invasive diagnostics for iPingYou.
 */

import { execa } from 'execa';
import chalk from 'chalk';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { commandExists, detectOS, isLinuxSSHActive } from '../lib/services/platform.js';
import { pingBroker } from '../lib/client/broker.js';
import { classifyCommand, redactSensitive } from '../lib/ai/safety.js';

let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

const results = [];

function record(status, name, detail = '', hint = '') {
  results.push({ status, name, detail, hint });
  const icon = {
    pass: chalk.green('✓'),
    warn: chalk.yellow('!'),
    fail: chalk.red('✗'),
    skip: chalk.dim('-'),
  }[status] || chalk.dim('-');

  const coloredName = status === 'fail'
    ? chalk.red(name)
    : status === 'warn'
      ? chalk.yellow(name)
      : status === 'skip'
        ? chalk.dim(name)
        : chalk.white(name);

  console.log(`  ${icon} ${coloredName}${detail ? chalk.dim(` — ${detail}`) : ''}`);
  if (hint) console.log(chalk.dim(`     ${hint}`));
}

async function check(name, fn) {
  try {
    const outcome = await fn();
    if (typeof outcome === 'string') record('pass', name, outcome);
    else record(outcome.status || 'pass', name, outcome.detail || '', outcome.hint || '');
  } catch (err) {
    record('fail', name, redactSensitive(err.message));
  }
}

async function commandVersion(command, args = ['--version']) {
  if (!(await commandExists(command))) {
    return { status: 'fail', detail: 'missing', hint: `Install ${command} and ensure it is on PATH.` };
  }

  const result = await execa(command, args, { reject: false, timeout: 5000 });
  const output = (result.stdout || result.stderr || '').split(/\r?\n/)[0].trim();
  return { status: 'pass', detail: output || 'found' };
}

async function commandFound(command) {
  if (!(await commandExists(command))) {
    return { status: 'fail', detail: 'missing', hint: `Install ${command} and ensure it is on PATH.` };
  }
  return { status: 'pass', detail: 'found' };
}

async function checkSshService() {
  const osInfo = detectOS();
  if (osInfo.isMac) {
    const launchctl = await execa('launchctl', ['print-disabled', 'system'], { reject: false, timeout: 5000 });
    const launchctlOutput = `${launchctl.stdout || ''}\n${launchctl.stderr || ''}`.toLowerCase();
    const launchctlMatch = launchctlOutput.match(/"com\.openssh\.sshd"\s*=>\s*(enabled|disabled)/);
    if (launchctlMatch) {
      if (launchctlMatch[1] === 'enabled') return { status: 'pass', detail: 'Remote Login is enabled' };
      return {
        status: 'warn',
        detail: 'Remote Login appears off',
        hint: 'Enable System Settings → General → Sharing → Remote Login before hosting SSH.',
      };
    }

    const result = await execa('systemsetup', ['-getremotelogin'], { reject: false, timeout: 5000 });
    const output = result.stdout || result.stderr || '';
    if (/on/i.test(output)) return { status: 'pass', detail: 'Remote Login is on' };
    if (/off/i.test(output)) {
      return {
        status: 'warn',
        detail: 'Remote Login appears off',
        hint: 'Enable System Settings → General → Sharing → Remote Login before hosting SSH.',
      };
    }
    return {
      status: 'warn',
      detail: 'Could not determine Remote Login state',
      hint: 'macOS may require admin permission to query this setting.',
    };
  }

  if (osInfo.isLinux) {
    const active = await isLinuxSSHActive();
    if (active) return { status: 'pass', detail: 'SSH service is active' };
    return {
      status: 'warn',
      detail: 'SSH service is not reported active',
      hint: 'Run `sudo systemctl start ssh`, `sudo service ssh start` or equivalent before hosting.',
    };
  }

  if (osInfo.isWindows) {
    const result = await execa('sc', ['query', 'sshd'], { reject: false, timeout: 5000 });
    if (/RUNNING/i.test(result.stdout)) return { status: 'pass', detail: 'OpenSSH Server is running' };
    return {
      status: 'warn',
      detail: 'OpenSSH Server is not reported running',
      hint: 'Start OpenSSH Server from Services before hosting.',
    };
  }

  return { status: 'skip', detail: 'unsupported OS check' };
}

async function checkEphemeralKeyParse() {
  if (!(await commandExists('ssh-keygen'))) {
    return { status: 'skip', detail: 'ssh-keygen missing' };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipingyou-doctor-key-'));
  const keyPath = path.join(dir, 'key');
  try {
    const generated = await execa('ssh-keygen', ['-t', 'ed25519', '-C', 'ipingyou-doctor', '-f', keyPath, '-N', ''], {
      reject: false,
      timeout: 10000,
    });
    if (generated.exitCode !== 0) {
      return { status: 'fail', detail: generated.stderr.trim() || 'ssh-keygen failed' };
    }

    const parsed = await execa('ssh-keygen', ['-y', '-f', keyPath], { reject: false, timeout: 10000 });
    if (parsed.exitCode !== 0) {
      return { status: 'fail', detail: parsed.stderr.trim() || 'generated key could not be parsed' };
    }

    return { status: 'pass', detail: 'generated ed25519 key parses correctly' };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function checkConfigDirectory() {
  const configDir = path.join(os.homedir(), '.ipingyou');
  if (!fs.existsSync(configDir)) return { status: 'pass', detail: 'no config directory yet' };
  const stat = fs.statSync(configDir);
  if (!stat.isDirectory()) return { status: 'fail', detail: `${configDir} is not a directory` };
  return { status: 'pass', detail: configDir };
}

function checkTempDirectory() {
  const tmp = os.tmpdir();
  const probe = path.join(tmp, `ipingyou-doctor-${Date.now()}`);
  fs.writeFileSync(probe, 'ok', { mode: 0o600 });
  fs.unlinkSync(probe);
  return { status: 'pass', detail: tmp };
}

function checkMacPrivacyHints() {
  if (process.platform !== 'darwin') return { status: 'skip', detail: 'not macOS' };
  const protectedDirs = ['Downloads', 'Desktop', 'Documents']
    .map(name => path.join(os.homedir(), name))
    .filter(dir => fs.existsSync(dir));

  if (protectedDirs.length === 0) return { status: 'skip', detail: 'no standard protected folders found' };
  return {
    status: 'skip',
    detail: 'macOS protected folder note',
    hint: 'Prefer the iPingYou drop folder, or grant Full Disk Access to sshd/Remote Login.',
  };
}

function checkAiSafety() {
  const cases = [
    ['pwd', false],
    ['cat .env', true],
    ['printenv', true],
    ['cat ~/.ssh/id_ed25519', true],
    ['cat ~/.ipingyou/config.json', true],
  ];

  for (const [command, shouldBlock] of cases) {
    const result = classifyCommand(command);
    if (result.blocked !== shouldBlock) {
      return { status: 'fail', detail: `AI safety mismatch for ${command}` };
    }
  }

  return { status: 'pass', detail: 'secret path/command guards active' };
}

async function runProjectSelfTest(label, command) {
  // Prefer splitting simple commands into args to avoid shell interpolation
  const parts = String(command).split(' ').filter(Boolean);
  const cmd = parts.shift();
  const args = parts;
  const result = await execa(cmd, args, {
    reject: false,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });

  if (result.exitCode === 0) return { status: 'pass', detail: label };
  return {
    status: 'fail',
    detail: `${label} failed`,
    hint: redactSensitive((result.stderr || result.stdout || '').split(/\r?\n/).slice(-4).join(' ')),
  };
}

export async function startDoctorMode(options = {}) {
  BROKER_URL = process.env.BROKER_URL || BROKER_URL;
  results.length = 0;

  console.log('');
  console.log(chalk.bold.cyan('  🩺 iPingYou Doctor'));
  console.log(chalk.dim('  ─────────────────────────────────────'));
  console.log(chalk.dim('  Non-invasive diagnostics. Doctor reports issues but does not install, delete, or change settings.'));
  console.log('');

  const osInfo = detectOS();
  record('pass', 'Runtime', `${osInfo.platform} ${osInfo.arch}, Node ${process.version}, host ${osInfo.hostname}`);

  console.log(chalk.bold('\n  Core tools'));
  await check('ssh client', () => commandVersion('ssh', ['-V']));
  await check('scp client', () => commandFound('scp'));
  await check('ssh-keygen', () => commandFound('ssh-keygen'));
  await check('cloudflared', () => commandVersion('cloudflared', ['--version']));
  await check('tmux', () => commandVersion('tmux', ['-V']));

  console.log(chalk.bold('\n  Host readiness'));
  await check('SSH service', checkSshService);
  await check('Ephemeral SSH key parse', checkEphemeralKeyParse);
  await check('Temporary directory writable', checkTempDirectory);
  await check('Config directory', checkConfigDirectory);
  await check('macOS protected folder note', checkMacPrivacyHints);

  console.log(chalk.bold('\n  Broker'));
  await check(`Broker health (${BROKER_URL})`, async () => {
    const ok = await pingBroker(BROKER_URL);
    return ok
      ? { status: 'pass', detail: 'reachable' }
      : { status: 'warn', detail: 'unreachable', hint: 'Use a private broker or check your network/BROKER_URL.' };
  });

  console.log(chalk.bold('\n  AI mode'));
  await check('Groq API key', () => process.env.GROQ_API_KEY
    ? { status: 'pass', detail: 'GROQ_API_KEY is set' }
    : { status: 'warn', detail: 'GROQ_API_KEY is not set', hint: 'AI mode will ask for it interactively and keep it in memory only.' });
  await check('AI safety rules', checkAiSafety);

  console.log(chalk.bold('\n  Project self-tests'));
  await check('CLI syntax', () => runProjectSelfTest('node --check src/cli.js', 'node --check src/cli.js'));
  await check('AI syntax', () => runProjectSelfTest('node --check src/modes/ai.js', 'node --check src/modes/ai.js'));
  await check('Crypto proof', () => runProjectSelfTest('node test/test_e2e_crypto.js', 'node test/test_e2e_crypto.js'));

  if (options.full) {
    await check('Broker integration', async () => {
      const localBroker = await pingBroker('http://localhost:4000');
      if (!localBroker) {
        return {
          status: 'skip',
          detail: 'localhost:4000 broker is not running',
          hint: 'Start `node src/server.js` in another terminal, then rerun `ipingyou doctor --full`.',
        };
      }
      return runProjectSelfTest('node test/test_broker_integration.js', 'node test/test_broker_integration.js');
    });
  } else {
    record('skip', 'Broker integration', 'run `ipingyou doctor --full` with local broker running');
  }

  const counts = results.reduce((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1;
    return acc;
  }, {});

  console.log('');
  console.log(chalk.bold('  Summary'));
  console.log(chalk.dim('  ─────────────────────────────────────'));
  console.log(`  ${chalk.green(`${counts.pass || 0} pass`)}  ${chalk.yellow(`${counts.warn || 0} warn`)}  ${chalk.red(`${counts.fail || 0} fail`)}  ${chalk.dim(`${counts.skip || 0} skip`)}`);

  if (counts.fail) {
    console.log(chalk.red('\n  Doctor found failures that should be fixed before release.'));
    process.exitCode = 1;
  } else if (counts.warn) {
    console.log(chalk.yellow('\n  Doctor found warnings. The app can run, but review the notes above.'));
  } else {
    console.log(chalk.green('\n  Doctor found no issues. Looking crisp.'));
  }
}
