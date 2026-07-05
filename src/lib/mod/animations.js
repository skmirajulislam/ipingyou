/**
 * ============================================================
 *  CLI Animations & Visual Effects
 * ============================================================
 *  Custom spinners, progress bars, and animated text effects
 *  for a premium CLI experience.
 * ============================================================
 */

import chalk from 'chalk';
import ora from 'ora';

// ─── Custom Spinner Frames ────────────────────────────────────

/** Cyber-themed spinner for encryption operations */
export const cryptoSpinner = {
  interval: 100,
  frames: [
    chalk.green('🔐 ▰▱▱▱▱▱▱'),
    chalk.green('🔐 ▰▰▱▱▱▱▱'),
    chalk.green('🔐 ▰▰▰▱▱▱▱'),
    chalk.green('🔐 ▰▰▰▰▱▱▱'),
    chalk.green('🔐 ▰▰▰▰▰▱▱'),
    chalk.green('🔐 ▰▰▰▰▰▰▱'),
    chalk.green('🔐 ▰▰▰▰▰▰▰'),
    chalk.cyan('🔓 ▰▰▰▰▰▰▰'),
  ],
};

/** Network pulse for connection operations */
export const networkSpinner = {
  interval: 120,
  frames: [
    chalk.cyan('📡 ·     '),
    chalk.cyan('📡 ··    '),
    chalk.cyan('📡 ···   '),
    chalk.cyan('📡 ····  '),
    chalk.cyan('📡 ····· '),
    chalk.cyan('📡 ······'),
    chalk.blue('📡 ─────→'),
    chalk.green('📡 ═════►'),
  ],
};

/** Tunnel establishment animation */
export const tunnelSpinner = {
  interval: 150,
  frames: [
    chalk.yellow('🌐 ╸       '),
    chalk.yellow('🌐 ═╸      '),
    chalk.yellow('🌐 ══╸     '),
    chalk.cyan('🌐 ═══╸    '),
    chalk.cyan('🌐 ════╸   '),
    chalk.blue('🌐 ═════╸  '),
    chalk.blue('🌐 ══════╸ '),
    chalk.green('🌐 ═══════►'),
  ],
};

/** File transfer animation */
export const fileTransferSpinner = {
  interval: 100,
  frames: [
    chalk.yellow('📦 [          ] 0%  '),
    chalk.yellow('📦 [█         ] 10% '),
    chalk.yellow('📦 [██        ] 20% '),
    chalk.cyan(  '📦 [███       ] 30% '),
    chalk.cyan(  '📦 [████      ] 40% '),
    chalk.cyan(  '📦 [█████     ] 50% '),
    chalk.blue(  '📦 [██████    ] 60% '),
    chalk.blue(  '📦 [███████   ] 70% '),
    chalk.green( '📦 [████████  ] 80% '),
    chalk.green( '📦 [█████████ ] 90% '),
    chalk.green( '📦 [██████████] 100%'),
  ],
};

/** SSH handshake animation */
export const sshSpinner = {
  interval: 130,
  frames: [
    chalk.yellow('🔑 ·         '),
    chalk.yellow('🔑 ··        '),
    chalk.cyan(  '🔑 ···       '),
    chalk.cyan(  '🔑 ····      '),
    chalk.blue(  '🔑 ·····     '),
    chalk.blue(  '🔑 ······    '),
    chalk.green( '🔑 ·······   '),
    chalk.green( '🔑 ✓ verified'),
  ],
};

// ─── Animated Spinner Helpers ─────────────────────────────────

/**
 * Create a styled ora spinner with a custom animation.
 * @param {string} text  — spinner label
 * @param {object} spinnerDef — { interval, frames }
 * @returns {import('ora').Ora}
 */
export function createSpinner(text, spinnerDef) {
  return ora({ text, spinner: spinnerDef });
}

/**
 * Animated multi-step progress display.
 * Runs through each step with a delay and animation.
 *
 * @param {Array<{text: string, duration: number, spinner?: object}>} steps
 */
export async function animatedSteps(steps) {
  for (const step of steps) {
    const spinnerDef = step.spinner || networkSpinner;
    const spinner = ora({ text: step.text, spinner: spinnerDef }).start();
    await sleep(step.duration);
    spinner.succeed(step.text);
  }
}

/**
 * Display an animated connection trace.
 * Shows a visual path from local → tunnel → remote.
 */
export async function showConnectionTrace(localLabel, remoteLabel) {
  const width = 40;
  const steps = [
    { pos: 0,  char: '╸',  color: chalk.yellow },
    { pos: 5,  char: '══╸', color: chalk.yellow },
    { pos: 10, char: '════╸', color: chalk.cyan },
    { pos: 15, char: '══════╸', color: chalk.cyan },
    { pos: 20, char: '════════╸', color: chalk.blue },
    { pos: 25, char: '══════════╸', color: chalk.blue },
    { pos: 30, char: '════════════╸', color: chalk.green },
    { pos: 35, char: '══════════════►', color: chalk.green },
  ];

  console.log('');
  console.log(chalk.dim('  ┌─────────────────────────────────────────────────────┐'));
  console.log(chalk.dim('  │') + `  ${chalk.cyan(localLabel)}  →  ${chalk.magenta('☁ Cloudflare')}  →  ${chalk.green(remoteLabel)}  ` + chalk.dim('│'));
  console.log(chalk.dim('  └─────────────────────────────────────────────────────┘'));

  for (const step of steps) {
    const line = `  ${step.color(step.char)}`;
    process.stdout.write(`\r${line}`);
    await sleep(120);
  }
  process.stdout.write('\r' + ' '.repeat(60) + '\r');
}

/**
 * Show a pulsing "LIVE" indicator.
 * @param {string} message
 * @param {number} pulses — how many times to pulse
 */
export async function pulseText(message, pulses = 3) {
  const colors = [chalk.red.bold, chalk.red, chalk.yellow, chalk.green, chalk.green.bold];
  for (let i = 0; i < pulses; i++) {
    for (const colorFn of colors) {
      process.stdout.write(`\r  ${colorFn('●')} ${message}`);
      await sleep(100);
    }
  }
  process.stdout.write(`\r  ${chalk.green.bold('●')} ${message}\n`);
}

/**
 * Typing effect — prints text character by character.
 * @param {string} text
 * @param {number} charDelay — ms per character
 */
export async function typeText(text, charDelay = 25) {
  for (const char of text) {
    process.stdout.write(char);
    await sleep(charDelay);
  }
  console.log('');
}

/**
 * Draw a gradient progress bar.
 * @param {number} percent — 0-100
 * @param {number} width   — bar width in chars
 */
export function progressBar(percent, width = 30) {
  const filled = Math.round((percent / 100) * width);
  const empty = width - filled;
  const filledStr = '█'.repeat(filled);
  const emptyStr = '░'.repeat(empty);

  let coloredFilled;
  if (percent < 30) coloredFilled = chalk.red(filledStr);
  else if (percent < 60) coloredFilled = chalk.yellow(filledStr);
  else if (percent < 90) coloredFilled = chalk.cyan(filledStr);
  else coloredFilled = chalk.green(filledStr);

  return `${coloredFilled}${chalk.dim(emptyStr)} ${chalk.white.bold(`${percent}%`)}`;
}

/**
 * Simulate a file transfer progress animation.
 * @param {string} filename
 * @param {string} direction — 'upload' or 'download'
 * @param {number} durationMs — total animation time
 */
export async function simulateTransferProgress(filename, direction, durationMs = 2000) {
  const icon = direction === 'upload' ? '📤' : '📥';
  const verb = direction === 'upload' ? 'Sending' : 'Receiving';
  const steps = 20;
  const stepDelay = durationMs / steps;

  console.log('');
  for (let i = 0; i <= steps; i++) {
    const pct = Math.round((i / steps) * 100);
    const bar = progressBar(pct);
    process.stdout.write(`\r  ${icon} ${verb} ${chalk.white.bold(filename)}  ${bar}`);
    await sleep(stepDelay);
  }
  console.log('');
  console.log(`  ${chalk.green('✓')} ${verb} complete: ${chalk.cyan(filename)}`);
}

// ─── Utility ──────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
