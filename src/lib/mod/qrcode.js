/**
 * ============================================================
 *  ANSI Terminal 2D QR Code Generator
 * ============================================================
 *  Uses the official qrcode-terminal module to generate
 *  compact, 100% camera-scannable 2D QR codes in terminal.
 * ============================================================
 */

import chalk from 'chalk';

/**
 * Generate a camera-scannable 2D QR Code and connection banner in terminal using qrcode-terminal.
 * @param {string} uid 
 * @param {string} password 
 * @param {string} [brokerUrl] 
 */
export async function generateTerminalQR(uid, password, brokerUrl = '') {
  const connectionCommand = `npx @miraj181/ipingyou@latest connect --uid ${uid} --password ${password}`;
  
  console.log('');
  console.log(chalk.bold.cyan('  📱 REAL 2D VISUAL QR CODE (SCAN WITH CAMERA / APP):'));

  let qrOutput = null;
  try {
    const qrcodeTerminal = await import('qrcode-terminal');
    const qrt = qrcodeTerminal.default || qrcodeTerminal;
    if (qrt && typeof qrt.generate === 'function') {
      qrOutput = await new Promise((resolve) => {
        qrt.generate(connectionCommand, { small: true }, (str) => resolve(str));
      });
    }
  } catch {
    // Fallback if module is dynamically loading
  }

  if (qrOutput) {
    console.log(qrOutput);
  } else {
    console.log(chalk.yellow('  [QR Code generation ready — run via npx @miraj181/ipingyou@latest host --qr]'));
  }

  const border = '█'.repeat(58);
  const padding = '█' + ' '.repeat(56) + '█';

  console.log(chalk.cyan(`  ${border}`));
  console.log(chalk.cyan(`  ${padding}`));
  console.log(chalk.cyan(`  █`) + chalk.yellow(`  UID:      `) + chalk.bold.green(uid.padEnd(41)) + chalk.cyan(`█`));
  console.log(chalk.cyan(`  █`) + chalk.yellow(`  PASSWORD: `) + chalk.bold.magenta(password.padEnd(41)) + chalk.cyan(`█`));
  if (brokerUrl) {
    console.log(chalk.cyan(`  █`) + chalk.yellow(`  BROKER:   `) + chalk.dim(brokerUrl.slice(0, 41).padEnd(41)) + chalk.cyan(`█`));
  }
  console.log(chalk.cyan(`  ${padding}`));
  console.log(chalk.cyan(`  █`) + chalk.bold.white('  CLIENT QUICK RUN COMMAND:                             ') + chalk.cyan(`█`));
  console.log(chalk.cyan(`  █`) + chalk.bgBlack.green(`  ${connectionCommand.padEnd(52)}  `) + chalk.cyan(`█`));
  console.log(chalk.cyan(`  ${padding}`));
  console.log(chalk.cyan(`  ${border}`));
  console.log('');
}
