/**
 * ============================================================
 *  ANSI Terminal QR Code Generator
 * ============================================================
 *  Renders formatted QR codes / Connection boxes directly
 *  in the terminal using UTF-8 block characters.
 * ============================================================
 */

import chalk from 'chalk';

/**
 * Generate a formatted terminal connection banner and QR/box view.
 * @param {string} uid 
 * @param {string} password 
 * @param {string} [brokerUrl] 
 */
export function generateTerminalQR(uid, password, brokerUrl = '') {
  const connectionCommand = `npx @miraj181/ipingyou@latest connect --uid ${uid} --password ${password}`;

  const border = '█'.repeat(58);
  const padding = '█' + ' '.repeat(56) + '█';

  console.log('');
  console.log(chalk.cyan(`  ${border}`));
  console.log(chalk.cyan(`  ${padding}`));
  console.log(chalk.cyan(`  █`) + chalk.bold.white('    📱 QUICK CONNECT QR & INSTRUCTIONS                 ') + chalk.cyan(`█`));
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
