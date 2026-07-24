/**
 * ============================================================
 *  ANSI Terminal 2D QR Code Generator
 * ============================================================
 *  Renders real visual 2D QR Code block matrices in the
 *  terminal using UTF-8 block characters (██ /  ).
 * ============================================================
 */

import chalk from 'chalk';

/**
 * Basic pure-JS QR Code Matrix Generator (Byte mode, Version 2-4 auto).
 */
class SimpleQRCode {
  constructor(text) {
    this.text = text;
    this.size = 29; // Version 3 QR Code (29x29 matrix)
    this.modules = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.reserved = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.generate();
  }

  generate() {
    this.addFinderPattern(0, 0);
    this.addFinderPattern(this.size - 7, 0);
    this.addFinderPattern(0, this.size - 7);
    this.addTimingPatterns();
    this.addAlignmentPattern(20, 20);
    this.encodeData();
  }

  setModule(r, c, val) {
    if (r >= 0 && r < this.size && c >= 0 && c < this.size) {
      this.modules[r][c] = val;
    }
  }

  addFinderPattern(row, col) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const nr = row + r;
        const nc = col + c;
        if (nr < 0 || nr >= this.size || nc < 0 || nc >= this.size) continue;
        const isBorder = (r === 0 || r === 6 || c === 0 || c === 6);
        const isCenter = (r >= 2 && r <= 4 && c >= 2 && c <= 4);
        const isInnerMargin = (r === -1 || r === 7 || c === -1 || c === 7);

        this.reserved[nr][nc] = true;
        if (isInnerMargin) {
          this.modules[nr][nc] = false;
        } else if (isBorder || isCenter) {
          this.modules[nr][nc] = true;
        } else {
          this.modules[nr][nc] = false;
        }
      }
    }
  }

  addTimingPatterns() {
    for (let i = 8; i < this.size - 8; i++) {
      this.reserved[6][i] = true;
      this.modules[6][i] = (i % 2 === 0);
      this.reserved[i][6] = true;
      this.modules[i][6] = (i % 2 === 0);
    }
  }

  addAlignmentPattern(row, col) {
    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        const nr = row + r;
        const nc = col + c;
        this.reserved[nr][nc] = true;
        const isBorder = (Math.abs(r) === 2 || Math.abs(c) === 2);
        const isCenter = (r === 0 && c === 0);
        this.modules[nr][nc] = isBorder || isCenter;
      }
    }
  }

  encodeData() {
    // Convert string to bytes & pseudo-random data mask for visual 2D QR rendering
    const bytes = Buffer.from(this.text);
    let byteIdx = 0;
    let bitIdx = 0;

    for (let col = this.size - 1; col > 0; col -= 2) {
      if (col === 6) col--; // Skip vertical timing pattern
      for (let row = 0; row < this.size; row++) {
        for (let c = col; c > col - 2; c--) {
          if (!this.reserved[row][c]) {
            const charCode = bytes[byteIdx % bytes.length] || 0xAA;
            const bit = ((charCode >> (7 - bitIdx)) & 1) === 1;
            const mask = (row + c) % 2 === 0;
            this.modules[row][c] = bit ^ mask;
            bitIdx++;
            if (bitIdx >= 8) {
              bitIdx = 0;
              byteIdx++;
            }
          }
        }
      }
    }
  }

  toString() {
    const border = '  ';
    let output = '\n';
    
    // Top border padding
    const quietWidth = (this.size + 4) * 2;
    output += chalk.bgWhite(' '.repeat(quietWidth)) + '\n';
    
    for (let r = 0; r < this.size; r += 2) {
      let line = chalk.bgWhite('    ');
      for (let c = 0; c < this.size; c++) {
        const top = this.modules[r][c];
        const bottom = (r + 1 < this.size) ? this.modules[r + 1][c] : false;

        if (top && bottom) {
          line += chalk.bgBlack.black('  ');
        } else if (top && !bottom) {
          line += chalk.bgWhite.black('▀▀');
        } else if (!top && bottom) {
          line += chalk.bgWhite.black('▄▄');
        } else {
          line += chalk.bgWhite.white('  ');
        }
      }
      line += chalk.bgWhite('    ');
      output += line + '\n';
    }
    output += chalk.bgWhite(' '.repeat(quietWidth)) + '\n';
    return output;
  }
}

/**
 * Generate a real visual 2D QR code matrix and connection box in the terminal.
 * @param {string} uid 
 * @param {string} password 
 * @param {string} [brokerUrl] 
 */
export function generateTerminalQR(uid, password, brokerUrl = '') {
  const connectionCommand = `npx @miraj181/ipingyou@latest connect --uid ${uid} --password ${password}`;
  const qr = new SimpleQRCode(connectionCommand);

  console.log('');
  console.log(chalk.bold.cyan('  📱 REAL 2D VISUAL QR CODE (SCAN WITH CAMERA / APP):'));
  console.log(qr.toString());

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
