/**
 * ============================================================
 *  OS Native Clipboard Auto-Copy Module
 * ============================================================
 *  Copies text directly to system clipboard on macOS, Linux, Windows.
 * ============================================================
 */

import { exec } from 'child_process';
import chalk from 'chalk';

/**
 * Copies a string to the system clipboard asynchronously.
 * @param {string} text 
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  if (!text) return false;

  return new Promise((resolve) => {
    let command = '';

    if (process.platform === 'darwin') {
      command = 'pbcopy';
    } else if (process.platform === 'win32') {
      command = 'clip';
    } else {
      // Linux / BSD
      command = 'xclip -selection clipboard || xsel -b';
    }

    try {
      const proc = exec(command, (err) => {
        if (err) resolve(false);
        else resolve(true);
      });

      if (proc.stdin) {
        proc.stdin.write(text);
        proc.stdin.end();
      } else {
        resolve(false);
      }
    } catch {
      resolve(false);
    }
  });
}

/**
 * Helper to copy connect command and display confirmation.
 * @param {string} commandText 
 */
export async function autoCopyConnectCommand(commandText) {
  const success = await copyToClipboard(commandText);
  if (success) {
    console.log(chalk.bold.green('  📋 Quick Connect command copied to clipboard! (Ready to paste)'));
  }
}
