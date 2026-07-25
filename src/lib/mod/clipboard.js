/**
 * ============================================================
 *  OS Native Clipboard Auto-Copy Module
 * ============================================================
 *  Copies text directly to system clipboard on macOS, Linux, Windows.
 * ============================================================
 */

import { execa } from 'execa';
import chalk from 'chalk';

/**
 * Copies a string to the system clipboard asynchronously.
 * @param {string} text 
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  if (!text) return false;

  try {
    let command = '';
    let args = [];

    if (process.platform === 'darwin') {
      command = 'pbcopy';
    } else if (process.platform === 'win32') {
      command = 'clip';
    } else {
      // Linux / BSD — try xclip first
      command = 'xclip';
      args = ['-selection', 'clipboard'];
    }

    await execa(command, args, {
      input: text,
      reject: true,
      timeout: 3000,
    });
    return true;
  } catch {
    // Fallback for Linux: try xsel if xclip failed
    if (process.platform !== 'darwin' && process.platform !== 'win32') {
      try {
        await execa('xsel', ['-b'], {
          input: text,
          reject: true,
          timeout: 3000,
        });
        return true;
      } catch {}
    }
    return false;
  }
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
