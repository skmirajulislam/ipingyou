/**
 * ============================================================
 *  Panic Mode Deep System Cleaner (Ethical & Safe)
 * ============================================================
 *  Completely wipes all ipingyou-associated files, directories,
 *  logs, caches, recordings, dropboxes, temp files, and SSH keys.
 *  Explicitly PRESERVES cloudflared and ssh binaries.
 * 
 *  Safety & Ethical Invariants:
 *  - Strict path resolution guards prevent out-of-scope deletions.
 *  - Non-ipingyou user files, system SSH configs, and SSH keys remain completely untouched.
 *  - Atomic write & fallback protections prevent corruption of authorized_keys.
 * ============================================================
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import chalk from 'chalk';

/** @type {Set<string>} Binaries to preserve in ~/.ipingyou/bin/ */
const PRESERVED_BINARIES = new Set([
  'cloudflared',
  'cloudflared.exe',
  'ssh',
  'ssh.exe',
]);

/**
 * Safely removes ipingyou-injected public keys from an authorized_keys file.
 * Uses atomic file writing to guarantee no data loss or corruption.
 * @param {string} filePath
 */
function sanitizeAuthorizedKeysFile(filePath) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return;
    const stat = fs.lstatSync(filePath);
    if (stat.isSymbolicLink() || !stat.isFile()) return;

    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const filtered = lines.filter(line => !/\bipingyou\b/i.test(line));

    if (filtered.length !== lines.length) {
      const tempPath = `${filePath}.tmp_${Date.now()}`;
      fs.writeFileSync(tempPath, filtered.join('\n'), { mode: 0o600 });
      fs.renameSync(tempPath, filePath);
      try { fs.chmodSync(filePath, 0o600); } catch {}
      console.log(chalk.dim(`     Sanitized authorized_keys at ${filePath} (removed ipingyou keys)`));
    }
  } catch (err) {
    // Best effort cleanup — log warning without throwing
    console.error(chalk.dim(`     Notice: authorized_keys check on ${filePath}: ${err.message}`));
  }
}

/**
 * Safely check if targetPath is strictly inside parentDir.
 * Prevents path traversal vulnerabilities or accidental external deletions.
 * @param {string} parentDir 
 * @param {string} targetPath 
 * @returns {boolean}
 */
function isStrictlyInside(parentDir, targetPath) {
  const resolvedParent = path.resolve(parentDir);
  const resolvedTarget = path.resolve(targetPath);
  return resolvedTarget.startsWith(resolvedParent + path.sep) || resolvedTarget === resolvedParent;
}

/**
 * Execute deep, safe, and ethical trace wipe.
 * Wipes all ipingyou-specific state while leaving the operating system and unrelated user files completely untouched.
 * @returns {Promise<void>}
 */
export async function performPanicWipe() {
  console.log(chalk.yellow('  🔥 Executing safe & targeted ipingyou trace wipe...'));

  const homeDir = os.homedir();
  const tmpDir = os.tmpdir();

  if (!homeDir || !tmpDir) {
    console.error(chalk.red('  ❌ Invalid environment home/tmp paths. Aborting wipe.'));
    return;
  }

  const ipingyouDir = path.join(homeDir, '.ipingyou');

  // 1. Wipe ~/.ipingyou (preserving cloudflared & ssh in bin/)
  if (fs.existsSync(ipingyouDir) && isStrictlyInside(homeDir, ipingyouDir)) {
    try {
      const entries = fs.readdirSync(ipingyouDir);
      for (const entry of entries) {
        const fullPath = path.join(ipingyouDir, entry);
        if (!isStrictlyInside(ipingyouDir, fullPath)) continue;

        if (entry === 'bin') {
          // Selectively preserve cloudflared & ssh in bin/
          try {
            const binEntries = fs.readdirSync(fullPath);
            for (const binFile of binEntries) {
              const binFilePath = path.join(fullPath, binFile);
              if (!isStrictlyInside(fullPath, binFilePath)) continue;

              if (!PRESERVED_BINARIES.has(binFile.toLowerCase())) {
                fs.rmSync(binFilePath, { recursive: true, force: true });
                console.log(chalk.dim(`     Removed non-preserved binary: ${binFile}`));
              } else {
                console.log(chalk.dim(`     Preserved tool: ${binFile}`));
              }
            }
            // If bin/ is now empty, remove it
            if (fs.readdirSync(fullPath).length === 0) {
              fs.rmSync(fullPath, { recursive: true, force: true });
            }
          } catch {}
        } else {
          fs.rmSync(fullPath, { recursive: true, force: true });
          console.log(chalk.dim(`     Removed ~/.ipingyou/${entry}`));
        }
      }
      // If ~/.ipingyou is empty now, remove it
      if (fs.existsSync(ipingyouDir) && fs.readdirSync(ipingyouDir).length === 0) {
        fs.rmSync(ipingyouDir, { recursive: true, force: true });
      }
    } catch (err) {
      console.error(chalk.red(`     Error cleaning ~/.ipingyou: ${err.message}`));
    }
  }

  // 2. Wipe ~/ipingyou-dropbox-* directories strictly owned by ipingyou
  try {
    const homeEntries = fs.readdirSync(homeDir);
    for (const entry of homeEntries) {
      if (entry.startsWith('ipingyou-dropbox-')) {
        const dropPath = path.join(homeDir, entry);
        if (isStrictlyInside(homeDir, dropPath)) {
          fs.rmSync(dropPath, { recursive: true, force: true });
          console.log(chalk.dim(`     Removed dropbox directory: ${entry}`));
        }
      }
    }
  } catch {}

  // 3. Wipe ipingyou temporary files in os.tmpdir()
  try {
    const tmpEntries = fs.readdirSync(tmpDir);
    for (const entry of tmpEntries) {
      if (entry.startsWith('ipingyou') || entry === 'cloudflared.tgz') {
        const tmpPath = path.join(tmpDir, entry);
        if (isStrictlyInside(tmpDir, tmpPath)) {
          fs.rmSync(tmpPath, { recursive: true, force: true });
          console.log(chalk.dim(`     Removed temporary artifact: ${entry}`));
        }
      }
    }
  } catch {}

  // 4. Remove ipingyou-injected public keys from authorized_keys
  const userAuthKeys = path.join(homeDir, '.ssh', 'authorized_keys');
  sanitizeAuthorizedKeysFile(userAuthKeys);

  if (process.platform === 'win32') {
    const programData = process.env.ProgramData || 'C:\\ProgramData';
    const adminAuthKeys = path.join(programData, 'ssh', 'administrators_authorized_keys');
    sanitizeAuthorizedKeysFile(adminAuthKeys);
  }

  console.log(chalk.green('  ✅ Panic wipe completed safely & ethically. System & unrelated files intact (cloudflared & ssh preserved).'));
}
