/**
 * ============================================================
 *  Platform Detection & Dependency Auto-Bootstrapper
 * ============================================================
 *  Detects OS, ensures download tools exist, then auto-installs
 *  ssh/cloudflared if missing. Bootstraps curl/wget first if
 *  even those are absent.
 * ============================================================
 */

import { execaCommand } from 'execa';
import chalk from 'chalk';
import ora from 'ora';
import os from 'node:os';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { chmod, mkdir, stat, rename } from 'node:fs/promises';
import { join } from 'node:path';

// ─── OS Detection ────────────────────────────────────────────

/**
 * Detect the current operating system.
 * @returns {{ platform: string, isLinux: boolean, isMac: boolean, isWindows: boolean, distro: string|null, arch: string, hostname: string }}
 */
export function detectOS() {
  const platform = process.platform;
  return {
    platform,
    isLinux: platform === 'linux',
    isMac: platform === 'darwin',
    isWindows: platform === 'win32',
    distro: null,
    arch: os.arch(),
    hostname: os.hostname(),
  };
}

/**
 * Detect Linux distribution family.
 * @returns {Promise<string>}  'debian' | 'arch' | 'fedora' | 'unknown'
 */
export async function detectLinuxDistro() {
  try {
    const { stdout } = await execaCommand('cat /etc/os-release', { reject: false });
    const lower = stdout.toLowerCase();
    if (lower.includes('ubuntu') || lower.includes('debian') || lower.includes('kali') || lower.includes('mint')) {
      return 'debian';
    }
    if (lower.includes('arch') || lower.includes('manjaro')) {
      return 'arch';
    }
    if (lower.includes('fedora') || lower.includes('centos') || lower.includes('rhel')) {
      return 'fedora';
    }
  } catch { /* ignore */ }
  return 'unknown';
}

// ─── Utility Helpers ─────────────────────────────────────────

/**
 * Check if a command exists on PATH.
 * @param {string} cmd
 * @returns {Promise<boolean>}
 */
export async function commandExists(cmd) {
  try {
    const checkCmd = process.platform === 'win32' ? `where ${cmd}` : `which ${cmd}`;
    await execaCommand(checkCmd, { reject: true });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if sudo is available (Linux/macOS).
 * @returns {Promise<boolean>}
 */
export async function hasSudo() {
  if (process.platform === 'win32') return false;
  return commandExists('sudo');
}

/**
 * Run a shell command with a spinner.
 * @param {string} label
 * @param {string} cmd
 * @param {object} [opts]
 * @returns {Promise<boolean>}
 */
async function runWithSpinner(label, cmd, opts = {}) {
  const spinner = ora(label).start();
  try {
    await execaCommand(cmd, { stdio: 'pipe', reject: true, ...opts });
    spinner.succeed(label.replace('...', '') + chalk.green(' ✓'));
    return true;
  } catch (err) {
    spinner.fail(label.replace('...', '') + chalk.red(` ✗  ${err.shortMessage || err.message}`));
    return false;
  }
}

/**
 * Resolve the CPU architecture for download URLs.
 * @returns {string}
 */
function resolveArch() {
  const arch = os.arch();
  switch (arch) {
    case 'x64':  return 'amd64';
    case 'arm64': return 'arm64';
    case 'arm':   return 'arm';
    default:      return arch;
  }
}

// ─── Download Tool Bootstrap ─────────────────────────────────

/**
 * Find the first available download tool.
 * @returns {Promise<string|null>}  'curl' | 'wget' | 'powershell' | null
 */
async function findDownloader() {
  for (const tool of ['curl', 'wget']) {
    if (await commandExists(tool)) return tool;
  }
  // Windows fallback: PowerShell is almost always present
  if (process.platform === 'win32') {
    if (await commandExists('powershell')) return 'powershell';
  }
  return null;
}

/**
 * Ensure at least one download tool (curl/wget) is installed.
 * If none exist, install curl using the system package manager.
 * @returns {Promise<string>}  The download tool name that is now available.
 * @throws {Error} If no downloader can be provisioned.
 */
async function ensureDownloader() {
  let tool = await findDownloader();
  if (tool) return tool;

  console.log(chalk.yellow('\n  ⚠️  No download tool found (curl, wget). Bootstrapping curl...\n'));

  const osInfo = detectOS();

  if (osInfo.isLinux) {
    const distro = await detectLinuxDistro();
    const sudo = (await hasSudo()) ? 'sudo ' : '';

    const installCmds = {
      debian: `${sudo}apt-get update -qq && ${sudo}apt-get install -y curl`,
      arch:   `${sudo}pacman -Sy --noconfirm curl`,
      fedora: `${sudo}dnf install -y curl`,
    };

    const cmd = installCmds[distro];
    if (cmd) {
      const ok = await runWithSpinner(`  Installing ${chalk.cyan('curl')} via ${distro} package manager...`, cmd);
      if (ok) return 'curl';
    }
  } else if (osInfo.isMac) {
    // macOS: curl ships with Xcode CLT. If truly missing, try xcode-select.
    const ok = await runWithSpinner(
      `  Installing ${chalk.cyan('Xcode Command Line Tools')} (includes curl)...`,
      'xcode-select --install'
    );
    if (ok || await commandExists('curl')) return 'curl';
  } else if (osInfo.isWindows) {
    // Windows: try winget to install curl
    if (await commandExists('winget')) {
      const ok = await runWithSpinner(
        `  Installing ${chalk.cyan('curl')} via winget...`,
        'winget install --id cURL.cURL --accept-source-agreements --accept-package-agreements -e'
      );
      if (ok) return 'curl';
    }
    // PowerShell fallback is always available on modern Windows
    if (await commandExists('powershell')) return 'powershell';
  }

  throw new Error(
    'Could not provision a download tool (curl/wget). Please install curl manually and retry.'
  );
}

// ─── Download Helpers ────────────────────────────────────────

/**
 * Download a file using whichever tool is available.
 * @param {string} url
 * @param {string} destPath
 * @param {string} downloader  'curl' | 'wget' | 'powershell'
 * @returns {Promise<boolean>}
 */
async function downloadFile(url, destPath, downloader) {
  const cmds = {
    curl:       `curl -fsSL -o "${destPath}" "${url}"`,
    wget:       `wget -q -O "${destPath}" "${url}"`,
    powershell: `powershell -Command "Invoke-WebRequest -Uri '${url}' -OutFile '${destPath}'"`,
  };

  return runWithSpinner(
    `  Downloading ${chalk.cyan(url.split('/').pop())}...`,
    cmds[downloader]
  );
}

// ─── Cloudflared Installer ───────────────────────────────────

/**
 * Build the cloudflared download URL for the current platform.
 * @param {{ isLinux: boolean, isMac: boolean, isWindows: boolean }} osInfo
 * @returns {{ url: string, filename: string }|null}
 */
function cloudflaredDownloadUrl(osInfo) {
  const arch = resolveArch();
  const base = 'https://github.com/cloudflare/cloudflared/releases/latest/download';

  if (osInfo.isLinux) {
    return { url: `${base}/cloudflared-linux-${arch}`, filename: 'cloudflared' };
  }
  if (osInfo.isMac) {
    // Homebrew is preferred on macOS — but provide direct download as fallback
    return { url: `${base}/cloudflared-darwin-${arch}.tgz`, filename: 'cloudflared-darwin.tgz' };
  }
  if (osInfo.isWindows) {
    return { url: `${base}/cloudflared-windows-${arch}.exe`, filename: 'cloudflared.exe' };
  }
  return null;
}

/**
 * Install cloudflared binary from official GitHub releases.
 * @param {{ isLinux: boolean, isMac: boolean, isWindows: boolean }} osInfo
 * @param {string} downloader
 * @returns {Promise<boolean>}
 */
async function installCloudflared(osInfo, downloader) {
  // ── macOS: prefer Homebrew ─────────────────────────────────
  if (osInfo.isMac && await commandExists('brew')) {
    console.log(chalk.yellow('  🍺 Installing cloudflared via Homebrew...'));
    return runWithSpinner(
      `  ${chalk.cyan('brew install cloudflared')}...`,
      'brew install cloudflared'
    );
  }

  // ── Linux: try native package managers first ───────────────
  if (osInfo.isLinux) {
    const distro = await detectLinuxDistro();
    const sudo = (await hasSudo()) ? 'sudo ' : '';

    // Debian/Ubuntu: official Cloudflare apt repo
    if (distro === 'debian') {
      const aptOk = await runWithSpinner(
        `  Adding Cloudflare APT repo & installing ${chalk.cyan('cloudflared')}...`,
        [
          `${sudo}mkdir -p --mode=0755 /usr/share/keyrings`,
          `curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | ${sudo}tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null`,
          `echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | ${sudo}tee /etc/apt/sources.list.d/cloudflared.list`,
          `${sudo}apt-get update -qq`,
          `${sudo}apt-get install -y cloudflared`,
        ].join(' && ')
      );
      if (aptOk) return true;
      // Fall through to binary download if apt method fails
    }
  }

  // ── Windows: try winget first ──────────────────────────────
  if (osInfo.isWindows && await commandExists('winget')) {
    const ok = await runWithSpinner(
      `  Installing ${chalk.cyan('cloudflared')} via winget...`,
      'winget install --id Cloudflare.cloudflared --accept-source-agreements --accept-package-agreements -e'
    );
    if (ok) return true;
  }

  // ── Fallback: direct binary download ───────────────────────
  const dl = cloudflaredDownloadUrl(osInfo);
  if (!dl) {
    console.log(chalk.red('  ✗ Unsupported platform for cloudflared auto-install.'));
    return false;
  }

  const tmpDir = join(os.tmpdir(), 'ipingyou-bootstrap');
  try { await mkdir(tmpDir, { recursive: true }); } catch { /* exists */ }
  const destPath = join(tmpDir, dl.filename);

  const ok = await downloadFile(dl.url, destPath, downloader);
  if (!ok) return false;

  // Handle macOS .tgz extraction
  if (dl.filename.endsWith('.tgz')) {
    const extractOk = await runWithSpinner(
      `  Extracting ${chalk.cyan('cloudflared')} archive...`,
      `tar -xzf "${destPath}" -C "${tmpDir}"`
    );
    if (!extractOk) return false;
  }

  // Move binary to a PATH location
  if (osInfo.isLinux || osInfo.isMac) {
    const binaryPath = dl.filename.endsWith('.tgz')
      ? join(tmpDir, 'cloudflared')
      : destPath;

    try { await chmod(binaryPath, 0o755); } catch { /* ignore */ }

    const sudo = (await hasSudo()) ? 'sudo ' : '';
    const installPath = '/usr/local/bin/cloudflared';

    return runWithSpinner(
      `  Moving ${chalk.cyan('cloudflared')} to ${chalk.dim(installPath)}...`,
      `${sudo}mv "${binaryPath}" "${installPath}"`
    );
  }

  if (osInfo.isWindows) {
    // Place in user's local app data
    const winDir = join(os.homedir(), 'AppData', 'Local', 'cloudflared');
    try { await mkdir(winDir, { recursive: true }); } catch { /* exists */ }
    const finalPath = join(winDir, 'cloudflared.exe');

    try {
      await rename(destPath, finalPath);
      console.log(chalk.green(`  ✓ cloudflared installed at ${chalk.dim(finalPath)}`));
      console.log(chalk.yellow(`  ⚠️  Add ${chalk.dim(winDir)} to your PATH to use cloudflared globally.`));
      return true;
    } catch (err) {
      console.log(chalk.red(`  ✗ Failed to move cloudflared: ${err.message}`));
      return false;
    }
  }

  return false;
}

// ─── OpenSSH Installer ───────────────────────────────────────

/**
 * Install OpenSSH on the current platform.
 * @param {{ isLinux: boolean, isMac: boolean, isWindows: boolean }} osInfo
 * @returns {Promise<boolean>}
 */
async function installOpenSSH(osInfo) {
  if (osInfo.isMac) {
    // macOS ships with ssh; if missing, it means Xcode CLT isn't installed
    console.log(chalk.dim('  ℹ️  macOS ships with SSH by default.'));
    console.log(chalk.dim('     If missing, enable in: System Preferences → Sharing → Remote Login'));
    // Try xcode-select as last resort
    if (!(await commandExists('ssh'))) {
      return runWithSpinner(
        `  Installing ${chalk.cyan('Xcode Command Line Tools')} (includes ssh)...`,
        'xcode-select --install'
      );
    }
    return true;
  }

  if (osInfo.isLinux) {
    const distro = await detectLinuxDistro();
    const sudo = (await hasSudo()) ? 'sudo ' : '';

    const cmds = {
      debian: `${sudo}apt-get update -qq && ${sudo}apt-get install -y openssh-client openssh-server`,
      arch:   `${sudo}pacman -Sy --noconfirm openssh`,
      fedora: `${sudo}dnf install -y openssh-clients openssh-server`,
    };

    const cmd = cmds[distro];
    if (cmd) {
      return runWithSpinner(`  Installing ${chalk.cyan('openssh')} via ${distro} package manager...`, cmd);
    }

    console.log(chalk.red('  ✗ Unknown Linux distro — please install openssh manually.'));
    return false;
  }

  if (osInfo.isWindows) {
    // Try winget first
    if (await commandExists('winget')) {
      const ok = await runWithSpinner(
        `  Installing ${chalk.cyan('OpenSSH')} via winget...`,
        'winget install --id Microsoft.OpenSSH.Client --accept-source-agreements --accept-package-agreements -e'
      );
      if (ok) return true;
    }

    // Fallback: PowerShell Add-WindowsCapability
    if (await commandExists('powershell')) {
      const ok = await runWithSpinner(
        `  Installing ${chalk.cyan('OpenSSH')} via PowerShell...`,
        'powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"'
      );
      if (ok) return true;
    }

    console.log(chalk.yellow('  ⚠️  Could not auto-install OpenSSH on Windows.'));
    console.log(chalk.dim('     Manual: Settings → Apps → Optional Features → OpenSSH Client'));
    return false;
  }

  return false;
}

// ─── Main Dependency Check ───────────────────────────────────

/**
 * Run full dependency check with auto-bootstrap.
 *
 * Pipeline:
 *  1. Detect OS
 *  2. Check ssh + cloudflared
 *  3. If anything is missing → ensure a download tool exists (bootstrap curl if needed)
 *  4. Auto-install missing deps using the best method per platform
 *
 * @returns {Promise<{ ssh: boolean, cloudflared: boolean }>}
 */
export async function checkDependencies() {
  const osInfo = detectOS();
  const results = { ssh: false, cloudflared: false };

  console.log('');
  console.log(chalk.bold('  🔍 Dependency Check'));
  console.log(chalk.dim('  ─────────────────────────────────'));

  // ── Step 1: Probe for existing binaries ─────────────────────
  results.ssh = await commandExists('ssh');
  console.log(`  ${results.ssh ? chalk.green('✓') : chalk.red('✗')} ssh          ${results.ssh ? chalk.dim('found') : chalk.red('missing')}`);

  results.cloudflared = await commandExists('cloudflared');
  console.log(`  ${results.cloudflared ? chalk.green('✓') : chalk.red('✗')} cloudflared  ${results.cloudflared ? chalk.dim('found') : chalk.red('missing')}`);

  console.log('');

  // ── Step 2: Nothing missing? We're done ─────────────────────
  if (results.ssh && results.cloudflared) {
    console.log(chalk.green('  ✅ All dependencies satisfied!\n'));
    return results;
  }

  // ── Step 3: Bootstrap a download tool ───────────────────────
  let downloader;
  try {
    console.log(chalk.bold('  🔧 Bootstrapping download tools...'));

    // Check what download tools exist
    const hasCurl = await commandExists('curl');
    const hasWget = await commandExists('wget');
    const hasWinget = osInfo.isWindows ? await commandExists('winget') : false;

    console.log(`  ${hasCurl ? chalk.green('✓') : chalk.red('✗')} curl         ${hasCurl ? chalk.dim('found') : chalk.red('missing')}`);
    console.log(`  ${hasWget ? chalk.green('✓') : chalk.red('✗')} wget         ${hasWget ? chalk.dim('found') : chalk.red('missing')}`);
    if (osInfo.isWindows) {
      console.log(`  ${hasWinget ? chalk.green('✓') : chalk.red('✗')} winget       ${hasWinget ? chalk.dim('found') : chalk.red('missing')}`);
    }
    console.log('');

    downloader = await ensureDownloader();
    console.log(chalk.green(`  ✓ Using ${chalk.cyan(downloader)} as download tool\n`));
  } catch (err) {
    console.log(chalk.red(`\n  ✗ ${err.message}`));
    console.log(chalk.dim('  Cannot proceed with auto-installation.\n'));
    return results;
  }

  // ── Step 4: Install missing dependencies ────────────────────
  console.log(chalk.bold('  ⚡ Auto-installing missing dependencies...\n'));

  if (!results.ssh) {
    const installed = await installOpenSSH(osInfo);
    results.ssh = installed || (await commandExists('ssh'));
    console.log('');
  }

  if (!results.cloudflared) {
    const installed = await installCloudflared(osInfo, downloader);
    results.cloudflared = installed || (await commandExists('cloudflared'));
    console.log('');
  }

  // ── Final report ────────────────────────────────────────────
  console.log(chalk.dim('  ─────────────────────────────────'));
  console.log(chalk.bold('  📋 Final Status'));
  console.log(`  ${results.ssh ? chalk.green('✓') : chalk.red('✗')} ssh          ${results.ssh ? chalk.green('ready') : chalk.red('unavailable')}`);
  console.log(`  ${results.cloudflared ? chalk.green('✓') : chalk.red('✗')} cloudflared  ${results.cloudflared ? chalk.green('ready') : chalk.red('unavailable')}`);

  if (!results.ssh || !results.cloudflared) {
    console.log('');
    console.log(chalk.yellow('  ⚠️  Some dependencies could not be installed automatically.'));
    console.log(chalk.dim('     Please install them manually and re-run the tool.'));

    if (!results.cloudflared) {
      console.log(chalk.dim('     cloudflared → https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/'));
    }
    if (!results.ssh) {
      console.log(chalk.dim('     openssh    → https://www.openssh.com/portable.html'));
    }
  } else {
    console.log(chalk.green('\n  ✅ All dependencies satisfied!'));
  }

  console.log('');
  return results;
}
