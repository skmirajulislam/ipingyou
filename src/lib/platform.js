import { execa } from 'execa';
import chalk from 'chalk';
import os from 'node:os';
import fs from 'node:fs';

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

export async function detectLinuxDistro() {
  try {
    const data = await fs.promises.readFile('/etc/os-release', 'utf8');
    const lower = data.toLowerCase();
    if (/(ubuntu|debian|kali|mint)/.test(lower)) return 'debian';
    if (/(arch|manjaro)/.test(lower)) return 'arch';
    if (/(fedora|centos|rhel)/.test(lower)) return 'fedora';
  } catch {
    // Manual instructions fall back to the generic Linux guidance.
  }
  return 'unknown';
}

export async function commandExists(command) {
  if (!/^[a-zA-Z0-9._+-]{1,64}$/.test(String(command || ''))) return false;
  try {
    const probe = process.platform === 'win32' ? ['where', command] : ['which', command];
    await execa(probe[0], [probe[1]], {
      reject: true,
      timeout: 5000,
      maxBuffer: 64 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

function printInstallGuidance(osInfo, missing) {
  console.log(chalk.yellow('  ⚠️  Required system tools are missing.'));
  console.log(chalk.dim('     iPingYou does not download or execute native installers automatically.'));
  console.log(chalk.dim('     Install the tools through your trusted OS package manager, then rerun iPingYou.'));
  console.log('');

  if (missing.includes('cloudflared')) {
    if (osInfo.isMac) console.log(chalk.cyan('     brew install cloudflared'));
    else if (osInfo.isWindows) console.log(chalk.cyan('     winget install --id Cloudflare.cloudflared -e'));
    else console.log(chalk.cyan('     Follow: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/'));
  }

  if (missing.includes('ssh')) {
    if (osInfo.isMac) console.log(chalk.cyan('     Enable Remote Login in System Settings → General → Sharing'));
    else if (osInfo.isWindows) console.log(chalk.cyan('     Add OpenSSH Client/Server from Windows Optional Features'));
    else console.log(chalk.cyan('     Debian/Ubuntu: sudo apt-get install openssh-client openssh-server'));
  }
  console.log('');
}

export async function checkDependencies() {
  const osInfo = detectOS();
  const results = {
    ssh: await commandExists('ssh'),
    cloudflared: await commandExists('cloudflared'),
  };

  console.log('');
  console.log(chalk.bold('  🔍 Dependency Check'));
  console.log(chalk.dim('  ─────────────────────────────────'));
  console.log(`  ${results.ssh ? chalk.green('✓') : chalk.red('✗')} ssh          ${results.ssh ? chalk.dim('found') : chalk.red('missing')}`);
  console.log(`  ${results.cloudflared ? chalk.green('✓') : chalk.red('✗')} cloudflared  ${results.cloudflared ? chalk.dim('found') : chalk.red('missing')}`);
  console.log('');

  const missing = Object.entries(results)
    .filter(([, available]) => !available)
    .map(([name]) => name);
  if (missing.length > 0) {
    printInstallGuidance(osInfo, missing);
  } else {
    console.log(chalk.green('  ✅ All dependencies satisfied!\n'));
  }
  return results;
}
