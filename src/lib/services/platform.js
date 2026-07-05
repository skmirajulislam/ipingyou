import { execa } from 'execa';
import chalk from 'chalk';
import os from 'node:os';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';

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

/**
 * Downloads a file from a URL to a destination path, handling redirects.
 */
function downloadUrlToPath(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const request = https.get(url, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        file.close(() => {
          downloadUrlToPath(response.headers.location, dest).then(resolve).catch(reject);
        });
        return;
      }
      if (response.statusCode !== 200) {
        file.close();
        fs.unlink(dest, () => reject(new Error(`Failed to download: Status Code ${response.statusCode}`)));
        return;
      }
      response.pipe(file);
      file.on('finish', () => {
        file.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    });
    request.on('error', (err) => {
      file.close();
      fs.unlink(dest, () => reject(err));
    });
    file.on('error', (err) => {
      file.close();
      fs.unlink(dest, () => reject(err));
    });
  });
}

/**
 * Executes a command with standard IO inheritance and retries exactly once on failure.
 */
async function executeWithRetry(command, args, options = {}) {
  const fullCommand = `${command} ${args.join(' ')}`;
  try {
    await execa(command, args, { stdio: 'inherit', ...options });
  } catch (err) {
    console.log(chalk.yellow(`  ⚠️  Command failed: "${fullCommand}". Retrying once...`));
    try {
      await execa(command, args, { stdio: 'inherit', ...options });
    } catch (retryErr) {
      throw new Error(`Command failed after retry: "${fullCommand}". Error: ${retryErr.message}`);
    }
  }
}

/**
 * Robust Linux SSH service status check.
 */
export async function isLinuxSSHActive() {
  // 1. Try systemctl first if systemd is available
  try {
    const { stdout } = await execa('systemctl', ['is-active', 'ssh'], { reject: false, timeout: 3000 });
    if (stdout.trim() === 'active') return true;
  } catch {}
  try {
    const { stdout } = await execa('systemctl', ['is-active', 'sshd'], { reject: false, timeout: 3000 });
    if (stdout.trim() === 'active') return true;
  } catch {}

  // 2. Try service command status
  try {
    const { stdout } = await execa('service', ['ssh', 'status'], { reject: false, timeout: 3000 });
    if (stdout.toLowerCase().includes('running') || stdout.toLowerCase().includes('active')) return true;
  } catch {}
  try {
    const { stdout } = await execa('service', ['sshd', 'status'], { reject: false, timeout: 3000 });
    if (stdout.toLowerCase().includes('running') || stdout.toLowerCase().includes('active')) return true;
  } catch {}

  // 3. Try pgrep as a fallback to see if sshd process exists
  try {
    const { stdout } = await execa('pgrep', ['sshd'], { reject: false, timeout: 3000 });
    if (stdout.trim()) return true;
  } catch {}

  return false;
}

/**
 * Robust Linux SSH service start.
 */
export async function startLinuxSSH() {
  // Try systemctl first if systemd is available
  try {
    const isSystemd = await execa('systemctl', ['--version'], { reject: false, timeout: 3000 }).then(r => r.exitCode === 0);
    if (isSystemd) {
      try {
        await executeWithRetry('sudo', ['systemctl', 'start', 'ssh']);
        return;
      } catch {
        await executeWithRetry('sudo', ['systemctl', 'start', 'sshd']);
        return;
      }
    }
  } catch {}

  // Try service command
  try {
    await executeWithRetry('sudo', ['service', 'ssh', 'start']);
    return;
  } catch {}
  try {
    await executeWithRetry('sudo', ['service', 'sshd', 'start']);
    return;
  } catch {}

  // Try /etc/init.d
  try {
    await executeWithRetry('sudo', ['/etc/init.d/ssh', 'start']);
    return;
  } catch {}
  try {
    await executeWithRetry('sudo', ['/etc/init.d/sshd', 'start']);
    return;
  } catch {}

  // Try direct execution
  try {
    await executeWithRetry('sudo', ['/usr/sbin/sshd']);
    return;
  } catch {}
  try {
    await executeWithRetry('sudo', ['sshd']);
    return;
  } catch {}

  throw new Error('All attempts to start SSH service failed');
}

/**
 * Installs a missing dependency based on the operating system.
 */
async function autoInstallDependency(dep, osInfo) {
  const relLatest = 'releases/' + 'latest';
  if (dep === 'ssh') {
    if (osInfo.isMac) {
      const hasSsh = await commandExists('ssh');
      if (!hasSsh) {
        await executeWithRetry('brew', ['install', 'openssh']);
      }
      await executeWithRetry('sudo', ['systemsetup', '-setremotelogin', 'on']);
    } else if (osInfo.isWindows) {
      await executeWithRetry('powershell.exe', [
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        'Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'
      ]);
      await executeWithRetry('powershell.exe', [
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        'Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0'
      ]);
      await executeWithRetry('powershell.exe', [
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        'Set-Service -Name sshd -StartupType Automatic; Start-Service sshd'
      ]);
    } else if (osInfo.isLinux) {
      const distro = await detectLinuxDistro();
      if (distro === 'debian' || (await commandExists('apt-get'))) {
        await executeWithRetry('sudo', ['apt-get', 'update']);
        await executeWithRetry('sudo', ['apt-get', 'install', '-y', 'openssh-server', 'openssh-client']);
      } else if (distro === 'fedora' || (await commandExists('dnf'))) {
        await executeWithRetry('sudo', ['dnf', 'install', '-y', 'openssh-server', 'openssh-clients']);
      } else if (await commandExists('yum')) {
        await executeWithRetry('sudo', ['yum', 'install', '-y', 'openssh-server', 'openssh-clients']);
      } else if (distro === 'arch' || (await commandExists('pacman'))) {
        await executeWithRetry('sudo', ['pacman', '-S', '--noconfirm', 'openssh']);
      } else {
        throw new Error('Unsupported Linux distribution for automatic SSH installation. Please install openssh-server manually.');
      }
    }
  } else if (dep === 'cloudflared') {
    const localBinDir = path.join(os.homedir(), '.ipingyou', 'bin');
    await fs.promises.mkdir(localBinDir, { recursive: true, mode: 0o700 });
    const localPath = path.join(localBinDir, osInfo.isWindows ? 'cloudflared.exe' : 'cloudflared');

    if (osInfo.isMac) {
      const arch = osInfo.arch === 'arm64' ? 'arm64' : 'amd64';
      const url = `https://github.com/cloudflare/cloudflared/${relLatest}/download/cloudflared-darwin-${arch}.tgz`;
      const tgzPath = path.join(os.tmpdir(), 'cloudflared.tgz');
      await downloadUrlToPath(url, tgzPath);
      await execa('tar', ['-xzf', tgzPath, '-C', localBinDir]);
    } else if (osInfo.isWindows) {
      const arch = osInfo.arch === 'x64' ? 'amd64' : '386';
      const url = `https://github.com/cloudflare/cloudflared/${relLatest}/download/cloudflared-windows-${arch}.exe`;
      await downloadUrlToPath(url, localPath);
    } else if (osInfo.isLinux) {
      const arch = osInfo.arch === 'x64' ? 'amd64' : (osInfo.arch === 'arm64' ? 'arm64' : '386');
      const url = `https://github.com/cloudflare/cloudflared/${relLatest}/download/cloudflared-linux-${arch}`;
      await downloadUrlToPath(url, localPath);
      await fs.promises.chmod(localPath, 0o755);
    }
  }
}

export async function getCloudflaredPath() {
  if (await commandExists('cloudflared')) {
    return 'cloudflared';
  }
  const localBinDir = path.join(os.homedir(), '.ipingyou', 'bin');
  const localPath = path.join(localBinDir, process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared');
  if (fs.existsSync(localPath)) {
    return localPath;
  }
  return null;
}

export async function checkDependencies() {
  const osInfo = detectOS();
  const cfPath = await getCloudflaredPath();
  let results = {
    ssh: await commandExists('ssh'),
    cloudflared: cfPath !== null,
  };

  const missing = Object.entries(results)
    .filter(([, available]) => !available)
    .map(([name]) => name);

  if (missing.length > 0) {
    console.log('');
    console.log(chalk.bold('  🔍 Dependency Check'));
    console.log(chalk.dim('  ─────────────────────────────────'));
    console.log(`  ${results.ssh ? chalk.green('✓') : chalk.red('✗')} ssh          ${results.ssh ? chalk.dim('found') : chalk.red('missing')}`);
    console.log(`  ${results.cloudflared ? chalk.green('✓') : chalk.red('✗')} cloudflared  ${results.cloudflared ? chalk.dim('found') : chalk.red('missing')}`);
    console.log('');
    console.log(chalk.yellow(`  ⚠️  Missing dependencies found: ${missing.join(', ')}`));
    console.log(chalk.cyan(`  Attempting auto-installation...`));

    for (const dep of missing) {
      console.log(chalk.blue(`\n  📦 Installing ${dep}...`));
      try {
        await autoInstallDependency(dep, osInfo);
        console.log(chalk.green(`  ✓ Successfully installed ${dep}`));
      } catch (err) {
        throw new Error(`Auto-installation of ${dep} failed: ${err.message}`);
      }
    }

    // Re-verify after installation
    const finalCfPath = await getCloudflaredPath();
    results = {
      ssh: await commandExists('ssh'),
      cloudflared: finalCfPath !== null,
    };

    const stillMissing = Object.entries(results)
      .filter(([, available]) => !available)
      .map(([name]) => name);

    if (stillMissing.length > 0) {
      throw new Error(`Auto-installation succeeded but dependencies are still missing: ${stillMissing.join(', ')}`);
    }
  }

  console.log('');
  console.log(chalk.bold('  🔍 Dependency Check'));
  console.log(chalk.dim('  ─────────────────────────────────'));
  console.log(`  ✓ ssh          ${chalk.dim('found')}`);
  console.log(`  ✓ cloudflared  ${chalk.dim('found')}`);
  console.log(chalk.green('\n  ✅ All dependencies satisfied!\n'));

  return results;
}

