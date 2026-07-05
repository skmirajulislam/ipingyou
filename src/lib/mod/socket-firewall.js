import { execa } from 'execa';

export async function getSocketFirewallStatus() {
  try {
    const result = await execa('sfw', ['--version'], {
      reject: false,
      timeout: 15000,
      maxBuffer: 64 * 1024,
      env: { ...process.env, SFW_SKIP_UPDATE_CHECK: '1' },
    });
    return {
      available: result.exitCode === 0,
      version: String(result.stdout || result.stderr || '').trim() || null,
    };
  } catch {
    return { available: false, version: null };
  }
}

export async function runProtectedNpmInstall(args, options = {}) {
  const status = await getSocketFirewallStatus();
  if (!status.available) {
    throw new Error(
      'Socket Firewall is required for package installation. '
      + 'Install it first with: npm install -g sfw'
    );
  }

  return execa('sfw', ['npm', 'install', ...args], {
    ...options,
    reject: true,
    env: { ...process.env, ...options.env },
  });
}
