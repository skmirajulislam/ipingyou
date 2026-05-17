import chalk from 'chalk';
import os from 'node:os';
import { decrypt, encrypt } from './crypto.js';
import { createSpinner, cryptoSpinner, networkSpinner } from './animations.js';

export async function pingBroker(url) {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${url}/health`, { signal: controller.signal });
    clearTimeout(id);
    return res.ok;
  } catch {
    return false;
  }
}

export async function registerWithBroker(brokerUrl, uid, tunnelUrl, password, serviceConfig) {
  const spinner = createSpinner('Encrypting session data...', cryptoSpinner).start();

  try {
    await new Promise(r => setTimeout(r, 600));
    const payload = JSON.stringify({ url: tunnelUrl, ...serviceConfig });
    const encrypted = encrypt(payload, password);

    spinner.text = 'Registering with broker...';

    const res = await fetch(`${brokerUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        uid,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        salt: encrypted.salt,
        approvalRequired: Boolean(serviceConfig.approvalRequired),
        oneTime: Boolean(serviceConfig.oneTimeSharePath),
      }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    spinner.succeed(`Registered with broker ${chalk.dim(`(${brokerUrl})`)} ${chalk.green('[E2E encrypted]')}`);
    return true;
  } catch (err) {
    spinner.fail(`Broker registration failed: ${err.message}`);
    console.error(chalk.red(`  ❌ Error: ${err.message}`));
    console.log(chalk.yellow('  ⚠️  Remote clients won\'t be able to find you without the broker.'));
    console.log(chalk.dim('     Share the tunnel URL directly if needed.'));
    return false;
  }
}

export async function requestHostApproval(brokerUrl, uid, password, details) {
  const encrypted = encrypt(JSON.stringify(details), password);
  const res = await fetch(`${brokerUrl}/approval-request/${uid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(encrypted),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function waitForApproval(brokerUrl, uid, requestId, timeoutMs = 300000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const res = await fetch(`${brokerUrl}/approval-status/${uid}/${requestId}`);
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'approved') return true;
      if (data.status === 'denied') return false;
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error('Timed out waiting for host approval');
}

export async function fetchApprovalRequests(brokerUrl, uid) {
  const res = await fetch(`${brokerUrl}/approval-requests/${uid}`);
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function decideApprovalRequest(brokerUrl, uid, requestId, decision) {
  const res = await fetch(`${brokerUrl}/approval-requests/${uid}/${requestId}/${decision}`, { method: 'POST' });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function revokeUID(brokerUrl, uid) {
  await fetch(`${brokerUrl}/revoke/${uid}`, { method: 'DELETE' }).catch(() => {});
}

export async function resolveUID(brokerUrl, uid, password, silent = false, requestId = null) {
  const spinner = !silent ? createSpinner(`Resolving UID ${chalk.cyan(uid)}...`, networkSpinner).start() : null;

  try {
    const suffix = requestId ? `?requestId=${encodeURIComponent(requestId)}` : '';
    const res = await fetch(`${brokerUrl}/resolve/${uid}${suffix}`);

    if (res.status === 404) {
      if (spinner) spinner.fail('UID not found — the host may not be online or the session expired');
      else console.error(chalk.red('  ❌ UID not found or expired.'));
      return null;
    }
    if (res.status === 410) {
      if (spinner) spinner.fail('UID has expired — ask the host for a new session');
      else console.error(chalk.red('  ❌ UID expired.'));
      return null;
    }
    if (res.status === 423) {
      if (spinner) spinner.fail('Host approval is required before this session can be resolved');
      else console.error(chalk.red('  ❌ Host approval required.'));
      return null;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!data.iv || !data.ciphertext || !data.salt) {
      if (spinner) spinner.fail('Broker returned invalid response — missing encrypted data or salt');
      return null;
    }

    if (spinner) spinner.text = 'Decrypting tunnel URL locally...';
    if (!silent) await new Promise(r => setTimeout(r, 600));

    let decryptedPayload;
    try {
      decryptedPayload = decrypt(data.iv, data.ciphertext, password, data.salt);
    } catch {
      if (spinner) spinner.fail('Decryption failed — incorrect password or corrupted data');
      if (!spinner) console.error(chalk.red('  ❌ Error: Could not decrypt tunnel data. Incorrect password.'));
      return null;
    }

    let payloadConfig;
    try {
      payloadConfig = JSON.parse(decryptedPayload);
      if (typeof payloadConfig !== 'object' || !payloadConfig.url) {
        payloadConfig = { url: decryptedPayload, type: 'ssh' };
      }
    } catch {
      payloadConfig = { url: decryptedPayload, type: 'ssh' };
    }

    if (!payloadConfig.url.startsWith('https://')) {
      if (spinner) spinner.fail('Decrypted data is not a valid tunnel URL (incorrect password)');
      return null;
    }

    if (spinner) spinner.succeed(`Resolved: ${chalk.dim(payloadConfig.url)} ${chalk.green('[decrypted locally]')}`);
    return payloadConfig;
  } catch (err) {
    if (spinner) spinner.fail(`Broker lookup failed: ${err.message}`);
    return null;
  }
}

export async function pushTelemetry(brokerUrl, uid, password, username, action = 'connected') {
  try {
    let publicIp = 'Unknown';
    try {
      publicIp = await fetch('https://api.ipify.org').then(r => r.text());
    } catch {}

    const telemetry = {
      username,
      ip: publicIp,
      os: `${os.type()} ${os.release()} (${os.arch()})`,
      cpu: os.cpus()[0]?.model || 'Unknown CPU',
      ram: `${Math.round(os.totalmem() / 1024 / 1024 / 1024)} GB`,
      action,
      time: new Date().toLocaleTimeString()
    };

    const { iv, ciphertext, salt } = encrypt(JSON.stringify(telemetry), password);

    await fetch(`${brokerUrl}/client-info/${uid}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iv, ciphertext, salt }),
    });
  } catch {
    // Telemetry is optional.
  }
}
