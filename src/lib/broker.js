import chalk from 'chalk';
import os from 'node:os';
import { decrypt, encrypt } from './crypto.js';
import { createSpinner, cryptoSpinner, networkSpinner } from './animations.js';
import { logSessionEvent } from './session-log.js';

async function fetchWithLog(action, endpoint, options = {}) {
  const method = options.method || 'GET';
  const startedAt = Date.now();
  logSessionEvent('broker_request', { action, method, endpoint });
  try {
    const res = await fetch(endpoint, options);
    logSessionEvent('broker_response', {
      action,
      method,
      endpoint,
      status: res.status,
      ok: res.ok,
      durationMs: Date.now() - startedAt,
    });
    return res;
  } catch (err) {
    logSessionEvent('broker_error', {
      action,
      method,
      endpoint,
      error: err.message,
      durationMs: Date.now() - startedAt,
    }, 'error');
    throw err;
  }
}

export async function pingBroker(url) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 3000);
  try {
    const res = await fetchWithLog('health', `${url}/health`, { signal: controller.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(id);
  }
}

export async function registerWithBroker(brokerUrl, uid, tunnelUrl, password, serviceConfig) {
  const spinner = createSpinner('Encrypting session data...', cryptoSpinner).start();

  try {
    await new Promise(r => setTimeout(r, 600));
    const payload = JSON.stringify({ url: tunnelUrl, ...serviceConfig });
    const encrypted = encrypt(payload, password);

    spinner.text = 'Registering with broker...';

    const res = await fetchWithLog('register', `${brokerUrl}/register`, {
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
      logSessionEvent('broker_register_failed', { uid, status: res.status, error: data.error || 'unknown' }, 'error');
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    const result = await res.json();
    spinner.succeed(`Registered with broker ${chalk.dim(`(${brokerUrl})`)} ${chalk.green('[E2E encrypted]')}`);
    logSessionEvent('broker_registered', { uid, broker: brokerUrl });
    // Return the host authentication token — needed for all host-only broker operations
    return { success: true, hostToken: result.hostToken || null };
  } catch (err) {
    spinner.fail(`Broker registration failed: ${err.message}`);
    console.error(chalk.red(`  ❌ Error: ${err.message}`));
    logSessionEvent('broker_register_error', { uid, broker: brokerUrl, error: err.message }, 'error');
    console.log(chalk.yellow('  ⚠️  Remote clients won\'t be able to find you without the broker.'));
    console.log(chalk.dim('     Share the tunnel URL directly if needed.'));
    return { success: false, hostToken: null };
  }
}

export async function requestHostApproval(brokerUrl, uid, password, details) {
  const encrypted = encrypt(JSON.stringify(details), password);
  const res = await fetchWithLog('approval_request', `${brokerUrl}/approval-request/${uid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(encrypted),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    logSessionEvent('broker_approval_request_failed', { uid, status: res.status, error: data.error || 'unknown' }, 'error');
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function waitForApproval(brokerUrl, uid, requestId, timeoutMs = 300000) {
  const startedAt = Date.now();
  logSessionEvent('approval_wait_started', { uid, requestId, timeoutMs });
  while (Date.now() - startedAt < timeoutMs) {
    const res = await fetchWithLog('approval_status', `${brokerUrl}/approval-status/${uid}/${requestId}`);
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'approved') {
        logSessionEvent('approval_granted', { uid, requestId });
        return true;
      }
      if (data.status === 'denied') {
        logSessionEvent('approval_denied', { uid, requestId });
        return false;
      }
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  logSessionEvent('approval_timeout', { uid, requestId, timeoutMs }, 'warn');
  throw new Error('Timed out waiting for host approval');
}

export async function fetchApprovalRequests(brokerUrl, uid, hostToken) {
  const res = await fetchWithLog('approval_requests', `${brokerUrl}/approval-requests/${uid}`, {
    headers: hostToken ? { 'x-host-token': hostToken } : {},
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    logSessionEvent('broker_approval_fetch_failed', { uid, status: res.status, error: data.error || 'unknown' }, 'error');
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function decideApprovalRequest(brokerUrl, uid, requestId, decision, hostToken) {
  const res = await fetchWithLog('approval_decision', `${brokerUrl}/approval-requests/${uid}/${requestId}/${decision}`, {
    method: 'POST',
    headers: hostToken ? { 'x-host-token': hostToken } : {},
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    logSessionEvent('broker_approval_decision_failed', { uid, requestId, decision, status: res.status, error: data.error || 'unknown' }, 'error');
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  logSessionEvent('approval_decision_sent', { uid, requestId, decision });
  return res.json();
}

export async function revokeUID(brokerUrl, uid, hostToken) {
  try {
    await fetchWithLog('revoke', `${brokerUrl}/revoke/${uid}`, {
      method: 'DELETE',
      headers: hostToken ? { 'x-host-token': hostToken } : {},
    });
  } catch (err) {
    logSessionEvent('broker_revoke_failed', { uid, broker: brokerUrl, error: err.message }, 'warn');
  }
}

export async function resolveUID(brokerUrl, uid, password, silent = false, requestId = null) {
  const spinner = !silent ? createSpinner(`Resolving UID ${chalk.cyan(uid)}...`, networkSpinner).start() : null;

  try {
    const suffix = requestId ? `?requestId=${encodeURIComponent(requestId)}` : '';
    const res = await fetchWithLog('resolve', `${brokerUrl}/resolve/${uid}${suffix}`);

    if (res.status === 404) {
      if (spinner) spinner.fail('UID not found — the host may not be online or the session expired');
      else console.error(chalk.red('  ❌ UID not found or expired.'));
      logSessionEvent('broker_resolve_missing', { uid, status: 404 }, 'warn');
      return null;
    }
    if (res.status === 410) {
      if (spinner) spinner.fail('UID has expired — ask the host for a new session');
      else console.error(chalk.red('  ❌ UID expired.'));
      logSessionEvent('broker_resolve_expired', { uid, status: 410 }, 'warn');
      return null;
    }
    if (res.status === 423) {
      if (spinner) spinner.info('Host approval is required — submitting access request...');
      else console.log(chalk.yellow('  ⏳ Host approval required.'));
      logSessionEvent('broker_resolve_needs_approval', { uid, status: 423 }, 'warn');
      return { needsApproval: true };
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      logSessionEvent('broker_resolve_failed', { uid, status: res.status, error: data.error || 'unknown' }, 'error');
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!data.iv || !data.ciphertext || !data.salt) {
      if (spinner) spinner.fail('Broker returned invalid response — missing encrypted data or salt');
      logSessionEvent('broker_resolve_invalid', { uid }, 'error');
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
      logSessionEvent('broker_decrypt_failed', { uid }, 'warn');
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
      logSessionEvent('broker_decrypt_invalid_url', { uid }, 'warn');
      return null;
    }

    if (spinner) spinner.succeed(`Resolved: ${chalk.dim(payloadConfig.url)} ${chalk.green('[decrypted locally]')}`);
    logSessionEvent('broker_resolve_success', { uid, type: payloadConfig.type || 'ssh' });
    return payloadConfig;
  } catch (err) {
    if (spinner) spinner.fail(`Broker lookup failed: ${err.message}`);
    logSessionEvent('broker_resolve_error', { uid, error: err.message }, 'error');
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

    await fetchWithLog('telemetry', `${brokerUrl}/client-info/${uid}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iv, ciphertext, salt }),
    });
  } catch (err) {
    logSessionEvent('telemetry_failed', { uid, error: err.message }, 'warn');
  }
}
