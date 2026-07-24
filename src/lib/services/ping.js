/**
 * ============================================================
 *  Live Network Latency & RTT Indicator
 * ============================================================
 *  Measures real-time round-trip latency over HTTP/Tunnel.
 * ============================================================
 */

import chalk from 'chalk';

/**
 * Measure round-trip ping time to a target URL in milliseconds.
 * @param {string} targetUrl 
 * @returns {Promise<number>} RTT in ms (-1 if error)
 */
export async function measureLatency(targetUrl) {
  if (!targetUrl) return -1;
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const healthEndpoint = targetUrl.replace(/\/$/, '') + '/health';
    const res = await fetch(healthEndpoint, { method: 'HEAD', signal: controller.signal }).catch(() => null);
    clearTimeout(timeout);

    if (res) return Date.now() - start;
    return -1;
  } catch {
    return -1;
  }
}

/**
 * Format RTT latency into a human-readable chalk string.
 * @param {number} rttMs 
 * @returns {string}
 */
export function formatLatencyBadge(rttMs) {
  if (rttMs < 0) return chalk.dim('⚡ Latency: --ms');
  if (rttMs < 80) return chalk.green(`⚡ Latency: ${rttMs}ms (Excellent)`);
  if (rttMs < 200) return chalk.yellow(`⚡ Latency: ${rttMs}ms (Good)`);
  return chalk.red(`⚡ Latency: ${rttMs}ms (High)`);
}
