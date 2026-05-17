import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redactSensitive } from './ai/safety.js';

const LOG_DIR = path.join(os.homedir(), '.ipingyou', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'session-events.jsonl');

function sanitize(value) {
  if (typeof value === 'string') return redactSensitive(value);
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !/(password|privateKey|tunnelUrl|url|secret|token|apiKey)/i.test(key))
        .map(([key, item]) => [key, sanitize(item)])
    );
  }
  return value;
}

export function recordEvent(type, details = {}) {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
    const event = {
      time: new Date().toISOString(),
      type,
      details: sanitize(details),
    };
    fs.appendFileSync(LOG_FILE, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  } catch {
    // Session recording is best-effort.
  }
}

export function getSessionLogPath() {
  return LOG_FILE;
}
