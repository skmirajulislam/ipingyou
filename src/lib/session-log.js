import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redactSensitive } from './ai/safety.js';

const LOG_DIR = path.join(os.homedir(), '.ipingyou', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'session-events.jsonl');
const SESSION_LOG_DIR = path.join(os.tmpdir(), 'ipingyou-session-logs');

let sessionLogPath = null;
let sessionLogDisabled = false;
let cleanupRegistered = false;

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

export function initSessionLog(scope = 'session') {
  if (sessionLogPath || sessionLogDisabled) return sessionLogPath;
  try {
    fs.mkdirSync(SESSION_LOG_DIR, { recursive: true, mode: 0o700 });
    sessionLogPath = path.join(
      SESSION_LOG_DIR,
      `ipingyou-${scope}-${Date.now()}-${process.pid}.log`
    );
    fs.writeFileSync(sessionLogPath, '', { mode: 0o600 });
    if (!cleanupRegistered) {
      process.on('exit', () => cleanupSessionLog());
      cleanupRegistered = true;
    }
    logSessionEvent('session_start', { scope, pid: process.pid, node: process.version });
    return sessionLogPath;
  } catch (err) {
    sessionLogDisabled = true;
    console.error(`Session log setup failed: ${err.message}`);
    return null;
  }
}

export function getSessionLogPath() {
  return sessionLogPath;
}

export function logSessionEvent(type, details = {}, level = 'info') {
  if (!sessionLogPath || sessionLogDisabled) return;
  const entry = {
    time: new Date().toISOString(),
    level,
    type,
    details: sanitize(details),
  };
  try {
    fs.appendFileSync(sessionLogPath, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  } catch (err) {
    sessionLogDisabled = true;
    console.error(`Session log write failed: ${err.message}`);
  }
}

export function cleanupSessionLog() {
  if (!sessionLogPath) return;
  const target = sessionLogPath;
  sessionLogPath = null;
  try {
    if (fs.existsSync(target)) fs.unlinkSync(target);
  } catch (err) {
    console.error(`Session log cleanup failed: ${err.message}`);
  }
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
    logSessionEvent(type, details);
  } catch {
    // Session recording is best-effort.
  }
}
