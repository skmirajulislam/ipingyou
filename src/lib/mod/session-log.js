import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redactSensitive } from '../ai/safety.js';

const LOG_DIR = path.join(os.homedir(), '.ipingyou', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'session-events.jsonl');
const SESSION_LOG_DIR = path.join(os.tmpdir(), 'ipingyou-session-logs');
const MAX_HISTORY_LOG_BYTES = 5 * 1024 * 1024;
const MAX_SESSION_LOG_BYTES = 2 * 1024 * 1024;
const MAX_LOG_STRING_LENGTH = 16 * 1024;
const SESSION_LOG_FLUSH_BYTES = 64 * 1024;
const SESSION_LOG_FLUSH_MS = 250;

let sessionLogPath = null;
let sessionLogDisabled = false;
let cleanupRegistered = false;
let sessionLogBytes = 0;
let historyLogBytes = null;
let sessionLogBuffer = '';
let sessionLogFlushTimer = null;

function flushSessionLog() {
  if (sessionLogFlushTimer) clearTimeout(sessionLogFlushTimer);
  sessionLogFlushTimer = null;
  if (!sessionLogPath || !sessionLogBuffer) return;
  const buffered = sessionLogBuffer;
  sessionLogBuffer = '';
  try {
    fs.appendFileSync(sessionLogPath, buffered, { mode: 0o600 });
  } catch (err) {
    sessionLogDisabled = true;
    console.error(`Session log write failed: ${err.message}`);
  }
}

function scheduleSessionLogFlush() {
  if (sessionLogFlushTimer) return;
  sessionLogFlushTimer = setTimeout(flushSessionLog, SESSION_LOG_FLUSH_MS);
  sessionLogFlushTimer.unref?.();
}

function sanitize(value) {
  if (typeof value === 'string') {
    const redacted = redactSensitive(value);
    return redacted.length > MAX_LOG_STRING_LENGTH
      ? `${redacted.slice(0, MAX_LOG_STRING_LENGTH)}…[truncated]`
      : redacted;
  }
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
    const staleBefore = Date.now() - (24 * 60 * 60 * 1000);
    for (const name of fs.readdirSync(SESSION_LOG_DIR)) {
      if (!name.startsWith('ipingyou-')) continue;
      const candidate = path.join(SESSION_LOG_DIR, name);
      try {
        if (fs.statSync(candidate).mtimeMs < staleBefore) fs.unlinkSync(candidate);
      } catch {
        // Best-effort cleanup; another process may own or remove the file.
      }
    }
    sessionLogPath = path.join(
      SESSION_LOG_DIR,
      `ipingyou-${scope}-${Date.now()}-${process.pid}.log`
    );
    fs.writeFileSync(sessionLogPath, '', { mode: 0o600 });
    sessionLogBytes = 0;
    sessionLogBuffer = '';
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
    const line = `${JSON.stringify(entry)}\n`;
    const lineBytes = Buffer.byteLength(line);
    if (sessionLogBytes + lineBytes > MAX_SESSION_LOG_BYTES) {
      sessionLogDisabled = true;
      return;
    }
    sessionLogBuffer += line;
    sessionLogBytes += lineBytes;
    if (Buffer.byteLength(sessionLogBuffer) >= SESSION_LOG_FLUSH_BYTES) {
      flushSessionLog();
    } else {
      scheduleSessionLogFlush();
    }
  } catch (err) {
    sessionLogDisabled = true;
    console.error(`Session log write failed: ${err.message}`);
  }
}

export function cleanupSessionLog() {
  if (sessionLogPath) {
    flushSessionLog();
    const target = sessionLogPath;
    sessionLogPath = null;
    try {
      if (fs.existsSync(target)) fs.unlinkSync(target);
    } catch (err) {
      console.error(`Session log cleanup failed: ${err.message}`);
    }
  }

  try {
    if (fs.existsSync(LOG_DIR)) {
      fs.rmSync(LOG_DIR, { recursive: true, force: true });
    }
  } catch {
    // Best-effort directory removal
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
    const line = `${JSON.stringify(event)}\n`;
    const lineBytes = Buffer.byteLength(line);
    if (historyLogBytes === null) {
      historyLogBytes = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE).size : 0;
    }
    if (historyLogBytes + lineBytes > MAX_HISTORY_LOG_BYTES) {
      const previousLog = `${LOG_FILE}.1`;
      try {
        if (fs.existsSync(previousLog)) fs.unlinkSync(previousLog);
        if (fs.existsSync(LOG_FILE)) fs.renameSync(LOG_FILE, previousLog);
      } catch {
        fs.writeFileSync(LOG_FILE, '', { mode: 0o600 });
      }
      historyLogBytes = 0;
    }
    fs.appendFileSync(LOG_FILE, line, { mode: 0o600 });
    historyLogBytes += lineBytes;
    logSessionEvent(type, details);
  } catch {
    // Session recording is best-effort.
  }
}
