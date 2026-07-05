import { getAllowlistRegexes } from '../mod/allowlist.js';

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(gsk_[A-Za-z0-9_-]{20,})\b/g,
  /\b(sk-[A-Za-z0-9_-]{20,})\b/g,
  /\b(ghp_[A-Za-z0-9_]{20,})\b/g,
  /\b(xox[baprs]-[A-Za-z0-9-]{20,})\b/g,
  /(["']?(?:api[_-]?key|token|password|secret|private[_-]?key)["']?\s*[:=]\s*["']?)[^\s"',}]+/gi,
];

const BLOCKED_PATH_PATTERNS = [
  /(^|[\s~/])\.ssh(\/|$)/,
  /(^|[\s~/])\.gnupg(\/|$)/,
  /(^|[\s~/])\.aws(\/|$)/,
  /(^|[\s~/])\.config\/gh(\/|$)/,
  /(^|[\s~/])\.ipingyou(\/|$)/,
  /(^|[\s~/])\.npmrc($|\s)/,
  /(^|[\s~/])\.netrc($|\s)/,
  /(^|[\s~/])\.pypirc($|\s)/,
  /(^|[\s~/])\.env($|[\s.]|\/)/,
  /id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/,
];

const BLOCKED_PATH_SEGMENTS = new Set([
  '.ssh',
  '.gnupg',
  '.aws',
  '.ipingyou',
  '.kube',
  '.docker',
]);

const BLOCKED_PATH_BASENAMES = new Set([
  '.npmrc',
  '.netrc',
  '.pypirc',
  'credentials',
  'credentials.json',
  'known_hosts',
  'authorized_keys',
  'shadow',
  'sudoers',
]);

const PRIVATE_KEY_BASENAME = /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i;
const ENV_BASENAME = /^\.env(?:\.|$)/i;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

const BLOCKED_COMMAND_PATTERNS = [
  /^\s*(env|printenv|set)\b/,
  /\b(export|declare)\s+-p\b/,
  /\bsecurity\s+find-generic-password\b/,
  /\bpass\s+show\b/,
];

const DANGEROUS_COMMAND_PATTERNS = [
  /\brm\s+(-[^\s]*[rf][^\s]*|--recursive|--force)/,
  /\bsudo\b/,
  /\bchmod\b/,
  /\bchown\b/,
  /\bmv\b/,
  /\bcp\b/,
  /\binstall\b/,
  /\bnpm\s+(i|install|uninstall|remove|rm)\b/,
  /\b(pnpm|yarn)\s+(add|remove|install)\b/,
  /\b(git\s+(reset|clean|checkout|switch|merge|rebase|push|commit))\b/,
  /\b(curl|wget)\b/,
  />|>>|\btee\b/,
];
const SHELL_SYNTAX_PATTERN = /(?:[;&|`$()]|\\\r?\n)/;

const READ_ONLY_COMMAND_PATTERNS = [
  /^\s*(pwd|ls|find|rg|grep|sed|cat|head|tail|wc|git status|git diff|git log|git show|node --version|npm --version|which|date|uname)\b/,
];

export function redactSensitive(value) {
  let output = String(value ?? '');
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, (match, prefix) => prefix ? `${prefix}[REDACTED]` : '[REDACTED]');
  }
  return output;
}

export function truncateForModel(value, maxChars = 12000) {
  const text = redactSensitive(value);
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n[TRUNCATED ${text.length - maxChars} chars]`;
}

export function commandTouchesBlockedPath(command) {
  return BLOCKED_PATH_PATTERNS.some(pattern => pattern.test(command));
}

export function assertSafeReadablePath(filePath) {
  const value = String(filePath ?? '');
  if (!value || value.length > 4096) {
    throw new Error('Invalid file path');
  }
  if (CONTROL_CHARACTERS.test(value)) {
    throw new Error('File path contains control characters');
  }

  const normalized = value.replace(/\\/g, '/').replace(/\/+/g, '/');
  const segments = normalized.toLowerCase().split('/').filter(Boolean);
  const basename = segments.at(-1) || '';

  if (
    segments.some(segment => BLOCKED_PATH_SEGMENTS.has(segment))
    || BLOCKED_PATH_BASENAMES.has(basename)
    || PRIVATE_KEY_BASENAME.test(basename)
    || ENV_BASENAME.test(basename)
    || normalized.toLowerCase().includes('/.config/gh/')
    || normalized.toLowerCase().includes('/proc/') && basename === 'environ'
  ) {
    throw new Error('Path references a protected secret/config location');
  }

  return value;
}

export function classifyCommand(command) {
  const text = String(command || '').trim();
  if (!text) return { blocked: true, needsApproval: true, reason: 'Empty command' };

  if (commandTouchesBlockedPath(text)) {
    return {
      blocked: true,
      needsApproval: true,
      reason: 'Command references a protected secret/config path',
    };
  }

  if (BLOCKED_COMMAND_PATTERNS.some(pattern => pattern.test(text))) {
    return {
      blocked: true,
      needsApproval: true,
      reason: 'Command could dump environment variables or credential stores',
    };
  }

  if (DANGEROUS_COMMAND_PATTERNS.some(pattern => pattern.test(text))) {
    return { blocked: false, needsApproval: true, reason: 'Command may modify files, install packages, or access the network' };
  }

  if (SHELL_SYNTAX_PATTERN.test(text)) {
    return { blocked: false, needsApproval: true, reason: 'Command uses shell syntax and requires explicit approval' };
  }

  // User allowlists may suppress prompts only after non-bypassable safety checks.
  try {
    const userPatterns = getAllowlistRegexes();
    if (Array.isArray(userPatterns) && userPatterns.some(pattern => pattern.test(text))) {
      return { blocked: false, needsApproval: false, reason: 'Matched user allowlist' };
    }
  } catch {
    // Ignore allowlist errors and fall back to defaults.
  }

  if (READ_ONLY_COMMAND_PATTERNS.some(pattern => pattern.test(text))) {
    return { blocked: false, needsApproval: false, reason: 'Read-only command' };
  }

  return { blocked: false, needsApproval: true, reason: 'Command is not known to be read-only' };
}

export function sanitizeUserTask(task) {
  return redactSensitive(task)
    .replace(/session password\s*[:=]\s*\S+/gi, 'session password: [REDACTED]')
    .replace(/private key\s*[:=]\s*\S+/gi, 'private key: [REDACTED]');
}
