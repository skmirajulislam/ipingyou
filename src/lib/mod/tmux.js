import os from 'node:os';
import path from 'node:path';

import crypto from 'node:crypto';

export const TMUX_SESSION_PREFIX = 'SecureLink_';
export const TMUX_SESSION_NAME = 'SecureLink_Session';
export const TMUX_SOCKET_PATH = path.join(os.tmpdir(), `ipingyou-${process.getuid ? process.getuid() : process.pid}-tmux.sock`);

export function tmuxSocketArgs() {
  return ['-S', TMUX_SOCKET_PATH];
}

export function tmuxSocketCommand() {
  return `tmux -S ${TMUX_SOCKET_PATH}`;
}

export function buildTmuxSessionName(label) {
  const safeLabel = String(label || 'client')
    .replace(/[^a-zA-Z0-9_-]/g, '')
    .slice(0, 24) || 'client';
  const stamp = Date.now().toString(36);
  const rand = crypto.randomBytes(3).toString('hex');
  return `${TMUX_SESSION_PREFIX}${safeLabel}_${stamp}${rand}`;
}
