import os from 'node:os';
import path from 'node:path';

export const TMUX_SESSION_PREFIX = 'SecureLink_';
export const TMUX_SESSION_NAME = 'SecureLink_Session';
export const TMUX_SOCKET_PATH = path.join(os.tmpdir(), 'ipingyou-tmux.sock');

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
  const rand = Math.random().toString(36).slice(2, 6);
  return `${TMUX_SESSION_PREFIX}${safeLabel}_${stamp}${rand}`;
}
