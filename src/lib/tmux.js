import os from 'node:os';
import path from 'node:path';

export const TMUX_SESSION_NAME = 'SecureLink_Session';
export const TMUX_SOCKET_PATH = path.join(os.tmpdir(), 'ipingyou-tmux.sock');

export function tmuxSocketArgs() {
  return ['-S', TMUX_SOCKET_PATH];
}

export function tmuxSocketCommand() {
  return `tmux -S ${TMUX_SOCKET_PATH}`;
}
