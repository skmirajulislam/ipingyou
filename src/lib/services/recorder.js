/**
 * ============================================================
 *  SSH Terminal Session Recorder (Asciinema v2 .cast format)
 * ============================================================
 *  Records interactive SSH terminal sessions into standard
 *  Asciinema v2 .cast format files for audit playback.
 * ============================================================
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';

export class SessionRecorder {
  constructor(uid, width = 80, height = 24) {
    this.uid = uid;
    this.width = width;
    this.height = height;
    this.startTime = Date.now();
    this.recordingDir = path.join(os.homedir(), '.ipingyou', 'recordings');
    this.filePath = path.join(this.recordingDir, `session-${uid}-${Date.now()}.cast`);
    this.isRecording = false;

    this.init();
  }

  init() {
    try {
      if (!fs.existsSync(this.recordingDir)) {
        fs.mkdirSync(this.recordingDir, { recursive: true });
      }

      const header = JSON.stringify({
        version: 2,
        width: this.width,
        height: this.height,
        timestamp: Math.floor(this.startTime / 1000),
        title: `iPingYou SSH Session ${this.uid}`,
        env: { TERM: process.env.TERM || 'xterm-256color', SHELL: process.env.SHELL || '/bin/bash' }
      }) + '\n';

      fs.writeFileSync(this.filePath, header, 'utf8');
      this.isRecording = true;
      console.log(chalk.dim(`  📹 Session recording active: ${this.filePath}`));
    } catch (err) {
      console.error(chalk.yellow(`  ⚠️  Failed to initialize recorder: ${err.message}`));
      this.isRecording = false;
    }
  }

  /**
   * Record terminal output chunk.
   * @param {string|Buffer} data 
   */
  recordOutput(data) {
    if (!this.isRecording) return;
    try {
      const timeOffset = (Date.now() - this.startTime) / 1000;
      const text = typeof data === 'string' ? data : data.toString('utf8');
      const entry = JSON.stringify([timeOffset, 'o', text]) + '\n';
      fs.appendFileSync(this.filePath, entry, 'utf8');
    } catch {
      // Ignore write errors to prevent session interruption
    }
  }

  stop() {
    if (this.isRecording) {
      this.isRecording = false;
      console.log(chalk.green(`  ✅ Recording saved: ${this.filePath}`));
    }
  }
}
