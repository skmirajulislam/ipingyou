/**
 * ============================================================
 *  AI Post-Session Summarizer & Audit Service
 * ============================================================
 *  Analyzes session event logs with Groq AI to generate executive
 *  summaries of changes made during remote SSH sessions.
 * ============================================================
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';
import { executeAiQuery } from '../../modes/ai.js';

/**
 * Generate AI executive summary of past session logs.
 * @param {string} [uid] 
 */
export async function generateAiSessionSummary(uid = null) {
  const logDir = path.join(os.homedir(), '.ipingyou', 'logs');
  if (!fs.existsSync(logDir)) {
    console.log(chalk.yellow('  ⚠️  No session logs found in ~/.ipingyou/logs'));
    return;
  }

  const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
  if (files.length === 0) {
    console.log(chalk.yellow('  ⚠️  No session log files found.'));
    return;
  }

  let targetFile = files[files.length - 1]; // Latest file by default
  if (uid) {
    const match = files.find(f => f.includes(uid));
    if (match) targetFile = match;
  }

  const filePath = path.join(logDir, targetFile);
  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n');

  console.log(chalk.bold.cyan(`\n  🤖 Analyzing session log (${targetFile})...`));

  const prompt = `Analyze the following session log events from an SSH remote session and provide a bulleted summary of key events, client IP connections, approval decisions, file transfers, and commands:\n\n${lines.slice(-50).join('\n')}`;

  try {
    const summary = await executeAiQuery(prompt);
    console.log(chalk.bold.green('\n  📋 AI EXECUTIVE SESSION SUMMARY:'));
    console.log(chalk.white(summary));
  } catch (err) {
    console.log(chalk.red(`  ❌ AI Summary generation failed: ${err.message}`));
  }
}
