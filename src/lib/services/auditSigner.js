/**
 * ============================================================
 *  Tamper-Evident Cryptographic Signed Audit Log Service
 * ============================================================
 *  Exports session history logs into signed JSON/CSV formats
 *  with SHA-256 HMAC cryptographic signatures for audit verification.
 * ============================================================
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import chalk from 'chalk';

const SECRET_SALT = 'ipingyou-audit-signature-key-v1';

/**
 * Compute SHA-256 HMAC signature for log data string.
 * @param {string} content 
 * @returns {string}
 */
export function computeSignature(content) {
  return crypto.createHmac('sha256', SECRET_SALT).update(content).digest('hex');
}

/**
 * Export session logs to signed JSON or CSV format.
 * @param {'json'|'csv'} format 
 * @returns {string} Output file path
 */
export function exportSignedAuditLog(format = 'json') {
  const logDir = path.join(os.homedir(), '.ipingyou', 'logs');
  if (!fs.existsSync(logDir)) throw new Error('No log directory found');

  const files = fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl'));
  if (files.length === 0) throw new Error('No log files available');

  const allLogs = [];
  for (const f of files) {
    const lines = fs.readFileSync(path.join(logDir, f), 'utf8').trim().split('\n');
    for (const line of lines) {
      if (line) {
        try { allLogs.push(JSON.parse(line)); } catch {}
      }
    }
  }

  const exportDir = path.join(os.homedir(), '.ipingyou', 'exports');
  if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir, { recursive: true });

  const timestamp = Date.now();
  let content = '';
  let fileName = `audit-export-${timestamp}.${format}`;

  if (format === 'csv') {
    const headers = 'timestamp,event,uid,clientIp,status\n';
    const rows = allLogs.map(l => `"${l.timestamp || ''}","${l.event || ''}","${l.uid || ''}","${l.clientIp || ''}","${l.status || ''}"`).join('\n');
    content = headers + rows;
  } else {
    content = JSON.stringify(allLogs, null, 2);
  }

  const signature = computeSignature(content);
  const signedPayload = JSON.stringify({
    exportedAt: new Date().toISOString(),
    format,
    recordCount: allLogs.length,
    signature,
    data: content
  }, null, 2);

  const outPath = path.join(exportDir, fileName);
  fs.writeFileSync(outPath, signedPayload, 'utf8');

  console.log(chalk.bold.green(`  ✅ Cryptographic Signed Audit Log Exported: ${outPath}`));
  console.log(chalk.cyan(`  🔐 SHA-256 Signature: ${signature}`));
  return outPath;
}

/**
 * Verify cryptographic signature of exported audit file.
 * @param {string} filePath 
 * @returns {boolean}
 */
export function verifySignedAuditLog(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.signature || !parsed.data) {
      console.log(chalk.red('  ❌ INVALID AUDIT FILE: Missing signature or data field.'));
      return false;
    }

    const expectedSig = computeSignature(parsed.data);
    if (parsed.signature === expectedSig) {
      console.log(chalk.bold.green('  ✅ VERIFIED: Audit log signature is 100% VALID & TAMPER-FREE!'));
      console.log(chalk.dim(`     Records: ${parsed.recordCount} | Exported: ${parsed.exportedAt}`));
      return true;
    } else {
      console.log(chalk.bold.red('  🚨 WARNING: TAMPER DETECTED! Audit file signature mismatch.'));
      return false;
    }
  } catch (err) {
    console.log(chalk.red(`  ❌ Verification error: ${err.message}`));
    return false;
  }
}
