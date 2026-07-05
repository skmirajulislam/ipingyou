import crypto from 'node:crypto';
import fs from 'node:fs';
import { canUseWorkers, runWorkerTask } from './worker-runtime.js';

const WORKER_CHECKSUM_THRESHOLD_BYTES = 2 * 1024 * 1024;

async function calculateChecksumStream(filePath) {
  return new Promise((resolve) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', () => resolve(null));
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

export async function calculateChecksum(filePath) {
  const stat = await fs.promises.stat(filePath).catch(() => null);
  if (!stat || !stat.isFile()) return null;

  if (canUseWorkers() && stat.size >= WORKER_CHECKSUM_THRESHOLD_BYTES) {
    try {
      const result = await runWorkerTask('checksum', { filePath });
      return result.digest || null;
    } catch {
      return calculateChecksumStream(filePath);
    }
  }

  return calculateChecksumStream(filePath);
}
