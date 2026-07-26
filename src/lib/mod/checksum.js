import crypto from 'node:crypto';
import fs from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { canUseWorkers, runWorkerTask } from './worker-runtime.js';

const WORKER_CHECKSUM_THRESHOLD_BYTES = 2 * 1024 * 1024;

async function calculateChecksumStream(filePath) {
  try {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    await pipeline(stream, hash);
    return hash.digest('hex');
  } catch {
    return null;
  }
}

export async function calculateChecksum(filePath) {
  const stat = await fs.promises.stat(filePath).catch(() => null);
  if (!stat || !stat.isFile()) return null;

  if (canUseWorkers() && stat.size >= WORKER_CHECKSUM_THRESHOLD_BYTES) {
    try {
      const result = await runWorkerTask('checksum', { filePath });
      return result.digest || null;
    } catch (err) {
      if (err?.code === 'WORKER_QUEUE_FULL') throw err;
      return calculateChecksumStream(filePath);
    }
  }

  return calculateChecksumStream(filePath);
}
