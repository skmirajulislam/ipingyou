import { Worker } from 'node:worker_threads';

const workerUrl = new URL('./workers/crypto-checksum-worker.js', import.meta.url);
const workersDisabled = process.env.IPINGYOU_DISABLE_WORKERS === '1';

let worker = null;
let requestCounter = 0;
const pending = new Map();

function resetWorker(err) {
  for (const { reject } of pending.values()) {
    reject(err);
  }
  pending.clear();
  worker = null;
}

function ensureWorker() {
  if (worker || workersDisabled) return worker;

  worker = new Worker(workerUrl, {
    resourceLimits: {
      maxOldGenerationSizeMb: 128,
    },
  });
  worker.unref();

  worker.on('message', (message) => {
    const { id, ok, result, error } = message || {};
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    if (pending.size === 0) worker?.unref();
    if (ok) {
      entry.resolve(result);
      return;
    }
    entry.reject(new Error(error || 'Worker task failed'));
  });

  worker.on('error', (err) => {
    resetWorker(err);
  });

  worker.on('exit', (code) => {
    if (code !== 0) {
      resetWorker(new Error(`Worker exited with code ${code}`));
    } else {
      worker = null;
    }
  });

  return worker;
}

export function canUseWorkers() {
  return !workersDisabled;
}

export function runWorkerTask(type, payload) {
  if (!canUseWorkers()) {
    throw new Error('Worker threads are disabled');
  }
  const activeWorker = ensureWorker();
  if (!activeWorker) {
    throw new Error('Worker is not available');
  }

  const id = ++requestCounter;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    activeWorker.ref();
    activeWorker.postMessage({ id, type, payload });
  });
}
