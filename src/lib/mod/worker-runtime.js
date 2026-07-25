import { Worker } from 'node:worker_threads';

const workerUrl = new URL('../workers/crypto-checksum-worker.js', import.meta.url);
const workersDisabled = process.env.IPINGYOU_DISABLE_WORKERS === '1';
const MAX_PENDING_TASKS = 128;
const WORKER_IDLE_TIMEOUT_MS = 30 * 1000;

let worker = null;
let requestCounter = 0;
const pending = new Map();
let idleShutdownTimer = null;

function clearIdleShutdown() {
  if (idleShutdownTimer) clearTimeout(idleShutdownTimer);
  idleShutdownTimer = null;
}

function scheduleIdleShutdown() {
  clearIdleShutdown();
  if (!worker || pending.size > 0) return;
  const idleWorker = worker;
  idleShutdownTimer = setTimeout(() => {
    idleShutdownTimer = null;
    if (pending.size > 0 || worker !== idleWorker) return;
    worker = null;
    idleWorker.terminate().catch(() => {});
  }, WORKER_IDLE_TIMEOUT_MS);
  idleShutdownTimer.unref?.();
}

function resetWorker(err) {
  clearIdleShutdown();
  for (const { reject } of pending.values()) {
    reject(err);
  }
  pending.clear();
  worker = null;
}

function ensureWorker() {
  if (worker || workersDisabled) return worker;

  const activeWorker = new Worker(workerUrl, {
    resourceLimits: {
      maxOldGenerationSizeMb: 128,
    },
  });
  worker = activeWorker;
  activeWorker.unref();

  activeWorker.on('message', (message) => {
    const { id, ok, result, error } = message || {};
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    if (pending.size === 0 && worker === activeWorker) {
      activeWorker.unref();
      scheduleIdleShutdown();
    }
    if (ok) {
      entry.resolve(result);
      return;
    }
    entry.reject(new Error(error || 'Worker task failed'));
  });

  activeWorker.on('error', (err) => {
    if (worker === activeWorker) resetWorker(err);
  });

  activeWorker.on('exit', (code) => {
    if (worker !== activeWorker) return;
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
  if (pending.size >= MAX_PENDING_TASKS) {
    const error = new Error('Worker task queue is at capacity');
    error.code = 'WORKER_QUEUE_FULL';
    throw error;
  }

  const id = ++requestCounter;
  return new Promise((resolve, reject) => {
    clearIdleShutdown();
    pending.set(id, { resolve, reject });
    activeWorker.ref();
    activeWorker.postMessage({ id, type, payload });
  });
}
