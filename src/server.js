/**
 * ============================================================
 *  SecureLink-CLI — Central Broker Server
 * ============================================================
 *  A lightweight REST relay that pairs hosts and clients via
 *  temporary UIDs.  The broker is a DUMB PIPE — it stores and
 *  returns encrypted blobs without ever seeing plaintext.
 *  Encryption/decryption happens ONLY on the CLI side.
 * ============================================================
 */

import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import crypto from 'node:crypto';
import { cleanupSessionLog, initSessionLog, logSessionEvent } from './lib/session-log.js';

const app = express();
const brokerLogPath = initSessionLog('broker');
if (brokerLogPath) {
  console.log(`  📜 Broker session log: ${brokerLogPath}`);
}

// ─── Process-Level Error Handling ────────────────────────────
let shuttingDown = false;

function handleShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logSessionEvent('broker_shutdown', { signal });
  cleanupSessionLog();
  process.exit(0);
}

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err.message);
  logSessionEvent('broker_uncaught_exception', { error: err.message }, 'error');
  if (err.stack) console.error(err.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  const message = reason instanceof Error ? reason.message : String(reason);
  logSessionEvent('broker_unhandled_rejection', { error: message }, 'error');
});

// ─── Basic Security Headers ──────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // Limit JSON payload size to prevent payload-based DoS
app.use((req, res, next) => {
  const startedAt = Date.now();
  res.on('finish', () => {
    logSessionEvent('broker_http', {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - startedAt,
    });
  });
  next();
});

// ─── Rate Limiters ───────────────────────────────────────────
// Trust proxy is required if the server is behind a reverse proxy (like Render, Heroku, Cloudflare)
app.set('trust proxy', 1);

// General rate limiter for public requests (100 reqs per 15 minutes per IP)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limiter for registration/revocation endpoints (e.g. 20 reqs per 15 mins)
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many registration/revocation requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Higher limiter for host-authenticated endpoints (dashboard polling, approvals, telemetry views)
const hostLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  message: { error: 'Too many host requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Active Defense & IP Blacklisting (IDS) ──────────────────
const ipViolations = new Map(); // ip → violation_count
const blacklistedIPs = new Set();
const VIOLATION_THRESHOLD = 5; // Block IP after 5 malicious requests

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (blacklistedIPs.has(ip)) {
    console.warn(`🛡️  Dropped traffic from blacklisted IP: ${ip}`);
    return res.status(403).json({ error: 'Your IP has been banned due to suspicious activity.' });
  }
  next();
});

function recordViolation(req) {
  const ip = req.ip || req.connection.remoteAddress;
  const count = (ipViolations.get(ip) || 0) + 1;
  ipViolations.set(ip, count);
  console.warn(`🚨 Violation recorded for IP ${ip} (${count}/${VIOLATION_THRESHOLD})`);
  
  if (count >= VIOLATION_THRESHOLD) {
    blacklistedIPs.add(ip);
    console.error(`💥 HACKING DETECTED: Auto-banned IP ${ip} to defend server.`);
  }
}

// ─── Constants & Limits ──────────────────────────────────────
const TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_UIDS = 50000;        // Max concurrent tunnels (prevent memory leak)
const MAX_VIOLATIONS = 50000;  // Max tracked malicious IPs before reset
const MAX_RESOLVES_PER_UID = 100; // Max resolves before auto-revoke (anti-scraping)
const BROKER_SECRET = process.env.BROKER_HMAC_SECRET || crypto.randomBytes(32).toString('hex');

const store = new Map(); // uid → { iv, ciphertext, salt, createdAt, clients: [], approvals: [], hostToken, resolveCount }

// ─── Security Helpers ────────────────────────────────────────
const SAFE_PARAM = /^[a-zA-Z0-9_-]{1,64}$/;
const HOST_TOKEN_FORMAT = /^[a-f0-9]{64}$/i;

function isSafeParam(val) {
  return typeof val === 'string' && SAFE_PARAM.test(val);
}

function generateHostToken(uid) {
  return crypto.createHmac('sha256', BROKER_SECRET).update(uid).digest('hex');
}

function requireHostToken(req, res, entry) {
  const token = req.headers['x-host-token'];
  if (!token || token !== entry.hostToken) {
    recordViolation(req);
    res.status(403).json({ error: 'Forbidden — invalid or missing host authentication token' });
    return false;
  }
  return true;
}

function isEncryptedPayload(body) {
  return body
    && /^[a-f0-9]{32}$/i.test(body.iv || '')
    && /^[a-f0-9]{32}$/i.test(body.salt || '')
    && typeof body.ciphertext === 'string'
    && body.ciphertext.length > 0
    && /^[A-Za-z0-9+/]+={0,2}$/.test(body.ciphertext);
}

function pruneExpired() {
  const now = Date.now();
  for (const [uid, entry] of store) {
    if (now - entry.createdAt > TTL_MS) {
      store.delete(uid);
      console.log(`🗑️  Expired UID: ${uid}`);
    }
  }

  // Strict check to prevent malicious OOM overflow
  if (ipViolations.size > MAX_VIOLATIONS) ipViolations.clear();
  if (blacklistedIPs.size > MAX_VIOLATIONS) blacklistedIPs.clear();
}

// Run pruning every 5 minutes
setInterval(pruneExpired, 5 * 60 * 1000);

// ─── Routes ──────────────────────────────────────────────────

// Health
app.get('/health', generalLimiter, (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), activeUIDs: store.size });
});

/**
 * POST /register
 * Body: { uid: string, iv: string, ciphertext: string, salt: string }
 *
 * The broker receives an ALREADY-ENCRYPTED blob from the host CLI.
 * It never decrypts — just stores the { iv, ciphertext } pair.
 */
app.post('/register', strictLimiter, (req, res) => {
  try {
    const { uid, iv, ciphertext, salt, approvalRequired = false, oneTime = false, hostToken: providedHostToken } = req.body;

    if (!uid || !iv || !ciphertext || !salt) {
      recordViolation(req);
      return res.status(400).json({ error: 'Missing uid, iv, ciphertext, or salt' });
    }

    if (typeof uid !== 'string' || uid.length < 6 || uid.length > 16) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid UID format (6-16 chars)' });
    }

    // Validate IV format — must be 32 hex chars (16 bytes)
    if (!/^[a-f0-9]{32}$/i.test(iv)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid IV format (expected 32 hex chars)' });
    }

    if (!/^[a-f0-9]{32}$/i.test(salt)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid salt format (expected 32 hex chars)' });
    }

    // Validate ciphertext is non-empty base64
    if (typeof ciphertext !== 'string' || ciphertext.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(ciphertext)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid ciphertext' });
    }

    // Prevent broker OOM
    if (store.size >= MAX_UIDS && !store.has(uid)) {
      return res.status(503).json({ error: 'Broker is at maximum capacity. Please try again later.' });
    }

    // Use provided host token if valid; otherwise generate a fresh one
    const hostToken = (typeof providedHostToken === 'string' && HOST_TOKEN_FORMAT.test(providedHostToken))
      ? providedHostToken
      : generateHostToken(uid + Date.now().toString());

    // Store the encrypted blob as-is — broker NEVER decrypts
    store.set(uid, {
      iv,
      ciphertext,
      salt,
      approvalRequired: Boolean(approvalRequired),
      oneTime: Boolean(oneTime),
      createdAt: Date.now(),
      clients: [],
      approvals: [],
      hostToken,
      resolveCount: 0,
    });

    console.log(`✅ [${new Date().toLocaleTimeString()}] Registered UID: ${uid} (encrypted, ${ciphertext.length} bytes)`);
    // Return host token — this is the ONLY time it's sent; host must store it
    res.json({ status: 'registered', uid, hostToken, expiresIn: '1 hour' });
  } catch (err) {
    console.error('❌ Register error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /resolve/:uid
 * Returns the ENCRYPTED blob { iv, ciphertext } for a given UID.
 * The client CLI decrypts it locally — the broker never sees plaintext.
 */
app.get('/resolve/:uid', generalLimiter, (req, res) => {
  try {
    const { uid } = req.params;
    if (!isSafeParam(uid)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid UID format' });
    }

    const entry = store.get(uid);

    if (!entry) {
      return res.status(404).json({ error: 'UID not found or expired' });
    }

    // Check TTL
    if (Date.now() - entry.createdAt > TTL_MS) {
      store.delete(uid);
      return res.status(410).json({ error: 'UID expired' });
    }

    // Enforce one-time sharing: check BEFORE sending response (prevents race condition)
    if (entry.oneTime && entry.resolveCount > 0) {
      store.delete(uid);
      return res.status(410).json({ error: 'One-time session already consumed' });
    }

    // Anti-scraping: cap total resolves per UID
    if (entry.resolveCount >= MAX_RESOLVES_PER_UID) {
      store.delete(uid);
      return res.status(429).json({ error: 'Resolve limit exceeded — session revoked for security' });
    }

    if (entry.approvalRequired) {
      const requestId = req.query.requestId;
      if (requestId && !isSafeParam(requestId)) {
        recordViolation(req);
        return res.status(400).json({ error: 'Invalid requestId format' });
      }
      const approved = entry.approvals.find(request => request.id === requestId && request.status === 'approved');
      if (!approved) {
        return res.status(423).json({ error: 'Host approval required before resolving this session' });
      }
    }

    // Increment resolve counter atomically BEFORE sending response
    entry.resolveCount = (entry.resolveCount || 0) + 1;

    console.log(`🔍 [${new Date().toLocaleTimeString()}] Resolved UID: ${uid} (resolve #${entry.resolveCount})`);

    // Return encrypted blob — client decrypts
    res.json({ uid, iv: entry.iv, ciphertext: entry.ciphertext, salt: entry.salt });

    // Enforce one-time sharing: auto-delete AFTER response sent
    if (entry.oneTime) {
      store.delete(uid);
      console.log(`🔒 [${new Date().toLocaleTimeString()}] One-time UID ${uid} auto-revoked after first resolve`);
    }
  } catch (err) {
    console.error('❌ Resolve error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /approval-request/:uid
 * Client submits encrypted approval metadata. Broker cannot decrypt it.
 */
app.post('/approval-request/:uid', generalLimiter, (req, res) => {
  try {
    const { uid } = req.params;
    if (!isSafeParam(uid)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid UID format' });
    }
    const entry = store.get(uid);
    if (!entry) return res.status(404).json({ error: 'UID not found' });
    if (!isEncryptedPayload(req.body)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid encrypted approval payload' });
    }

    // Generate cryptographically secure request ID
    const id = crypto.randomBytes(12).toString('hex');
    const request = {
      id,
      iv: req.body.iv,
      ciphertext: req.body.ciphertext,
      salt: req.body.salt,
      status: entry.approvalRequired ? 'pending' : 'approved',
      createdAt: Date.now(),
      decidedAt: entry.approvalRequired ? null : Date.now(),
    };

    entry.approvals.push(request);
    if (entry.approvals.length > 50) entry.approvals.shift();
    res.json({ requestId: id, status: request.status, approvalRequired: entry.approvalRequired });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// HOST-ONLY: List approval requests (requires host token)
app.get('/approval-requests/:uid', hostLimiter, (req, res) => {
  if (!isSafeParam(req.params.uid)) return res.status(400).json({ error: 'Invalid UID' });
  const entry = store.get(req.params.uid);
  if (!entry) return res.status(404).json({ error: 'UID not found' });
  // Require host token to view approval list
  if (!requireHostToken(req, res, entry)) return;
  // Strip encrypted payloads — host dashboard only needs id/status/timestamps
  const sanitized = entry.approvals.map(a => ({ id: a.id, status: a.status, createdAt: a.createdAt, decidedAt: a.decidedAt }));
  res.json({ approvalRequired: entry.approvalRequired, approvals: sanitized });
});

// HOST-ONLY: Decide on an approval request (requires host token)
app.post('/approval-requests/:uid/:requestId/:decision', strictLimiter, (req, res) => {
  if (!isSafeParam(req.params.uid) || !isSafeParam(req.params.requestId)) {
    recordViolation(req);
    return res.status(400).json({ error: 'Invalid parameter format' });
  }
  const entry = store.get(req.params.uid);
  if (!entry) return res.status(404).json({ error: 'UID not found' });
  // CRITICAL: Only the host can approve/deny requests
  if (!requireHostToken(req, res, entry)) return;
  const request = entry.approvals.find(item => item.id === req.params.requestId);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (!['approved', 'denied'].includes(req.params.decision)) return res.status(400).json({ error: 'Invalid decision' });
  // Prevent re-deciding already decided requests
  if (request.status !== 'pending') return res.status(409).json({ error: 'Request already decided' });

  request.status = req.params.decision;
  request.decidedAt = Date.now();
  res.json({ status: request.status });
});

// CLIENT: Check own approval status (requires valid requestId — unguessable 24-char hex)
app.get('/approval-status/:uid/:requestId', generalLimiter, (req, res) => {
  if (!isSafeParam(req.params.uid) || !isSafeParam(req.params.requestId)) {
    return res.status(400).json({ error: 'Invalid parameter format' });
  }
  const entry = store.get(req.params.uid);
  if (!entry) return res.status(404).json({ error: 'UID not found' });
  const request = entry.approvals.find(item => item.id === req.params.requestId);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  // Only return status — never leak encrypted approval data
  res.json({ status: request.status });
});

/**
 * POST /client-info/:uid
 * Clients securely post their encrypted hardware telemetry.
 */
app.post('/client-info/:uid', generalLimiter, (req, res) => {
  try {
    const { uid } = req.params;
    if (!isSafeParam(uid)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid UID format' });
    }
    const entry = store.get(uid);
    if (!entry) return res.status(404).json({ error: 'UID not found' });
    if (!isEncryptedPayload(req.body)) {
      recordViolation(req);
      return res.status(400).json({ error: 'Invalid encrypted telemetry payload' });
    }

    entry.clients.push({ iv: req.body.iv, ciphertext: req.body.ciphertext, salt: req.body.salt, seenAt: Date.now() });
    
    // Keep max 50 recent client pings to prevent memory leaks
    if (entry.clients.length > 50) entry.clients.shift();

    res.json({ status: 'ok' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /clients/:uid
 * Host retrieves all securely encrypted client telemetry blobs.
 */
// HOST-ONLY: View client telemetry (requires host token)
app.get('/clients/:uid', hostLimiter, (req, res) => {
  try {
    const { uid } = req.params;
    if (!isSafeParam(uid)) return res.status(400).json({ error: 'Invalid UID format' });
    const entry = store.get(uid);
    if (!entry) return res.status(404).json({ error: 'UID not found' });
    if (!requireHostToken(req, res, entry)) return;

    res.json({ clients: entry.clients });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /revoke/:uid
 * Allows host to explicitly remove their UID before expiry.
 */
// HOST-ONLY: Revoke a session (requires host token)
app.delete('/revoke/:uid', strictLimiter, (req, res) => {
  const { uid } = req.params;
  if (!isSafeParam(uid)) {
    recordViolation(req);
    return res.status(400).json({ error: 'Invalid UID format' });
  }
  const entry = store.get(uid);
  if (!entry) return res.json({ status: 'not_found' });
  if (!requireHostToken(req, res, entry)) return;
  store.delete(uid);
  console.log(`🚫 [${new Date().toLocaleTimeString()}] Revoked UID: ${uid} (authenticated)`);
  res.json({ status: 'revoked' });
});

// ─── Global Error Handler ────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ Express Error:', err.message);
  logSessionEvent('broker_express_error', { path: req.originalUrl, method: req.method, error: err.message }, 'error');
  if (err.stack) console.error(err.stack);
  res.status(err.status || 500).json({ error: 'Internal Server Error' });
});

// ─── Launch ──────────────────────────────────────────────────
// Render injects PORT; locally we use BROKER_PORT; fallback 4000
const PORT = process.env.PORT || process.env.BROKER_PORT || 4000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║   🔗  SecureLink Broker — Active         ║');
  console.log(`  ║   📡  Port: ${String(PORT).padEnd(29)}║`);
  console.log('  ║   🔒  Zero-Knowledge Encrypted Store     ║');
  console.log('  ║   ⏱️   TTL: 1 hour per UID                ║');
  console.log('  ║   🚫  Broker NEVER sees plaintext        ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});

export default app;
