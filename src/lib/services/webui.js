/**
 * ============================================================
 *  Mobile Web UI & Dashboard Service
 * ============================================================
 *  Starts an embedded express web server providing a responsive
 *  glassmorphism mobile UI for status, quick commands, and file transfers.
 * ============================================================
 */

import express from 'express';
import http from 'http';
import chalk from 'chalk';

/**
 * Start embedded Web UI server.
 * @param {object} options 
 * @returns {Promise<{ server: http.Server, url: string, port: number }>}
 */
export async function startMobileWebUI({ uid, password, port = 8080, sessionState }) {
  const app = express();
  app.use(express.json());

  // HTML Dashboard
  app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>iPingYou — Mobile Control Center</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: rgba(30, 41, 59, 0.7);
      --accent: #38bdf8;
      --green: #4ade80;
      --text: #f8fafc;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 20px;
      display: flex;
      flex-direction: column;
      align-items: center;
      min-height: 100vh;
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 24px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    h1 { font-size: 1.4rem; color: var(--accent); margin-top: 0; text-align: center; }
    .badge {
      display: inline-block;
      background: rgba(74, 222, 128, 0.2);
      color: var(--green);
      padding: 4px 12px;
      border-radius: 99px;
      font-size: 0.85rem;
      font-weight: 600;
    }
    .info-group { margin: 16px 0; font-size: 0.95rem; line-height: 1.6; }
    .info-label { color: #94a3b8; }
    .btn {
      width: 100%;
      padding: 12px;
      margin-top: 10px;
      background: var(--accent);
      color: #0f172a;
      border: none;
      border-radius: 8px;
      font-weight: bold;
      font-size: 1rem;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>📱 iPingYou Mobile Control Center</h1>
    <div style="text-align: center;"><span class="badge">● HOST SESSION ACTIVE</span></div>
    
    <div class="info-group">
      <div><span class="info-label">Session UID:</span> <strong>${uid}</strong></div>
      <div><span class="info-label">Encryption Key:</span> <code>${password}</code></div>
      <div><span class="info-label">Status:</span> Secure Tunnel Active</div>
    </div>

    <button class="btn" onclick="alert('Connect via SSH command: npx ipingyou connect --uid ${uid}')">📋 Copy Connection Info</button>
  </div>
</body>
</html>
    `);
  });

  app.get('/api/status', (req, res) => {
    res.json({ status: 'active', uid, extraMinutes: sessionState.extraMinutes || 0 });
  });

  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      const url = `http://localhost:${port}`;
      console.log(chalk.bold.cyan(`  📱 Mobile Web UI active on ${url}`));
      resolve({ server, url, port });
    }).on('error', () => {
      // Fallback to random available port if 8080 is busy
      const fallbackServer = app.listen(0, () => {
        const p = fallbackServer.address().port;
        const url = `http://localhost:${p}`;
        console.log(chalk.bold.cyan(`  📱 Mobile Web UI active on ${url}`));
        resolve({ server: fallbackServer, url, port: p });
      });
    });
  });
}
