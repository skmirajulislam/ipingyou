import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';
import { openUrl } from '../mod/open-url.js';
import chalk from 'chalk';
import { secureSensitive, secureSensitiveUrl } from '../mod/secure-print.js';

const HTML_CONTENT = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>iPingYou — Secure Chat Room</title>
  <style>
    :root {
      --bg: #0f172a;
      --bg-panel: #1e293b;
      --text: #f8fafc;
      --primary: #38bdf8;
      --accent: #818cf8;
      --danger: #ef4444;
      --border: #334155;
    }
    body {
      margin: 0; padding: 0; font-family: 'Inter', system-ui, sans-serif;
      background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column;
    }
    header {
      background: var(--bg-panel); padding: 1rem 2rem; border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
    }
    h1 { margin: 0; font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .badge { background: var(--primary); color: #000; padding: 0.2rem 0.5rem; border-radius: 999px; font-size: 0.8rem; font-weight: bold; }
    .leave-btn {
      background: var(--danger); color: white; border: none; padding: 0.5rem 1rem; border-radius: 0.5rem;
      font-weight: bold; cursor: pointer; transition: opacity 0.2s;
    }
    .leave-btn:hover { opacity: 0.8; }
    main {
      flex: 1; display: flex; overflow: hidden;
    }
    .sidebar {
      width: 250px; background: var(--bg-panel); border-right: 1px solid var(--border);
      padding: 1rem; overflow-y: auto;
    }
    .chat-area {
      flex: 1; display: flex; flex-direction: column; background: var(--bg);
    }
    .messages {
      flex: 1; padding: 1.5rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;
    }
    .message { max-width: 70%; padding: 0.8rem 1rem; border-radius: 1rem; line-height: 1.4; animation: popIn 0.3s ease-out; }
    .message.system { max-width: 100%; align-self: center; background: transparent; color: #94a3b8; font-size: 0.9rem; font-style: italic; text-align: center; }
    .message.self { align-self: flex-end; background: var(--primary); color: #000; border-bottom-right-radius: 0.25rem; }
    .message.other { align-self: flex-start; background: var(--bg-panel); border-bottom-left-radius: 0.25rem; }
    .message-header { font-size: 0.75rem; margin-bottom: 0.25rem; opacity: 0.8; }
    .input-area {
      padding: 1rem; background: var(--bg-panel); border-top: 1px solid var(--border); display: flex; gap: 1rem;
    }
    input[type="text"] {
      flex: 1; background: var(--bg); border: 1px solid var(--border); color: var(--text);
      padding: 0.75rem 1rem; border-radius: 0.5rem; outline: none; transition: border-color 0.2s;
    }
    input[type="text"]:focus { border-color: var(--primary); }
    button.send {
      background: var(--accent); color: white; border: none; padding: 0 1.5rem; border-radius: 0.5rem;
      font-weight: bold; cursor: pointer; transition: transform 0.1s, opacity 0.2s;
    }
    button.send:active { transform: scale(0.95); }
    @keyframes popIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    
    .btn-action { padding: 0.4rem 0.8rem; border-radius: 0.4rem; font-weight: bold; border: none; cursor: pointer; font-size: 0.8rem; }
    .btn-approve { background: #22c55e; color: #000; }
    .btn-deny { background: var(--danger); color: white; }
    .badge-pending { background: #eab308; color: #000; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: bold; }
    .modal { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(15,23,42,0.85); backdrop-filter: blur(4px); display: none; justify-content: center; align-items: center; z-index: 1000; }
    .modal.open { display: flex; }
    .modal-content { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 12px; width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto; padding: 1.5rem; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    .approval-card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
    #toast { position: fixed; bottom: 2rem; right: 2rem; background: #22c55e; color: #000; padding: 0.8rem 1.5rem; border-radius: 8px; font-weight: bold; opacity: 0; transition: opacity 0.3s; pointer-events: none; z-index: 2000; }
    #toast.show { opacity: 1; }
  </style>
</head>
<body>
  <header>
    <h1>💬 SecureLink Chat <span class="badge" id="conn-count">0 connected</span></h1>
    <div style="display:flex;gap:0.75rem;align-items:center">
      <button class="leave-btn" id="approvals-btn" style="display:none;background:var(--accent);" type="button">
        🛡️ Host Approvals <span class="badge-pending" id="pending-badge" style="display:none">0</span>
      </button>
      <button class="leave-btn" id="leave-btn" type="button">Leave Room</button>
    </div>
  </header>
  <main>
    <div class="sidebar">
      <h3 style="margin-top:0; font-size: 0.9rem; color: #94a3b8; text-transform: uppercase;">Participants</h3>
      <ul class="user-list" id="users"></ul>
    </div>
    <div class="chat-area">
      <div class="messages" id="msgs"></div>
      <form class="input-area" id="chat-form">
        <input type="text" id="msg-input" placeholder="Type a secure message..." autocomplete="off" disabled>
        <button type="submit" class="send" id="send-btn" disabled>Send</button>
      </form>
    </div>
  </main>

  <div class="modal" id="approvals-modal">
    <div class="modal-content">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
        <h2 style="margin:0;font-size:1.2rem;color:var(--primary)">🛡️ Host Client Approvals</h2>
        <button id="close-modal-btn" class="leave-btn" style="background:var(--border)" type="button">✕ Close</button>
      </div>
      <div id="approvals-list"><p style="color:#94a3b8;font-style:italic">No pending approval requests</p></div>
    </div>
  </div>
  <div id="toast"></div>

  <script>
    const isHost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    let username = isHost ? 'Host' : (prompt('Enter your name for the chat:', 'Guest_' + Math.floor(Math.random() * 899 + 100)) || '').trim();
    if (!username) username = isHost ? 'Host' : 'Guest_' + Math.floor(Math.random() * 899 + 100);

    function showBodyMessage(text, color) {
      const message = document.createElement('h2');
      message.style.cssText = 'text-align:center;margin-top:20vh';
      if (color) message.style.color = color;
      message.textContent = text;
      document.body.replaceChildren(message);
    }

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2500);
    }

    const sessionPassword = window.location.hash.substring(1);
    const hostControlToken = new URLSearchParams(window.location.search).get('hostControlToken');
    if (!sessionPassword) {
      showBodyMessage('Fatal: Missing session password in URL hash. Cannot decrypt E2E chat.', 'red');
      throw new Error("Missing password");
    }

    const approvalsBtn = document.getElementById('approvals-btn');
    const pendingBadge = document.getElementById('pending-badge');
    const approvalsModal = document.getElementById('approvals-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const approvalsList = document.getElementById('approvals-list');

    if (hostControlToken || isHost) {
      approvalsBtn.style.display = 'flex';
      approvalsBtn.onclick = () => approvalsModal.classList.add('open');
      closeModalBtn.onclick = () => approvalsModal.classList.remove('open');
      approvalsModal.onclick = (e) => { if (e.target === approvalsModal) approvalsModal.classList.remove('open'); };

      async function fetchApprovals() {
        try {
          const res = await fetch('/api/approvals');
          if (res.ok) {
            const data = await res.json();
            renderApprovals(data.approvals || []);
          }
        } catch {}
      }

      function renderApprovals(approvals) {
        const pending = approvals.filter(a => a.status === 'pending');
        if (pending.length > 0) {
          pendingBadge.style.display = 'inline-block';
          pendingBadge.textContent = pending.length;
        } else {
          pendingBadge.style.display = 'none';
        }

        if (approvals.length === 0) {
          const empty = document.createElement('p');
          empty.style.cssText = 'color:#94a3b8;font-style:italic';
          empty.textContent = 'No client requests yet';
          approvalsList.replaceChildren(empty);
          return;
        }

        const fragment = document.createDocumentFragment();
        const sortedApprovals = [...approvals].sort((a, b) => (a.status === 'pending' ? -1 : (b.status === 'pending' ? 1 : 0)));
        for (const req of sortedApprovals) {
          const card = document.createElement('div');
          card.className = 'approval-card';
          const isPending = req.status === 'pending';

          const topRow = document.createElement('div');
          topRow.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem';
          const title = document.createElement('strong');
          title.textContent = 'Request ' + String(req.id || '');
          const statusSpan = document.createElement('span');
          statusSpan.className = 'badge-pending';
          statusSpan.style.background = isPending ? '#eab308' : (req.status === 'approved' ? '#22c55e' : '#ef4444');
          statusSpan.style.color = isPending || req.status === 'approved' ? '#000' : '#fff';
          statusSpan.textContent = (req.status || 'pending').toUpperCase();
          topRow.append(title, statusSpan);

          const detailsDiv = document.createElement('div');
          detailsDiv.style.cssText = 'font-size:0.85rem;color:#94a3b8;line-height:1.5';
          detailsDiv.textContent = 'User: ' + String(req.username || 'unknown') + ' | Host: ' + String(req.hostname || 'unknown') + ' | OS: ' + String(req.os || 'unknown') + ' | IP: ' + String(req.ip || 'unknown') + ' (Local: ' + String(req.localIp || 'unknown') + ')';

          card.append(topRow, detailsDiv);

          if (isPending) {
            const actions = document.createElement('div');
            actions.style.cssText = 'display:flex;gap:0.5rem;margin-top:0.75rem';
            const approveBtn = document.createElement('button');
            approveBtn.className = 'btn-action btn-approve';
            approveBtn.textContent = '✅ Approve';
            approveBtn.onclick = () => decide(req.id, 'approved');
            const denyBtn = document.createElement('button');
            denyBtn.className = 'btn-action btn-deny';
            denyBtn.textContent = '❌ Deny';
            denyBtn.onclick = () => decide(req.id, 'denied');
            actions.append(approveBtn, denyBtn);
            card.appendChild(actions);
          }
          fragment.appendChild(card);
        }
        approvalsList.replaceChildren(fragment);
      }

      async function decide(requestId, decision) {
        try {
          const res = await fetch('/api/approval', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ requestId, decision })
          });
          if (res.ok) {
            showToast(decision === 'approved' ? '✅ Client Approved!' : '❌ Client Denied!');
            fetchApprovals();
          } else {
            showToast('Failed: ' + (await res.json()).error);
          }
        } catch (err) { showToast('Error: ' + err.message); }
      }

      setInterval(fetchApprovals, 3000);
      fetchApprovals();
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(wsProtocol + '//' + window.location.host);

    const msgs = document.getElementById('msgs');
    const form = document.getElementById('chat-form');
    const input = document.getElementById('msg-input');
    const sendBtn = document.getElementById('send-btn');
    const leaveBtn = document.getElementById('leave-btn');
    const usersList = document.getElementById('users');
    const connCount = document.getElementById('conn-count');

    // ─── Web Crypto E2E AES-GCM ──────────────────────────────────
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    function buf2hex(buffer) { return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join(''); }
    function hex2buf(hexString) { return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16))); }

    async function deriveKey(password, saltBuffer) {
      const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveBits", "deriveKey"]
      );
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: saltBuffer, iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
    }

    async function encryptPayload(obj) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(sessionPassword, salt);
      const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, enc.encode(JSON.stringify(obj))
      );
      return {
        salt: buf2hex(salt),
        iv: buf2hex(iv),
        ciphertext: buf2hex(ciphertextBuffer)
      };
    }

    async function decryptPayload(encObj) {
      try {
        const salt = hex2buf(encObj.salt);
        const iv = hex2buf(encObj.iv);
        const ciphertext = hex2buf(encObj.ciphertext);
        const key = await deriveKey(sessionPassword, salt);
        const decryptedBuffer = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv }, key, ciphertext
        );
        return JSON.parse(dec.decode(decryptedBuffer));
      } catch (e) {
        return null;
      }
    }

    // ─── UI Logic ────────────────────────────────────────────────
    function appendMessage(msg) {
      const div = document.createElement('div');
      if (msg.type === 'system') {
        div.className = 'message system';
        div.textContent = msg.text;
      } else {
        div.className = 'message ' + (msg.sender === username ? 'self' : 'other');
        const header = document.createElement('div');
        header.className = 'message-header';
        header.textContent = String(msg.sender || 'Unknown') + ' • ' + String(msg.time || '');
        const body = document.createElement('div');
        body.textContent = String(msg.text || '');
        div.appendChild(header);
        div.appendChild(body);
      }
      msgs.appendChild(div);
      msgs.scrollTop = msgs.scrollHeight;
    }

    function updateUsers(users) {
      usersList.replaceChildren();
      users.forEach(u => {
        const li = document.createElement('li');
        li.className = 'user-item';
        li.textContent = u;
        usersList.appendChild(li);
      });
      connCount.textContent = users.length + ' connected';
    }

    ws.onopen = async () => {
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
      
      const encPayload = await encryptPayload({ type: 'join', sender: username });
      if (hostControlToken) ws.send(JSON.stringify({ type: 'host_auth', token: hostControlToken }));
      ws.send(JSON.stringify({ type: 'join_event', username })); // Send unencrypted name for sidebar
      ws.send(JSON.stringify({ type: 'e2e', payload: encPayload }));
    };

    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'state') {
        updateUsers(data.users);
      } else if (data.type === 'close') {
        appendMessage({ type: 'system', text: 'The Host has closed the chat room. You may leave now.' });
        ws.close();
        input.disabled = true;
        sendBtn.disabled = true;
      } else if (data.type === 'e2e') {
        // Decrypt the incoming E2E message
        const decrypted = await decryptPayload(data.payload);
        if (decrypted) {
          if (decrypted.type === 'join') {
            appendMessage({ type: 'system', text: \`\${decrypted.sender} has joined the chat (E2E Encrypted)\` });
          } else if (decrypted.type === 'chat') {
            appendMessage(decrypted);
          }
        }
      } else {
        appendMessage(data);
      }
    };

    ws.onclose = () => {
      appendMessage({ type: 'system', text: 'Connection closed.' });
      input.disabled = true;
      sendBtn.disabled = true;
    };

    form.onsubmit = async (e) => {
      e.preventDefault();
      const text = input.value.trim();
      if (!text) return;
      
      const msgObj = { type: 'chat', sender: username, text: text, time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) };
      const encPayload = await encryptPayload(msgObj);
      
      ws.send(JSON.stringify({ type: 'e2e', payload: encPayload }));
      input.value = '';
    };

    leaveBtn.onclick = () => {
      if (isHost) {
        if(confirm('Are you sure you want to close the chat room for everyone?')) {
          ws.send(JSON.stringify({ type: 'host_close' }));
          window.close();
        }
      } else {
        ws.close();
        window.close();
        showBodyMessage('You have left the chat. You can close this tab.');
      }
    };
  </script>
</body>
</html>
`;

export async function startChatServer(onClose, hostContext = null) {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      const reqPath = (req.url || '/').split('?')[0];

      if (reqPath === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html',
          'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ws: wss: http: https:",
        });
        res.end(HTML_CONTENT);
        return;
      }

      if (reqPath === '/api/approvals' && hostContext?.fetchDecryptedApprovals) {
        try {
          const data = await hostContext.fetchDecryptedApprovals();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(data));
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      if (reqPath === '/api/approval' && req.method === 'POST' && hostContext?.decideApproval) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const parsed = JSON.parse(body || '{}');
            const { requestId, decision } = parsed;
            await hostContext.decideApproval(requestId, decision);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    });

    const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
    const clients = new Map(); // ws -> username
    const hostControlToken = crypto.randomBytes(32).toString('base64url');

    function broadcastState() {
      const users = Array.from(clients.values());
      const payload = JSON.stringify({ type: 'state', users });
      for (const client of wss.clients) {
        if (client.readyState === 1) client.send(payload);
      }
    }

    function broadcastMsg(msg) {
      const payload = JSON.stringify(msg);
      for (const client of wss.clients) {
        if (client.readyState === 1) client.send(payload);
      }
    }

    wss.on('connection', (ws) => {
      ws.on('message', (message) => {
        try {
          if (message.length > 64 * 1024) return ws.close(1009, 'Message too large');
          const data = JSON.parse(message);
          if (!data || typeof data !== 'object') return;
          
          if (data.type === 'host_auth') {
            if (typeof data.token === 'string'
              && data.token.length === hostControlToken.length
              && crypto.timingSafeEqual(Buffer.from(data.token), Buffer.from(hostControlToken))) {
              ws.isHost = true;
            }
          } else if (data.type === 'e2e') {
            // E2E messages just get forwarded to all clients
            if (!data.payload || typeof data.payload !== 'object'
              || typeof data.payload.salt !== 'string' || typeof data.payload.iv !== 'string'
              || typeof data.payload.ciphertext !== 'string'
              || data.payload.salt.length > 64 || data.payload.iv.length > 64 || data.payload.ciphertext.length > 48 * 1024) return;
            broadcastMsg(data);
          } else if (data.type === 'join_event') {
            const username = String(data.username || `User_${Math.floor(Math.random()*1000)}`).slice(0, 64);
            clients.set(ws, username);
            broadcastState();
          } else if (data.type === 'host_close' && ws.isHost) {
            broadcastMsg({ type: 'close' });
            server.close();
            if (onClose) onClose();
          }
        } catch (e) {
          // ignore invalid parse
        }
      });

      ws.on('close', () => {
        clients.delete(ws);
        broadcastState();
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ port, server, hostControlToken });
    });
  });
}

export async function openLocalChatUI(port, password, hostControlToken = null) {
  try {
    const hostQuery = hostControlToken ? `?hostControlToken=${encodeURIComponent(hostControlToken)}` : '';
    const chatUrl = `http://localhost:${port}${hostQuery}#${password}`;
    await openUrl(chatUrl);
  } catch {
    const hostQuery = hostControlToken ? `?hostControlToken=${encodeURIComponent(secureSensitive(hostControlToken))}` : '';
    console.log(chalk.dim(`     Unable to auto-open browser. Visit ${secureSensitiveUrl(`http://localhost:${port}${hostQuery}`, password)}`));
  }
}

