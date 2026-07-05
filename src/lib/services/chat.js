import http from 'node:http';
import { WebSocketServer } from 'ws';
import { openUrl } from '../mod/open-url.js';
import chalk from 'chalk';
import { secureSensitiveUrl } from '../mod/secure-print.js';

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
    
    .user-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.5rem; }
    .user-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; border-radius: 0.5rem; background: var(--bg); }
    .user-item::before { content: ''; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; }
  </style>
</head>
<body>
  <header>
    <h1>💬 SecureLink Chat <span class="badge" id="conn-count">0 connected</span></h1>
    <button class="leave-btn" id="leave-btn">Leave Room</button>
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

  <script>
    const isHost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    let username = isHost ? 'Host' : prompt('Enter your name for the chat:', 'Client_' + Math.floor(Math.random()*1000));
    if (!username) username = 'Anonymous';

    function showBodyMessage(text, color) {
      const message = document.createElement('h2');
      message.style.cssText = 'text-align:center;margin-top:20vh';
      if (color) message.style.color = color;
      message.textContent = text;
      document.body.replaceChildren(message);
    }

    const sessionPassword = window.location.hash.substring(1);
    if (!sessionPassword) {
      showBodyMessage('Fatal: Missing session password in URL hash. Cannot decrypt E2E chat.', 'red');
      throw new Error("Missing password");
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

export async function startChatServer(onClose) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(HTML_CONTENT);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    const wss = new WebSocketServer({ server });
    const clients = new Map(); // ws -> username

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
          const data = JSON.parse(message);
          
          if (data.type === 'e2e') {
            // E2E messages just get forwarded to all clients
            broadcastMsg(data);
          } else if (data.type === 'join_event') {
            clients.set(ws, data.username || `User_${Math.floor(Math.random()*1000)}`);
            broadcastState();
          } else if (data.type === 'host_close') {
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
      resolve({ port, server });
    });
  });
}

export async function openLocalChatUI(port, password) {
  try {
    const chatUrl = `http://localhost:${port}#${password}`;
    await openUrl(chatUrl);
  } catch {
    console.log(chalk.dim(`     Unable to auto-open browser. Visit ${secureSensitiveUrl(`http://localhost:${port}`, password)}`));
  }
}
