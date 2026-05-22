<div align="center">
  <h1>🔗 iPingYou — SecureLink CLI v2.0</h1>
  <p><strong>Military-Grade, Zero-Knowledge P2P Remote Access & Collaboration Tool</strong></p>

  [![npm version](https://img.shields.io/npm/v/@miraj181/ipingyou.svg?style=flat-square)](https://www.npmjs.com/package/@miraj181/ipingyou)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
  [![Node.js Version](https://img.shields.io/node/v/@miraj181/ipingyou.svg?style=flat-square)](https://nodejs.org)
</div>

---

**iPingYou** is a zero-configuration Node.js CLI that establishes AES-encrypted, peer-to-peer SSH tunnels using Cloudflare's Edge network. Version 2.0 introduces **End-to-End Encrypted WebSockets**, **Terminal Mirroring**, **Passwordless Ephemeral Keys**, and **Background Daemonization**.

No firewalls to configure. No port forwarding. No plaintext leakage.

## ✨ God-Tier Features (New in v2.0)

* 🔐 **Ephemeral Passwordless Auth**: The Host automatically injects a temporary `Ed25519` key into `authorized_keys`. Clients connect instantly without knowing the machine's actual root/user password. Keys are purged immediately on exit.
* 💬 **E2E Web Crypto Chat Room**: A real-time, browser-based chat UI using native Web Crypto API (`AES-GCM`). Your chat keys are passed via URL fragments (`#password`) so they never touch a server—not even the Host machine's Node server!
* 📺 **Terminal Mirroring**: Wrap client SSH sessions in a multiplexed `tmux` terminal. The Host can spectate connected clients in real-time right from the dashboard to audit or assist.
* 🔄 **Reverse Port Forwarding (`ssh -R`)**: Clients can expose their *local* `localhost` development ports back to the Host through the secure tunnel.
* 📡 **Hardware Telemetry Verification**: Clients silently generate hardware footprint reports (OS, RAM, CPU, IP), encrypt them locally with the session password, and send them to the Host for authorization.
* 🚨 **Panic Kill-Switch**: Type `ipingyou panic` to instantly vaporize all associated keys, wipe all alias configs, and send a `SIGKILL` to every active tunnel and SSH shell.
* 👻 **Daemonization**: Run `ipingyou service install` to quietly install and run the Host listener in the background (survives system reboots using PM2).
* 🧭 **Approval Gate**: Require the Host to explicitly approve clients before they receive tunnel/key material.
* 📦 **One-Time File Share**: Serve a single file/folder over SCP and revoke after use.
* 🌐 **HTTP & TCP Exposure**: Share a local web app or any TCP service (DB/RDP/VNC) beyond SSH.
* 📂 **Shared Drop Folder**: Auto-prepared dropbox folder for safe file transfers (macOS friendly), removed on exit.
* 🧾 **Live Session Logs**: Host/client/broker write ephemeral per-session logs with actions and request/response status, removed on exit.

---

## 🚀 Quick Start

You don't need to download any code. `iPingYou` runs natively from the global npm registry.

### The "On-the-Fly" Way (Recommended)
```bash
# Start the interactive wizard
npx @miraj181/ipingyou

# Instantly spin up your machine as a Host
npx @miraj181/ipingyou host

# Connect to a remote machine using a session UID
npx @miraj181/ipingyou connect
```

### Global Install
```bash
npm install -g @miraj181/ipingyou

# Execute globally using aliases:
ipingyou
# or
securelink
```

---

## 🔒 Zero-Knowledge Architecture

The public broker server exists solely to rendezvous connections and approvals. It is fundamentally a **"Dumb Pipe"**.

### Session Bootstrap & Data Path

```mermaid
graph LR
    H[Host CLI] -->|AES-256-CBC Encrypted Session Payload| B((Broker Relay))
    H -->|Host Auth Token for approvals and telemetry| B
    B -->|Encrypted Session Payload| C[Client CLI]
    C -->|Locally Decrypts Password| C
    C -->|Direct Cloudflare SSH/TCP| H
    C -->|E2E AES-GCM WebSockets| H
```

1. **Host** starts up, spawns `cloudflared` tunnels for SSH/HTTP/TCP and Chat, then generates a random **AES-256 Session Password** plus a **host-only auth token**.
2. **Host** encrypts the session payload with the password and registers the ciphertext (plus the host token) with the Broker under a short UID.
3. **Client** runs `ipingyou connect`, enters the UID and Password.
4. **Client** fetches the ciphertext, decrypts it locally, and connects directly via SSH or WebSockets.
5. On `Ctrl+C`, `tree-kill` initiates a graceful shutdown, revokes the UID from the broker, and removes session artifacts.

### Approval Gate Flow (Optional)

```mermaid
sequenceDiagram
    participant C as Client CLI
    participant B as Broker Relay
    participant H as Host CLI
    C->>B: approval-request encrypted metadata
    H->>B: fetch approvals with x-host-token
    H->>B: approve/deny with x-host-token
    C->>B: poll approval status
    B-->>C: approved/denied
```

1. **Client** submits encrypted approval metadata (username, host, intent) to the Broker.
2. **Host** lists and decides approvals using its host-only auth token; the Broker never shares this token with clients.
3. **Client** polls for approval status and proceeds only when approved.

---

## 🛡️ Security Scanner Disclaimer

Because **iPingYou** is a powerful remote administration tool with features like background daemonization (via PM2), secure shell execution (`execa`), and anti-forensics capabilities (`panic` mode), automated security scanners (such as Socket.dev or enterprise EDRs) may flag this package as a **potential risk** or **malware-like**. 

These alerts (e.g., "AI-detected potential code anomaly", "Shell access", "Network access") are **expected behavior** for a peer-to-peer tunneling utility. The source code is entirely open-source, heavily documented, and uses zero-knowledge encryption to ensure your data is safe.

---

| Tool | Required | Installation Guide |
|------|----------|--------------------|
| **Node.js ≥18** | ✅ | [nodejs.org](https://nodejs.org) |
| **`ssh`** | ✅ | Ships native on macOS/Linux. Windows: `winget install Microsoft.OpenSSH.Client` |
| **`cloudflared`** | ✅ | `brew install cloudflared` or [Download Here](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) |
| **`tmux`** | 〰️ | *Optional*. Required on Host machine if you want to use **Terminal Mirroring**. |

*(Note: The CLI auto-detects your OS and will attempt to guide you on how to install any missing dependencies!)*

---

## 📖 CLI Command Reference

| Command | Description |
|---------|-------------|
| `ipingyou` | Interactive CLI dashboard wizard. |
| `ipingyou host` | Start hosting and exposing your local machine securely. |
| `ipingyou connect -u <UID>` | Connect directly to a specific UID. |
| `ipingyou ai` | Groq-powered task assistant with guarded local/remote tools. |
| `ipingyou doctor` | Diagnostics for dependencies, SSH, broker, SCP, AI, and tests. |
| `ipingyou panic` | 🚨 Self-destruct mode. Wipes configs, memory, and kills all processes. |
| `ipingyou service install` | 👻 Installs Host mode as an always-on background daemon. |
| `ipingyou service stop` | Stops and removes the background daemon. |
| `ipingyou service status` | Shows background daemon status. |
| `ipingyou allowlist` | Manage the AI command allowlist (list/add/remove). |
| `ipingyou history` | View session event logs from `~/.ipingyou/logs`. |

---

## 📜 License

[MIT License](LICENSE) © Sk Mirajul Islam
