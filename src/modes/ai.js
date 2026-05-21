/**
 * AI Mode — privacy-first local/remote task assistant powered by Groq.
 */

import { execa, execaCommand } from 'execa';
import chalk from 'chalk';
import inquirer from 'inquirer';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getAlias } from '../lib/config.js';
import { resolveUID } from '../lib/broker.js';
import { buildSshArgs, extractHostname } from '../lib/ssh.js';
import { addCleanupHook, cleanupAll } from '../lib/cleanup.js';
import { startHostMode } from './host.js';
import { startClientMode } from './client.js';
import { performSCPNonInteractive } from './client.js';
import { DEFAULT_AI_MODEL, createGroqChatCompletion, getGroqApiKey, getRateLimitWarnings, listGroqModels, estimateTokensForMessages } from '../lib/ai/groq.js';
import { classifyCommand, redactSensitive, sanitizeUserTask, truncateForModel } from '../lib/ai/safety.js';
import { recordEvent } from '../lib/session-log.js';

let BROKER_URL = process.env.BROKER_URL || 'https://ipingyou.onrender.com';

const SYSTEM_PROMPT = `You are iPingYou AI Mode, a careful terminal task assistant.
You can request local tools. You must protect user secrets.
Never ask to read private keys, .env files, token stores, ~/.ssh, ~/.ipingyou, or password/config files.
Never include secrets in your final answer. Prefer read-only inspection before changes.
For commands, request the smallest safe command needed.
When you need a command, call a tool. When finished, answer concisely with what happened and next steps.`;

const TOOLS = [
  {
    type: 'function',
    function: {
      name: 'run_command',
      description: 'Run a shell command in the selected AI session scope. In remote mode this runs on the remote host via SSH.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        properties: {
          command: { type: 'string', description: 'The command to execute.' },
          reason: { type: 'string', description: 'Short reason for running this command.' },
        },
        required: ['command', 'reason'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'read_text_file',
      description: 'Read a non-secret text file from the selected session scope.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        properties: {
          filePath: { type: 'string', description: 'Path to a non-secret text file.' },
        },
        required: ['filePath'],
      },
    },
  },
];

const APP_ACTIONS = [
  {
    id: 'host',
    label: 'Start host mode',
    description: 'Expose this machine through iPingYou host mode.',
    pattern: /\b(host|allow remote access|share this machine|expose this machine|start server)\b/i,
    run: async () => startHostMode(),
  },
  {
    id: 'connect',
    label: 'Access a remote machine',
    description: 'Run the normal iPingYou connect flow for SSH/SCP/chat/reverse tunnel.',
    pattern: /\b(connect|access remote|remote machine|ssh|scp|upload|download|file transfer|join chat|reverse tunnel)\b/i,
    run: async () => startClientMode(),
  },
  {
    id: 'help',
    label: 'Show AI mode help',
    description: 'Explain what AI mode can do safely.',
    pattern: /\b(help|what can you do|ai mode|how does this work)\b/i,
    run: async () => {
      console.log('');
      console.log(chalk.bold.cyan('  AI Mode Help'));
      console.log(chalk.dim('  ─────────────────────────────────────'));
      console.log('  • Ask local/remote task questions and AI can inspect with guarded commands.');
      console.log('  • Ask for normal app actions like host/connect/upload/download and AI will offer to launch that flow.');
      console.log('  • Secrets, decrypted tunnel URLs, private keys, .env, ~/.ssh, and ~/.ipingyou are blocked/redacted.');
      console.log('  • Risky commands require confirmation before execution.');
      console.log('');
    },
  },
];

function normalizePrivateKey(privateKey) {
  const normalized = String(privateKey || '').replace(/\\n/g, '\n').replace(/\r\n/g, '\n');
  return normalized.endsWith('\n') ? normalized : `${normalized}\n`;
}

async function writeEphemeralPrivateKey(privateKey) {
  const keyPath = path.join(os.tmpdir(), `ipingyou_ai_${Date.now()}`);
  fs.writeFileSync(keyPath, normalizePrivateKey(privateKey), { mode: 0o600 });

  const result = await execa('ssh-keygen', ['-y', '-f', keyPath], {
    reject: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (result.exitCode !== 0) {
    try { fs.unlinkSync(keyPath); } catch { }
    throw new Error(result.stderr.trim() || 'OpenSSH could not parse the host-provided private key');
  }

  addCleanupHook(() => {
    try { fs.unlinkSync(keyPath); } catch { }
  });

  return keyPath;
}

function parseToolArgs(raw) {
  try {
    return JSON.parse(raw || '{}');
  } catch {
    return {};
  }
}

function buildToolResult(result) {
  return truncateForModel(JSON.stringify(result, null, 2), 12000);
}

async function confirmCommand(scope, command, reason, classification) {
  if (classification.blocked) {
    return false;
  }

  if (!classification.needsApproval) {
    console.log(chalk.dim(`  AI tool: ${scope} $ ${command}`));
    return true;
  }

  console.log('');
  console.log(chalk.yellow('  AI wants to run a command that needs approval:'));
  console.log(chalk.dim(`  Scope:  ${scope}`));
  console.log(chalk.dim(`  Reason: ${reason || classification.reason}`));
  console.log(chalk.cyan(`  ${command}`));

  const { allow } = await inquirer.prompt([{
    type: 'confirm',
    name: 'allow',
    message: 'Allow this command?',
    default: false,
  }]);

  return allow;
}

function matchAppAction(task) {
  const lowered = String(task || '').toLowerCase();
  if (/\b(panic|self[- ]?destruct|wipe traces)\b/i.test(lowered)) {
    return {
      id: 'panic_blocked',
      label: 'Panic mode',
      description: 'Panic mode is intentionally not launched from AI mode. Run `ipingyou panic` directly if you mean it.',
      blocked: true,
    };
  }

  return APP_ACTIONS.find(action => action.pattern.test(task)) || null;
}

async function maybeRunMatchedAppAction(task) {
  const action = matchAppAction(task);
  if (!action) return false;

  console.log('');
  console.log(chalk.cyan(`  I matched this to an iPingYou function: ${action.label}`));
  console.log(chalk.dim(`  ${action.description}`));

  if (action.blocked) {
    console.log(chalk.yellow('  This function is not executed from AI mode for safety.'));
    return true;
  }

  const { runIt } = await inquirer.prompt([{
    type: 'confirm',
    name: 'runIt',
    message: 'Do you want me to run this app function now?',
    default: true,
  }]);

  if (!runIt) return false;
  await action.run();
  return true;
}

function showRateLimitWarnings(rateLimit) {
  const warnings = getRateLimitWarnings(rateLimit, 0.8);
  for (const warning of warnings) {
    console.log(chalk.yellow(
      `  ⚠️  Groq ${warning.label} limit is ${warning.percent}% used ` +
      `(${warning.remaining}/${warning.limit} remaining${warning.reset ? `, resets in ${warning.reset}` : ''}).`
    ));
    console.log(chalk.dim('     Consider switching API key/model or pausing before the key hits its limit.'));
  }
}

async function runLocalCommand(command) {
  const result = await execaCommand(command, {
    shell: true,
    reject: false,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });

  return {
    exitCode: result.exitCode,
    stdout: redactSensitive(result.stdout || ''),
    stderr: redactSensitive(result.stderr || ''),
  };
}

async function runRemoteCommand(context, command) {
  const sshArgs = buildSshArgs(context.hostname, context.privateKeyPath);
  sshArgs.push(`${context.username}@${context.hostname}`, command);
  const result = await execa('ssh', sshArgs, {
    reject: false,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });

  return {
    exitCode: result.exitCode,
    stdout: redactSensitive(result.stdout || ''),
    stderr: redactSensitive(result.stderr || ''),
  };
}

function assertReadablePath(filePath) {
  const classification = classifyCommand(`cat ${filePath}`);
  if (classification.blocked) {
    throw new Error(classification.reason);
  }
}

async function readLocalTextFile(filePath) {
  assertReadablePath(filePath);
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('Path is not a file');
  if (stat.size > 256 * 1024) throw new Error('File is too large for AI mode; use a targeted command instead');
  return redactSensitive(fs.readFileSync(filePath, 'utf8'));
}

async function readRemoteTextFile(context, filePath) {
  assertReadablePath(filePath);
  return runRemoteCommand(context, `python3 - <<'PY'\nfrom pathlib import Path\np=Path(${JSON.stringify(filePath)})\nif not p.is_file(): raise SystemExit('Path is not a file')\nif p.stat().st_size > 262144: raise SystemExit('File is too large for AI mode')\nprint(p.read_text(errors='replace'), end='')\nPY`);
}

async function setupRemoteContext() {
  const { targetMode } = await inquirer.prompt([{
    type: 'list',
    name: 'targetMode',
    message: 'How should AI connect to the remote host?',
    choices: [
      { name: 'Enter UID/session password', value: 'manual' },
      { name: 'Use saved alias', value: 'alias' },
    ],
  }]);

  let uid;
  let password;
  let username;

  if (targetMode === 'alias') {
    const { aliasName } = await inquirer.prompt([{
      type: 'input',
      name: 'aliasName',
      message: 'Alias name:',
      validate: v => v.trim().length > 0 || 'Required',
    }]);
    const alias = getAlias(aliasName.trim());
    if (!alias) throw new Error(`Alias not found: ${aliasName.trim()}`);
    uid = alias.uid;
    password = alias.password;
    username = alias.username;
  } else {
    const answers = await inquirer.prompt([
      { type: 'input', name: 'uid', message: 'Remote host UID:', validate: v => v.trim().length > 0 || 'Required' },
      { type: 'password', name: 'password', message: 'Session password:', mask: '*' },
      { type: 'input', name: 'username', message: 'SSH username:', default: process.env.USER || process.env.USERNAME || 'root' },
    ]);
    uid = answers.uid.trim();
    password = answers.password;
    username = answers.username.trim();
  }

  const payload = await resolveUID(BROKER_URL, uid, password);
  if (!payload || payload.type !== 'ssh') {
    throw new Error('AI remote mode requires an active SSH host session');
  }

  let privateKeyPath = null;
  if (payload.privateKey) {
    privateKeyPath = await writeEphemeralPrivateKey(payload.privateKey);
  }

  return {
    scope: 'remote',
    username,
    hostname: extractHostname(payload.url),
    privateKeyPath,
    sharedDropPath: payload.sharedDropPath || null,
  };
}

async function chooseModel(apiKey) {
  let models = [];
  try {
    models = await listGroqModels(apiKey);
  } catch (err) {
    console.log(chalk.yellow(`  ⚠️  Could not fetch Groq model list: ${err.message}`));
  }

  const ids = models.map(model => model.id).filter(Boolean);
  const preferred = [
    'qwen/qwen3-32b',
    'openai/gpt-oss-120b',
    'llama-3.3-70b-versatile',
    'groq/compound',
    'groq/compound-mini',
  ].filter(id => ids.length === 0 || ids.includes(id));

  const choices = [...new Set([...preferred, DEFAULT_AI_MODEL])].map(id => ({ name: id, value: id }));
  choices.push({ name: 'Type model manually', value: 'manual' });

  const { modelChoice } = await inquirer.prompt([{
    type: 'list',
    name: 'modelChoice',
    message: 'Which Groq model should AI mode use?',
    choices,
  }]);

  if (modelChoice !== 'manual') return modelChoice;

  const { manualModel } = await inquirer.prompt([{
    type: 'input',
    name: 'manualModel',
    message: 'Groq model id:',
    default: DEFAULT_AI_MODEL,
    validate: v => v.trim().length > 0 || 'Required',
  }]);
  return manualModel.trim();
}

async function executeToolCall(context, call) {
  const name = call.function?.name;
  const args = parseToolArgs(call.function?.arguments);

  if (name === 'run_command') {
    const command = String(args.command || '').trim();
    const reason = String(args.reason || '').trim();
    const classification = classifyCommand(command);
    if (classification.blocked) {
      return buildToolResult({ ok: false, blocked: true, error: classification.reason });
    }

    const approved = await confirmCommand(context.scope, command, reason, classification);
    if (!approved) {
      return buildToolResult({ ok: false, blocked: true, error: 'User denied command execution' });
    }

    const result = context.scope === 'remote'
      ? await runRemoteCommand(context, command)
      : await runLocalCommand(command);

    recordEvent('ai_command_executed', { scope: context.scope, command, approved: true, exitCode: result.exitCode });

    return buildToolResult({ ok: result.exitCode === 0, ...result });
  }

  if (name === 'read_text_file') {
    const filePath = String(args.filePath || '').trim();
    if (!filePath) return buildToolResult({ ok: false, error: 'Missing filePath' });

    if (context.scope === 'remote') {
      const result = await readRemoteTextFile(context, filePath);
      return buildToolResult({ ok: result.exitCode === 0, content: result.stdout, stderr: result.stderr });
    }

    const content = await readLocalTextFile(filePath);
    return buildToolResult({ ok: true, content: truncateForModel(content, 12000) });
  }

  return buildToolResult({ ok: false, error: `Unknown tool: ${name}` });
}

async function runAgentTurn(apiKey, model, context, messages, task) {
  messages.push({ role: 'user', content: sanitizeUserTask(task) });
  let sessionTokens = 0;

  for (let step = 0; step < 8; step++) {
    let completion;
    try {
      completion = await createGroqChatCompletion(apiKey, {
        model,
        messages,
        tools: TOOLS,
        tool_choice: 'auto',
        temperature: 0.2,
        max_completion_tokens: 2048,
      });
    } catch (err) {
      showRateLimitWarnings(err.rateLimit);
      if (err.status === 429) {
        console.log(chalk.yellow('  ⚠️  Groq rate limit reached for this API key/model.'));
        console.log(chalk.dim('     Switch API key/model or wait for the reset window before continuing.'));
        return;
      }
      throw err;
    }
    showRateLimitWarnings(completion._rateLimit);

    const message = completion.choices?.[0]?.message;
    if (!message) throw new Error('Groq returned an empty response');

    // Estimate token usage for this turn and record it
    try {
      const est = estimateTokensForMessages(messages.map(m => m.content || ''), message.content || '');
      sessionTokens += est;
      recordEvent('ai_tokens_used', { tokens: est, cumulative: sessionTokens });
      const pricePerToken = Number(process.env.GROQ_PRICE_PER_TOKEN) || 0.00001;
      recordEvent('ai_cost_estimate', { tokens: sessionTokens, cost: +(sessionTokens * pricePerToken).toFixed(6), currency: 'USD' });
    } catch {
      // best-effort only
    }

    messages.push(message);

    if (!message.tool_calls || message.tool_calls.length === 0) {
      console.log('');
      console.log(chalk.green('  AI: ') + redactSensitive(message.content || 'Done.'));
      return;
    }

    for (const call of message.tool_calls) {
      try {
        const content = await executeToolCall(context, call);
        messages.push({ role: 'tool', tool_call_id: call.id, content });
      } catch (err) {
        messages.push({
          role: 'tool',
          tool_call_id: call.id,
          content: buildToolResult({ ok: false, error: redactSensitive(err.message) }),
        });
      }
    }
  }

  console.log(chalk.yellow('  ⚠️  AI reached the per-task tool limit. Ask it to continue if needed.'));
}

export async function startAIMode() {
  console.log('');
  console.log(chalk.bold.cyan('  🤖 AI MODE — Task Assistant'));
  console.log(chalk.dim('  ─────────────────────────────────────'));
  console.log(chalk.dim('  Privacy: API keys, private keys, session passwords, tunnel URLs, ~/.ssh, ~/.ipingyou, and .env files are blocked/redacted.'));
  console.log(chalk.dim('  Note: your task text and sanitized tool results are sent to Groq for inference.'));
  console.log('');

  const { consent } = await inquirer.prompt([{
    type: 'confirm',
    name: 'consent',
    message: 'Continue with Groq AI mode under these privacy rules?',
    default: true,
  }]);
  if (!consent) return;

  let apiKey = getGroqApiKey();
  if (!apiKey) {
    const { enteredKey } = await inquirer.prompt([{
      type: 'password',
      name: 'enteredKey',
      message: 'Groq API key (stored only in memory for this session):',
      mask: '*',
      validate: v => v.trim().length > 0 || 'Required',
    }]);
    apiKey = enteredKey.trim();
  }

  const model = await chooseModel(apiKey);

  const { scope } = await inquirer.prompt([{
    type: 'list',
    name: 'scope',
    message: 'Where should AI mode work?',
    choices: [
      { name: 'Local machine', value: 'local' },
      { name: 'Remote machine through iPingYou SSH session', value: 'remote' },
    ],
  }]);

  const context = scope === 'remote'
    ? await setupRemoteContext()
    : { scope: 'local' };

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    {
      role: 'system',
      content: `Session scope: ${context.scope}. Current working directory: ${process.cwd()}. Remote details and secrets are intentionally hidden from you.`,
    },
  ];

  console.log('');
  console.log(chalk.green(`  ✓ AI mode ready with ${model}. Type a task, or type exit to quit.`));
  console.log(chalk.dim('  Press Ctrl+C any time to terminate the session.'));

  while (true) {
    const { task } = await inquirer.prompt([{
      type: 'input',
      name: 'task',
      message: 'AI task:',
      validate: v => v.trim().length > 0 || 'Required',
    }]);

    const trimmed = task.trim();
    if (/^(exit|quit|q)$/i.test(trimmed)) break;
    // Try AI Transfer Assistant parsing first (upload/download automation)
    if (await tryAITransfer(trimmed, context)) continue;
    if (await maybeRunMatchedAppAction(trimmed)) continue;
    await runAgentTurn(apiKey, model, context, messages, trimmed);
  }

  await cleanupAll();
}

async function tryAITransfer(task, context) {
  const uploadRegex = /\b(?:upload|send|scp)\b\s+(.+?)\s+(?:to|->|into)\s+(.+)$/i;
  const downloadRegex = /\b(?:download|get|fetch|scp)\b\s+(.+?)\s+(?:to|into|->)\s+(.+)$/i;
  let m = task.match(uploadRegex);
  let direction = null;
  let src = null;
  let dst = null;
  if (m) {
    direction = 'upload'; src = m[1].trim(); dst = m[2].trim();
  } else {
    m = task.match(downloadRegex);
    if (m) { direction = 'download'; src = m[1].trim(); dst = m[2].trim(); }
  }

  if (!direction) return false;

  console.log('');
  console.log(chalk.cyan('  AI Transfer Assistant: detected a transfer intent.'));

  const localPath = direction === 'upload' ? src : dst;
  const remotePath = direction === 'upload' ? dst : src;

  // ─── Reuse existing remote context if available ─────────────
  if (context && context.scope === 'remote' && context.hostname && context.username) {
    console.log(chalk.dim(`  Using active remote session: ${context.username}@${context.hostname}`));

    const { getSshControlOptions, formatScpRemotePath } = await import('../lib/ssh.js');

    const proxyCommand = `cloudflared access tcp --hostname ${context.hostname}`;
    const scpArgs = [
      '-r',
      '-o', `ProxyCommand=${proxyCommand}`,
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'IdentitiesOnly=yes',
      ...getSshControlOptions(context.hostname),
    ];
    if (context.privateKeyPath) {
      scpArgs.push('-i', context.privateKeyPath, '-o', 'IdentityAgent=none');
    }

    const remoteSpec = `${context.username}@${context.hostname}:${formatScpRemotePath(remotePath)}`;
    if (direction === 'upload') {
      scpArgs.push(localPath, remoteSpec);
    } else {
      scpArgs.push(remoteSpec, localPath);
    }

    try {
      const result = await execa('scp', scpArgs, { stdio: 'inherit', reject: false });
      if (result.exitCode === 0) {
        console.log(chalk.green('  ✅ Transfer completed via active remote session.'));
        recordEvent('ai_transfer_success', { direction, localPath, remotePath, hostname: context.hostname, reusedContext: true });
      } else {
        console.log(chalk.red(`  ❌ Transfer failed (exit code ${result.exitCode})`));
        recordEvent('ai_transfer_failed', { direction, localPath, remotePath, hostname: context.hostname, reusedContext: true });
      }
      return true;
    } catch (err) {
      console.log(chalk.red(`  ❌ Transfer error: ${err.message}`));
      return true;
    }
  }

  // ─── Fallback: prompt for UID/password (local scope) ────────
  console.log(chalk.dim('  No active remote session — prompting for connection details.'));

  const answers = await inquirer.prompt([
    { type: 'input', name: 'uid', message: 'Target host UID:', validate: v => v.trim().length > 0 || 'Required' },
    { type: 'password', name: 'password', message: 'Session password:', mask: '*', validate: v => v.trim().length > 0 || 'Required' },
    { type: 'input', name: 'username', message: 'SSH username on host:', default: process.env.USER || process.env.USERNAME || 'root' }
  ]);

  try {
    const ok = await performSCPNonInteractive({ brokerUrl: BROKER_URL, uid: answers.uid.trim(), password: answers.password.trim(), username: answers.username.trim(), direction, localPath, remotePath });
    if (ok) console.log(chalk.green('  ✅ Automated transfer completed.'));
    else console.log(chalk.red('  ❌ Automated transfer failed.'));
    return true;
  } catch (err) {
    console.log(chalk.red(`  ❌ Transfer error: ${err.message}`));
    return true;
  }
}

