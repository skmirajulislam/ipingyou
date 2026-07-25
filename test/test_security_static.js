import fs from 'node:fs';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const hostSource = fs.readFileSync(new URL('../src/modes/host.js', import.meta.url), 'utf8');
const chatSource = fs.readFileSync(new URL('../src/lib/services/chat.js', import.meta.url), 'utf8');
const cliSource = fs.readFileSync(new URL('../src/cli.js', import.meta.url), 'utf8');
const platformSource = fs.readFileSync(new URL('../src/lib/services/platform.js', import.meta.url), 'utf8');
const cleanupSource = fs.readFileSync(new URL('../src/lib/mod/cleanup.js', import.meta.url), 'utf8');
const sshSource = fs.readFileSync(new URL('../src/lib/services/ssh.js', import.meta.url), 'utf8');
const clientSource = fs.readFileSync(new URL('../src/modes/client.js', import.meta.url), 'utf8');
const serverSource = fs.readFileSync(new URL('../src/server.js', import.meta.url), 'utf8');
const webUiSource = fs.readFileSync(new URL('../src/lib/services/webui.js', import.meta.url), 'utf8');
const cryptoSource = fs.readFileSync(new URL('../src/lib/mod/crypto.js', import.meta.url), 'utf8');
const packageJson = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
);

assert(!hostSource.includes('.innerHTML'), 'Host dashboard must not render broker values through innerHTML');
assert(!chatSource.includes('.innerHTML'), 'Chat UI must not render values through innerHTML');
assert(!hostSource.includes("execa('pkill'"), 'Host controls must not kill unrelated SSH processes');
assert(
  hostSource.includes('Content-Security-Policy') && hostSource.includes('escapeDashboardHtml'),
  'Host dashboard CSP or server-side escaping is missing'
);
assert(
  !hostSource.includes("['install', '--no-save'"),
  'Private broker must not install dependencies at runtime'
);
assert(
  !/execa\(['"]npm['"],\s*\[['"]install['"]/.test(cliSource),
  'In-app npm installs must not bypass Socket Firewall'
);
assert(
  cliSource.includes('runProtectedNpmInstall'),
  'Service package installation must use Socket Firewall'
);
assert(
  hostSource.includes('no-agent-forwarding,no-X11-forwarding'),
  'Ephemeral authorized key restrictions are missing'
);
assert(
  hostSource.includes('serviceConfig.sshUsername'),
  'Host must publish the SSH username that received the ephemeral key'
);
assert(
  hostSource.includes('Ephemeral key injected for'),
  'Host must show which user received the ephemeral key'
);
assert(
  sshSource.includes('PasswordAuthentication=no') && clientSource.includes('getKeyOnlyAuthOptions'),
  'Client must force key-only authentication when an ephemeral key is present'
);
for (const forbiddenInstallerPattern of [
  'releases/latest',
  'downloadFile(',
  'tar -x',
  'Invoke-WebRequest',
  'Auto-installing',
]) {
  assert(
    !platformSource.includes(forbiddenInstallerPattern),
    `Unverified native installer behavior returned: ${forbiddenInstallerPattern}`
  );
}
const panicWipeSource = fs.readFileSync(new URL('../src/lib/mod/panic-wipe.js', import.meta.url), 'utf8');

for (const forbiddenCleanupPattern of [
  'rmSync(',
  'unlinkSync(',
  "execa('pkill'",
  'authorized_keys',
  'readdirSync(os.tmpdir',
]) {
  assert(
    !cleanupSource.includes(forbiddenCleanupPattern),
    `Unscoped destructive cleanup returned in cleanup.js: ${forbiddenCleanupPattern}`
  );
}

assert(
  panicWipeSource.includes('performPanicWipe') &&
  panicWipeSource.includes('PRESERVED_BINARIES') &&
  panicWipeSource.includes('cloudflared') &&
  panicWipeSource.includes('authorized_keys'),
  'Panic wipe module must safely sanitize authorized_keys and preserve cloudflared/ssh binaries'
);

assert(
  cliSource.includes('STOP CURRENT SESSION'),
  'Emergency cleanup must require local typed confirmation'
);
assert(
  serverSource.includes('function getClientIp(req)') && !serverSource.includes("req.headers['x-forwarded-for']"),
  'Broker must not trust caller-controlled X-Forwarded-For headers'
);
assert(
  serverSource.includes('UID is already registered by another host') && serverSource.includes('tokensMatch(existingEntry.hostToken, providedHostToken)'),
  'Broker must authenticate session re-registration'
);
assert(
  chatSource.includes("data.type === 'host_close' && ws.isHost") && chatSource.includes('hostControlToken'),
  'Chat close control must require a host capability'
);
assert(
  webUiSource.includes('accessToken') && webUiSource.includes('timingSafeEqual'),
  'Mobile UI must require an access capability'
);
assert(
  cryptoSource.includes("aes-256-gcm") && cryptoSource.includes('getAuthTag'),
  'Session encryption must provide authenticated encryption'
);

for (const removedDependency of ['shell-quote', 'tree-kill', 'nanoid', 'open']) {
  assert(
    !packageJson.dependencies?.[removedDependency],
    `Removed dependency returned: ${removedDependency}`
  );
}

console.log('Security regression checks passed');
