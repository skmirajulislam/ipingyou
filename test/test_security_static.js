import fs from 'node:fs';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const hostSource = fs.readFileSync(new URL('../src/modes/host.js', import.meta.url), 'utf8');
const chatSource = fs.readFileSync(new URL('../src/lib/chat.js', import.meta.url), 'utf8');
const cliSource = fs.readFileSync(new URL('../src/cli.js', import.meta.url), 'utf8');
const platformSource = fs.readFileSync(new URL('../src/lib/platform.js', import.meta.url), 'utf8');
const cleanupSource = fs.readFileSync(new URL('../src/lib/cleanup.js', import.meta.url), 'utf8');
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
for (const forbiddenCleanupPattern of [
  'rmSync(',
  'unlinkSync(',
  "execa('pkill'",
  'authorized_keys',
  'readdirSync(os.tmpdir',
]) {
  assert(
    !cleanupSource.includes(forbiddenCleanupPattern),
    `Unscoped destructive cleanup returned: ${forbiddenCleanupPattern}`
  );
}
assert(
  cliSource.includes('STOP CURRENT SESSION'),
  'Emergency cleanup must require local typed confirmation'
);

for (const removedDependency of ['shell-quote', 'tree-kill', 'nanoid', 'open']) {
  assert(
    !packageJson.dependencies?.[removedDependency],
    `Removed dependency returned: ${removedDependency}`
  );
}

console.log('Security regression checks passed');
