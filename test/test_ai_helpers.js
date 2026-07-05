import { ensureAllowlistFile, getAllowlistRegexes } from '../src/lib/mod/allowlist.js';
import { estimateTokensForMessages } from '../src/lib/ai/groq.js';
import { assertSafeReadablePath, classifyCommand } from '../src/lib/ai/safety.js';
import { parseLocalCommand } from '../src/modes/ai.js';
import { formatScpRemotePath } from '../src/lib/services/ssh.js';

async function run() {
    console.log('\nAI Helpers Test');
    console.log('----------------');

    // Ensure allowlist file is created
    const p = ensureAllowlistFile();
    console.log('  allowlist path:', p);

    const patterns = getAllowlistRegexes();
    if (!Array.isArray(patterns)) {
        console.error('  ❌ getAllowlistRegexes did not return an array');
        process.exit(1);
    }
    console.log('  ✅ allowlist loaded, patterns:', patterns.length);

    // Token estimator
    const messages = [{ content: 'Hello world' }, { content: 'Run a command' }];
    const est = estimateTokensForMessages(messages.map(m => m.content), 'OK');
    console.log('  ✅ estimated tokens:', est);

    const safePath = assertSafeReadablePath('./README.md');
    if (safePath !== './README.md') throw new Error('Safe path changed unexpectedly');
    for (const blockedPath of [
        '~/.ssh/id_ed25519',
        '/tmp/link/.env.production',
        '/home/user/.aws/credentials',
        '/proc/self/environ',
        'file\n--dangerous',
    ]) {
        let blocked = false;
        try { assertSafeReadablePath(blockedPath); } catch { blocked = true; }
        if (!blocked) throw new Error(`Protected path was allowed: ${blockedPath}`);
    }
    if (!classifyCommand('cat README.md; echo changed').needsApproval) {
        throw new Error('Shell syntax did not require approval');
    }
    if (!classifyCommand('printenv').blocked || !classifyCommand('cat ~/.ssh/id_rsa').blocked) {
        throw new Error('Non-bypassable command guards failed');
    }
    const parsed = parseLocalCommand('rg \"safe pattern\" README.md');
    if (parsed.join('|') !== 'rg|safe pattern|README.md') {
        throw new Error('Quoted local command parsing changed');
    }
    for (const unsafeCommand of ['cat README.md; id', 'echo $(id)', 'cat README.md\nid']) {
        let blocked = false;
        try { parseLocalCommand(unsafeCommand); } catch { blocked = true; }
        if (!blocked) throw new Error(`Shell operator was allowed locally: ${unsafeCommand}`);
    }
    const quotedRemotePath = formatScpRemotePath("/tmp/report'; touch /tmp/pwned; '");
    if (!quotedRemotePath.includes("'\\''") || !quotedRemotePath.startsWith("'")) {
        throw new Error('SCP remote path was not shell-quoted');
    }
    console.log('  ✅ AI path and shell-syntax guards');

    console.log('\nAll AI helper checks passed');
}

run().catch(err => { console.error(err); process.exit(1); });
