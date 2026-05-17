import { ensureAllowlistFile, getAllowlistRegexes } from '../src/lib/allowlist.js';
import { estimateTokensForMessages } from '../src/lib/ai/groq.js';

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

    console.log('\nAll AI helper checks passed');
}

run().catch(err => { console.error(err); process.exit(1); });
