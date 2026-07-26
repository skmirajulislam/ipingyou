import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ALLOWLIST_PATH = path.join(os.homedir(), '.ipingyou', 'allowlist.json');

export function getAllowlistRegexes() {
    try {
        if (!fs.existsSync(ALLOWLIST_PATH)) return [];
        const raw = fs.readFileSync(ALLOWLIST_PATH, 'utf8');
        const data = JSON.parse(raw || '[]');
        if (!Array.isArray(data)) return [];
        return data.map(s => {
            if (typeof s !== 'string' || s.length > 200) return null;
            try { return new RegExp(s); } catch { return null; }
        }).filter(Boolean);
    } catch {
        return [];
    }
}

export function ensureAllowlistFile() {
    try {
        if (!fs.existsSync(path.dirname(ALLOWLIST_PATH))) {
            fs.mkdirSync(path.dirname(ALLOWLIST_PATH), { recursive: true, mode: 0o700 });
        }
        if (!fs.existsSync(ALLOWLIST_PATH)) {
            fs.writeFileSync(ALLOWLIST_PATH, JSON.stringify([
                '^\\s*(pwd|ls|find|rg|grep|sed|cat|head|tail|wc|git status|git diff|git log|git show|node --version|npm --version|which|date|uname)\\b'
            ], null, 2), { mode: 0o600 });
        }
        return ALLOWLIST_PATH;
    } catch {
        return ALLOWLIST_PATH;
    }
}
