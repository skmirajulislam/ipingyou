/**
 * ============================================================
 *  Command Guardrails & Destructive Action Interceptor
 * ============================================================
 *  Intercepts and blocks dangerous commands (e.g. rm -rf, sudo, dd)
 *  to protect the host machine from accidental or malicious actions.
 * ============================================================
 */

import chalk from 'chalk';

export const DEFAULT_DENY_PATTERNS = [
  /\brm\s+-[rRfF]+\s+[\/*]/i,
  /\bsudo\s+rm\b/i,
  /\bdd\s+if=/i,
  /\bmkfs\b/i,
  /\bchmod\s+-R\s+777\s+[\/*]/i,
  />\s*\/dev\/sd[a-z]/i,
  /\bshutdown\b/i,
  /\breboot\b/i
];

export class CommandGuardrails {
  constructor(denyRulesString = '') {
    this.denyRules = [...DEFAULT_DENY_PATTERNS];

    if (denyRulesString) {
      const customPatterns = denyRulesString.split(',').map(s => s.trim()).filter(Boolean);
      for (const pattern of customPatterns) {
        try {
          if (pattern.length > 200) continue;
          this.denyRules.push(new RegExp(pattern, 'i'));
        } catch {
          // Ignore invalid regex
        }
      }
    }
  }

  /**
   * Evaluates if a command string contains dangerous or denied patterns.
   * @param {string} command 
   * @returns {{ allowed: boolean, matchedPattern: string|null }}
   */
  checkCommand(command) {
    if (!command) return { allowed: true, matchedPattern: null };

    for (const rule of this.denyRules) {
      if (rule.test(command)) {
        return { allowed: false, matchedPattern: rule.toString() };
      }
    }

    return { allowed: true, matchedPattern: null };
  }
}
