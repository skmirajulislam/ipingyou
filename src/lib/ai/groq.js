const GROQ_API_BASE = 'https://api.groq.com/openai/v1';

export const DEFAULT_AI_MODEL = 'qwen/qwen3-32b';

export function getGroqApiKey() {
  return process.env.GROQ_API_KEY || null;
}

export async function listGroqModels(apiKey) {
  const res = await fetch(`${GROQ_API_BASE}/models`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
  });

  if (!res.ok) {
    const message = await res.text().catch(() => '');
    throw new Error(`Groq model lookup failed: HTTP ${res.status} ${message}`.trim());
  }

  const data = await res.json();
  return Array.isArray(data.data) ? data.data : [];
}

export async function createGroqChatCompletion(apiKey, body) {
  const res = await fetch(`${GROQ_API_BASE}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const message = await res.text().catch(() => '');
    const err = new Error(`Groq chat completion failed: HTTP ${res.status} ${message}`.trim());
    err.status = res.status;
    err.rateLimit = parseGroqRateLimitHeaders(res.headers);
    throw err;
  }

  const data = await res.json();
  data._rateLimit = parseGroqRateLimitHeaders(res.headers);
  return data;
}

export function parseGroqRateLimitHeaders(headers) {
  const readNumber = (name) => {
    const value = headers.get(name);
    if (!value) return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };

  return {
    limitRequests: readNumber('x-ratelimit-limit-requests'),
    remainingRequests: readNumber('x-ratelimit-remaining-requests'),
    resetRequests: headers.get('x-ratelimit-reset-requests') || null,
    limitTokens: readNumber('x-ratelimit-limit-tokens'),
    remainingTokens: readNumber('x-ratelimit-remaining-tokens'),
    resetTokens: headers.get('x-ratelimit-reset-tokens') || null,
    retryAfter: headers.get('retry-after') || null,
  };
}

// Lightweight token estimator: approximate tokens by characters/4
export function estimateTokensForMessages(messages = [], completionText = '') {
  try {
    let chars = 0;
    for (const m of messages || []) {
      if (!m) continue;
      chars += String(m).length;
    }
    chars += String(completionText || '').length;
    return Math.max(0, Math.ceil(chars / 4));
  } catch {
    return 0;
  }
}

export function getRateLimitWarnings(rateLimit, threshold = 0.8) {
  if (!rateLimit) return [];

  const warnings = [];
  const checks = [
    {
      label: 'daily request',
      limit: rateLimit.limitRequests,
      remaining: rateLimit.remainingRequests,
      reset: rateLimit.resetRequests,
    },
    {
      label: 'per-minute token',
      limit: rateLimit.limitTokens,
      remaining: rateLimit.remainingTokens,
      reset: rateLimit.resetTokens,
    },
  ];

  for (const item of checks) {
    if (!item.limit || item.remaining === null || item.remaining === undefined) continue;
    const used = Math.max(0, item.limit - item.remaining);
    const ratio = used / item.limit;
    if (ratio >= threshold) {
      warnings.push({
        ...item,
        used,
        percent: Math.round(ratio * 100),
      });
    }
  }

  return warnings;
}
