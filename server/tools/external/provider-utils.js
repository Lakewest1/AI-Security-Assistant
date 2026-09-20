/**
 * Shared read-only provider HTTP helpers.
 * Keeps retry/timeout/error handling consistent without exposing provider secrets.
 */
const RETRYABLE_HTTP = new Set([408, 425, 429, 500, 502, 503, 504]);

function safeMessage(message, fallback) {
  return String(message || fallback || "Provider request failed").slice(0, 500);
}

function retryAfterMs(response, fallbackMs) {
  const value = response?.headers?.get?.("retry-after");
  if (!value) return fallbackMs;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.min(Math.max(seconds * 1000, 0), fallbackMs * 4);
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.min(Math.max(date - Date.now(), 0), fallbackMs * 4);
  return fallbackMs;
}

async function fetchWithRetry(url, {
  method = "GET",
  headers = {},
  body,
  timeoutMs = 8000,
  maxRetries = 1,
  retryBaseMs = 250,
  parse = "json",
} = {}) {
  let lastError = null;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
      });

      let payload = null;
      if (parse === "text") {
        try { payload = await response.text(); } catch { payload = null; }
      } else {
        try { payload = await response.json(); } catch { payload = null; }
      }

      if (RETRYABLE_HTTP.has(response.status) && attempt < maxRetries) {
        const delay = retryAfterMs(response, retryBaseMs * (2 ** attempt));
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      return { response, payload, attempts: attempt + 1 };
    } catch (error) {
      lastError = error;
      if (error?.name === "AbortError") {
        const timeout = new Error(`Provider request timed out after ${timeoutMs}ms`);
        timeout.category = "tool_timeout";
        throw timeout;
      }
      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, retryBaseMs * (2 ** attempt)));
        continue;
      }
      const network = new Error("Provider network request failed");
      network.category = "network_error";
      throw network;
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastError || Object.assign(new Error("Provider request failed"), { category: "network_error" });
}

function statusForHttp(status) {
  if (status === 401) return "unauthorized";
  if (status === 403) return "unauthorized";
  if (status === 404) return "not_found";
  if (status === 408 || status === 504) return "timeout";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "unavailable";
  return "error";
}

function publicResult(provider, status, message, findings = {}) {
  return {
    ok: true,
    success: true,
    provider,
    status,
    collectedAt: new Date().toISOString(),
    message: safeMessage(message, status),
    findings: findings && typeof findings === "object" ? findings : {},
    evidence: Object.entries(findings || {}).map(([field, value]) => ({
      field, value, source: provider,
    })),
  };
}

function successResult(provider, findings) {
  return {
    ok: true,
    success: true,
    provider,
    status: "success",
    collectedAt: new Date().toISOString(),
    findings: findings || {},
    evidence: Object.entries(findings || {}).map(([field, value]) => ({
      field, value, source: provider,
    })),
  };
}

function compactObject(value) {
  if (!value || typeof value !== "object") return {};
  return Object.fromEntries(Object.entries(value).filter(([, v]) =>
    v !== undefined && v !== null && v !== ""
  ));
}

module.exports = {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  successResult,
  compactObject,
};
