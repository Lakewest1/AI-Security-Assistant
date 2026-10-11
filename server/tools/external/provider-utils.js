/**
 * Shared read-only provider HTTP helpers.
 * Keeps retry/timeout/error handling consistent without exposing provider secrets.
 */
const RETRYABLE_HTTP = new Set([408, 425, 429, 500, 502, 503, 504]);
const MAX_PROVIDER_RESPONSE_BYTES = Number(process.env.PROVIDER_MAX_RESPONSE_BYTES) > 0
  ? Math.min(Number(process.env.PROVIDER_MAX_RESPONSE_BYTES), 10 * 1024 * 1024)
  : 2 * 1024 * 1024;
const RESPONSE_TIMEOUTS = new WeakMap();

function createResponseTimeout(controller, timeoutMs) {
  const tracked = new Set();
  let timedOut = false;
  const timeout = {
    get timedOut() { return timedOut; },
    bind(response) {
      if (!response || (typeof response !== "object" && typeof response !== "function")) return;
      tracked.add(response);
      RESPONSE_TIMEOUTS.set(response, timeout);
    },
    finish() {
      clearTimeout(timer);
      for (const response of tracked) RESPONSE_TIMEOUTS.delete(response);
      tracked.clear();
    },
  };
  const timer = setTimeout(() => {
    timedOut = true;
    try { controller.abort(); } catch { /* best effort */ }
  }, timeoutMs);
  return timeout;
}

function requestTimeoutError() {
  return Object.assign(new Error("Provider request timed out"), {
    category: "tool_timeout",
    code: "TIMEOUT",
    status: 408,
  });
}

function finishResponseTimeout(response) {
  if (response && RESPONSE_TIMEOUTS.has(response)) RESPONSE_TIMEOUTS.get(response).finish();
}

function responseTooLargeError() {
  return Object.assign(new Error("Provider response exceeded the size limit"), { category: "response_too_large" });
}

function responseBodyUnavailableError() {
  return Object.assign(new Error("Provider response body unavailable"), { category: "response_body_unavailable" });
}

function responseLimit(maxBytes) {
  return Number.isSafeInteger(maxBytes) && maxBytes > 0
    ? Math.min(maxBytes, 10 * 1024 * 1024)
    : MAX_PROVIDER_RESPONSE_BYTES;
}

async function readResponseBody(response, {
  maxBytes = MAX_PROVIDER_RESPONSE_BYTES,
  parse = "json",
} = {}) {
  const limit = responseLimit(maxBytes);
  const timeout = response && RESPONSE_TIMEOUTS.get(response);
  try {
  const declaredLength = response?.headers?.get?.("content-length");
  if (typeof declaredLength === "string" && /^\d+$/.test(declaredLength.trim()) && Number(declaredLength) > limit) {
    try { await response.body?.cancel?.(); } catch { /* best-effort cancellation */ }
    throw responseTooLargeError();
  }

  if (!response?.body || typeof response.body.getReader !== "function") {
    throw responseBodyUnavailableError();
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value?.byteLength || 0;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        throw responseTooLargeError();
      }
      chunks.push(value);
    }
  } catch (error) {
    if (timeout?.timedOut) throw requestTimeoutError();
    throw error;
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const text = new TextDecoder().decode(bytes);
  if (parse === "text") return text;
  try { return JSON.parse(text); } catch { return null; }
  } finally {
    timeout?.finish();
  }
}

function limitResponseStream(response, { maxBytes = MAX_PROVIDER_RESPONSE_BYTES, highWaterMark = 1 } = {}) {
  const timeout = response && RESPONSE_TIMEOUTS.get(response);
  if (!response?.body) {
    finishResponseTimeout(response);
    return response;
  }
  if (typeof response.body.getReader !== "function" || typeof ReadableStream !== "function" || typeof Response !== "function") {
    timeout?.finish();
    throw responseBodyUnavailableError();
  }

  const limit = responseLimit(maxBytes);
  const declaredLength = response?.headers?.get?.("content-length");
  if (typeof declaredLength === "string" && /^\d+$/.test(declaredLength.trim()) && Number(declaredLength) > limit) {
    try { response.body.cancel?.().catch?.(() => {}); } catch { /* best-effort cancellation */ }
    timeout?.finish();
    throw responseTooLargeError();
  }

  const reader = response.body.getReader();
  let total = 0;
  const boundedBody = new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          reader.releaseLock();
          timeout?.finish();
          controller.close();
          return;
        }
        total += value?.byteLength || 0;
        if (total > limit) {
          try { await reader.cancel(); } catch { /* best-effort cancellation */ }
          try { reader.releaseLock(); } catch { /* already released */ }
          timeout?.finish();
          controller.error(responseTooLargeError());
          return;
        }
        controller.enqueue(value);
      } catch (error) {
        try { reader.releaseLock(); } catch { /* already released */ }
        const safeError = timeout?.timedOut ? requestTimeoutError() : error;
        timeout?.finish();
        controller.error(safeError);
      }
    },
    async cancel(reason) {
      try {
        await reader.cancel(reason);
      } finally {
        try { reader.releaseLock(); } catch { /* already released */ }
        timeout?.finish();
      }
    },
  }, { highWaterMark });

  const boundedResponse = new Response(boundedBody, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  for (const property of ["url", "redirected", "type"]) {
    try { Object.defineProperty(boundedResponse, property, { value: response[property] }); } catch { /* optional metadata */ }
  }
  if (timeout) {
    RESPONSE_TIMEOUTS.delete(response);
    timeout.bind(boundedResponse);
  }
  return boundedResponse;
}

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
  maxResponseBytes = MAX_PROVIDER_RESPONSE_BYTES,
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

      const payload = await readResponseBody(response, { parse, maxBytes: maxResponseBytes });

      if (RETRYABLE_HTTP.has(response.status) && attempt < maxRetries) {
        const delay = retryAfterMs(response, retryBaseMs * (2 ** attempt));
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      return { response, payload, attempts: attempt + 1 };
    } catch (error) {
      if (error?.category === "response_too_large" || error?.category === "response_body_unavailable") throw error;
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
  if (status === 403) return "forbidden";
  if (status === 422) return "invalid_request";
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

function normalizeHttpUrl(value, { allowBareDomain = true } = {}) {
  if (typeof value !== "string") return null;
  let candidate = value.trim().replace(/[),.;]+$/, "");
  if (!candidate || candidate.length > 2048) return null;
  if (allowBareDomain && !/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }
  try {
    const parsed = new URL(candidate);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function normalizeDomain(value) {
  if (typeof value !== "string") return null;
  const candidate = value.trim().replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
  if (!candidate || candidate.length > 253) return null;
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(candidate)) return null;
  return candidate;
}

function compactObject(value) {
  if (!value || typeof value !== "object") return {};
  return Object.fromEntries(Object.entries(value).filter(([, v]) =>
    v !== undefined && v !== null && v !== ""
  ));
}

module.exports = {
  fetchWithRetry,
  readResponseBody,
  limitResponseStream,
  createResponseTimeout,
  finishResponseTimeout,
  MAX_PROVIDER_RESPONSE_BYTES,
  statusForHttp,
  publicResult,
  successResult,
  compactObject,
  normalizeHttpUrl,
  normalizeDomain,
};
