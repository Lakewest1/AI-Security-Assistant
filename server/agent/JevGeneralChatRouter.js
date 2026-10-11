"use strict";

const { limitResponseStream } = require("../tools/external/provider-utils");

const ALLOWED_ROUTES = new Set(["fast", "balanced", "powerful"]);
const ALLOWED_INTENTS = new Set(["code", "explanation", "troubleshooting", "architecture"]);
const MAX_MESSAGES = 12;
const MAX_MESSAGE_CHARS = 12_000;
const RESPONSE_TIMEOUT_MS = 2_500;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MIN_CONFIDENCE = 0.55;

// Ambiguous or security-adjacent inputs stay on the existing local router.
const PRIVATE_OR_SECURITY_PATTERNS = [
  /\b(?:security|cybersecurity|threat|incident|vulnerab(?:ility|le)|malware|ransomware|phishing|exploit|forensic|investigat(?:e|ion)|indicator of compromise|ioc|siem|detection|monitoring|reputation|virus.?total|abuseipdb|censys|urlscan|breach|malicious|suspicious|network|vpc|subnet|firewall|port scan|authentication|authorization|host)\b/i,
  /\b(?:password|passwd|secret|credential|api[_ -]?key|access[_ -]?token|auth(?:orization)?|bearer|private key|client[_ -]?secret)\b/i,
  /\b(?:log|logs|logfile|stack trace|audit trail|provider response|security report|scan result|finding|evidence|hash|md5|sha-?1|sha-?256|sha-?512)\b/i,
  /https?:\/\/|\bwww\./i,
  /\bhxxps?:|(?:\[\.\]|\(\.\))/i,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i,
  /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b/i,
  /\b[a-f0-9]{32}(?:[a-f0-9]{8}|[a-f0-9]{24}|[a-f0-9]{32})?\b/i,
  /\bCVE-\d{4}-\d{4,}\b/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*\S+/i,
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/i,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
];

function serverSupportsSdk(runtimeVersion = process.versions.node) {
  const major = Number(String(runtimeVersion).split(".")[0]);
  return Number.isInteger(major) && major >= 20;
}

function featureFlagEnabled(env = process.env) {
  return env.JEV_GENERAL_CHAT_ROUTING === "true" && env.JEV_ROUTING_RUNTIME_APPROVED === "true";
}

function deriveSafeRoutingState(messages, intents, currentUserText) {
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > MAX_MESSAGES) return null;
  if (typeof currentUserText !== "string" || currentUserText.length === 0 || currentUserText.length > MAX_MESSAGE_CHARS) return null;
  if (!Array.isArray(intents) || intents.some((intent) => !ALLOWED_INTENTS.has(intent))) return null;

  for (const message of messages) {
    if (!message || !["user", "assistant"].includes(message.role) || typeof message.content !== "string") return null;
    if (message.content.length > MAX_MESSAGE_CHARS) return null;
    if (PRIVATE_OR_SECURITY_PATTERNS.some((pattern) => pattern.test(message.content))) return null;
  }

  // Only this fixed, server-derived feature vector is sent. Message text and history are never sent.
  const size = currentUserText.length < 150 ? "short" : currentUserText.length < 1500 ? "medium" : "long";
  return Object.freeze({
    taskKinds: Object.freeze(intents.length ? [...new Set(intents)] : ["general"]),
    size,
  });
}

function createBoundedFetch(fetchImpl = globalThis.fetch, maxBytes = MAX_RESPONSE_BYTES) {
  if (typeof fetchImpl !== "function") throw new TypeError("A fetch implementation is required");
  return async (input, init) => {
    const response = await fetchImpl(input, { ...init, redirect: "error" });
    return limitResponseStream(response, { maxBytes, highWaterMark: 0 });
  };
}

function createClient({ apiKey, fetchImpl = globalThis.fetch, timeoutMs = RESPONSE_TIMEOUT_MS, maxResponseBytes = MAX_RESPONSE_BYTES } = {}) {
  if (!serverSupportsSdk() || typeof apiKey !== "string" || apiKey.trim() === "") return null;
  try {
    // Lazy loading keeps the feature unavailable without parsing the SDK on Node 18.
    const { TypeSafeClient } = require("@typesafe-ai/sdk");
    return new TypeSafeClient({
      apiKey,
      baseURL: "https://api.typesafe.ai",
      timeout: timeoutMs,
      retry: {
        maxRetries: 0,
        apiConnectionError: false,
        apiTimeoutError: false,
      },
      logLevel: "off",
      fetch: createBoundedFetch(fetchImpl, maxResponseBytes),
    });
  } catch {
    return null;
  }
}

let sharedClient;
let clientResolved = false;

function getClient() {
  if (!clientResolved) {
    clientResolved = true;
    sharedClient = createClient({ apiKey: process.env.JEV_API_KEY || process.env.TYPESAFE_API_KEY });
  }
  return sharedClient;
}

function isAllowedRecommendation(result) {
  const answer = result?.answers?.route;
  return answer?.type === "choice"
    && ALLOWED_ROUTES.has(answer.choice)
    && Number.isFinite(answer.confidence)
    && answer.confidence >= MIN_CONFIDENCE
    && answer.confidence <= 1
    ? answer.choice
    : null;
}

async function recommendRoute({ messages, intents, currentUserText, deterministicRoute, client, timeoutMs = RESPONSE_TIMEOUT_MS } = {}) {
  const fallbackRoute = ALLOWED_ROUTES.has(deterministicRoute) ? deterministicRoute : "balanced";
  if (!featureFlagEnabled() || !serverSupportsSdk()) return { route: fallbackRoute, usedJev: false };

  const state = deriveSafeRoutingState(messages, intents, currentUserText);
  if (!state) return { route: fallbackRoute, usedJev: false };

  const activeClient = client || getClient();
  if (!activeClient || typeof activeClient.systemOne !== "function") return { route: fallbackRoute, usedJev: false };

  try {
    const result = await activeClient.systemOne({
      state,
      questions: {
        route: {
          type: "choice",
          instructions: "Choose the existing general-chat provider route that best fits these coarse task features. Do not infer a security investigation route.",
          criteria: {
            fast: "Short, straightforward general conversation.",
            balanced: "Typical general chat, explanation, troubleshooting, or coding request.",
            powerful: "Long or complex general-chat request.",
          },
        },
      },
    }, {
      timeout: Number.isFinite(timeoutMs) && timeoutMs > 0 ? Math.min(timeoutMs, RESPONSE_TIMEOUT_MS) : RESPONSE_TIMEOUT_MS,
      retry: { maxRetries: 0, apiConnectionError: false, apiTimeoutError: false },
    });
    const route = isAllowedRecommendation(result);
    return route ? { route, usedJev: true } : { route: fallbackRoute, usedJev: false };
  } catch {
    // Never surface SDK/provider errors or their response details through this routing path.
    return { route: fallbackRoute, usedJev: false };
  }
}

module.exports = {
  ALLOWED_ROUTES,
  MAX_RESPONSE_BYTES,
  RESPONSE_TIMEOUT_MS,
  createBoundedFetch,
  createClient,
  deriveSafeRoutingState,
  featureFlagEnabled,
  isAllowedRecommendation,
  recommendRoute,
  serverSupportsSdk,
};
