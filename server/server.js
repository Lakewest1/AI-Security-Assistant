require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const OpenAIProvider = require("./providers/openai");
const AnthropicProvider = require("./providers/anthropic");
const GeminiProvider = require("./providers/gemini");
const DeepSeekProvider = require("./providers/deepseek");
const GroqProvider = require("./providers/groq");
const OpenRouterProvider = require("./providers/openrouter");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT) || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

const FAST_MAX_TOKENS = Number(process.env.FAST_MAX_TOKENS) || 1024;
const BALANCED_MAX_TOKENS = Number(process.env.BALANCED_MAX_TOKENS) || 2048;
const POWERFUL_MAX_TOKENS = Number(process.env.POWERFUL_MAX_TOKENS) || 4096;

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 60;

const MAX_HISTORY_MESSAGES = Number(process.env.MAX_HISTORY_MESSAGES) || 20;
const MAX_CONTEXT_CHARACTERS = Number(process.env.MAX_CONTEXT_CHARACTERS) || 30000;

const PROVIDER_TIMEOUT_MS = Number(process.env.PROVIDER_TIMEOUT_MS) || 20000;
const TOTAL_AI_REQUEST_TIMEOUT_MS = Number(process.env.TOTAL_AI_REQUEST_TIMEOUT_MS) || 45000;
const PROVIDER_COOLDOWN_MS = Number(process.env.PROVIDER_COOLDOWN_MS) || 30000;
const PROVIDER_FAILURE_THRESHOLD = Number(process.env.PROVIDER_FAILURE_THRESHOLD) || 3;

/* Cooldowns by category */
const COOLDOWN_BILLING_MS = Number(process.env.COOLDOWN_BILLING_MS) || 30 * 60 * 1000; // 30 min
const COOLDOWN_AUTH_MS = Number(process.env.COOLDOWN_AUTH_MS) || 30 * 60 * 1000; // 30 min
const COOLDOWN_MODEL_MS = Number(process.env.COOLDOWN_MODEL_MS) || 15 * 60 * 1000; // 15 min
const COOLDOWN_RATE_LIMIT_MS = Number(process.env.COOLDOWN_RATE_LIMIT_MS) || 60 * 1000; // 1 min
const COOLDOWN_SERVER_MS = Number(process.env.COOLDOWN_SERVER_MS) || 60 * 1000; // 1 min
const COOLDOWN_NETWORK_MS = Number(process.env.COOLDOWN_NETWORK_MS) || 30 * 1000; // 30 sec

const TRUST_PROXY = Number(process.env.TRUST_PROXY) || 1;

/* =========================================================
   PROVIDER INITIALIZATION
========================================================= */

function createProviderInstance(ProviderClass, config) {
  if (!config.apiKey) return null;
  return new ProviderClass(config);
}

const providers = {
  groq: createProviderInstance(GroqProvider, {
    name: "Groq",
    apiKey: process.env.GROQ_API_KEY,
    url: "https://api.groq.com/openai/v1/chat/completions",
    models: {
      fast: process.env.GROQ_FAST_MODEL || "llama-3.3-70b-versatile",
      balanced: process.env.GROQ_BALANCED_MODEL || "llama-3.3-70b-versatile",
      powerful: process.env.GROQ_POWERFUL_MODEL || "llama-3.3-70b-versatile",
    },
    routePriority: { fast: 1, balanced: 5, powerful: 5 },
  }),

  deepseek: createProviderInstance(DeepSeekProvider, {
    name: "DeepSeek",
    apiKey: process.env.DEEPSEEK_API_KEY,
    url: "https://api.deepseek.com/v1/chat/completions",
    models: {
      fast: process.env.DEEPSEEK_FAST_MODEL || "deepseek-chat",
      balanced: process.env.DEEPSEEK_BALANCED_MODEL || "deepseek-chat",
      powerful: process.env.DEEPSEEK_POWERFUL_MODEL || "deepseek-chat",
    },
    routePriority: { fast: 2, balanced: 1, powerful: 4 },
  }),

  gemini: createProviderInstance(GeminiProvider, {
    name: "Gemini",
    apiKey: process.env.GEMINI_API_KEY,
    url: "https://generativelanguage.googleapis.com/v1beta/models",
    models: {
      fast: process.env.GEMINI_FAST_MODEL || "gemini-2.0-flash",
      balanced: process.env.GEMINI_BALANCED_MODEL || "gemini-2.0-flash",
      powerful: process.env.GEMINI_POWERFUL_MODEL || "gemini-2.0-flash",
    },
    routePriority: { fast: 3, balanced: 3, powerful: 3 },
  }),

  openai: createProviderInstance(OpenAIProvider, {
    name: "OpenAI",
    apiKey: process.env.OPENAI_API_KEY,
    url: "https://api.openai.com/v1/chat/completions",
    models: {
      fast: process.env.OPENAI_FAST_MODEL || "gpt-4o-mini",
      balanced: process.env.OPENAI_BALANCED_MODEL || "gpt-4o",
      powerful: process.env.OPENAI_POWERFUL_MODEL || "gpt-4o",
    },
    routePriority: { fast: 4, balanced: 4, powerful: 1 },
  }),

  claude: createProviderInstance(AnthropicProvider, {
    name: "Claude",
    apiKey: process.env.ANTHROPIC_API_KEY,
    url: "https://api.anthropic.com/v1/messages",
    models: {
      fast: process.env.ANTHROPIC_FAST_MODEL || "claude-3-5-haiku-latest",
      balanced: process.env.ANTHROPIC_BALANCED_MODEL || "claude-3-5-sonnet-latest",
      powerful: process.env.ANTHROPIC_POWERFUL_MODEL || "claude-3-5-sonnet-latest",
    },
    routePriority: { fast: 5, balanced: 2, powerful: 2 },
  }),

  openrouter: createProviderInstance(OpenRouterProvider, {
    name: "OpenRouter",
    apiKey: process.env.OPENROUTER_API_KEY,
    url: "https://openrouter.ai/api/v1/chat/completions",
    models: {
      fast: process.env.OPENROUTER_FAST_MODEL || "meta-llama/llama-3.3-70b-instruct",
      balanced: process.env.OPENROUTER_BALANCED_MODEL || "meta-llama/llama-3.3-70b-instruct",
      powerful: process.env.OPENROUTER_POWERFUL_MODEL || "meta-llama/llama-3.3-70b-instruct",
    },
    routePriority: { fast: 6, balanced: 6, powerful: 6 },
    isFallbackOnly: true,
  }),
};

const activeProviders = Object.values(providers).filter(p => p !== null);
const primaryProviders = activeProviders.filter(p => !p.isFallbackOnly);
const fallbackProviders = activeProviders.filter(p => p.isFallbackOnly);

if (primaryProviders.length === 0 && fallbackProviders.length === 0) {
  console.error("❌ No AI providers configured");
  process.exit(1);
}

console.log(`✅ Primary: ${primaryProviders.map(p => p.name).join(", ") || "None"}`);
console.log(`✅ Fallback: ${fallbackProviders.map(p => p.name).join(", ") || "None"}`);

/* =========================================================
   CIRCUIT BREAKER (Per Provider + Model)
========================================================= */

const CircuitState = { CLOSED: "CLOSED", OPEN: "OPEN", HALF_OPEN: "HALF_OPEN" };

const circuitBreakers = new Map();

function getCircuitKey(providerName, model) {
  return `${providerName}:${model || "default"}`;
}

function getCircuit(key) {
  if (!circuitBreakers.has(key)) {
    circuitBreakers.set(key, {
      state: CircuitState.CLOSED,
      failures: 0,
      lastFailure: 0,
      cooldownUntil: 0,
      halfOpenTesting: false,
      category: null,
    });
  }
  return circuitBreakers.get(key);
}

function getCooldownForCategory(category) {
  switch (category) {
    case "billing": return COOLDOWN_BILLING_MS;
    case "auth": return COOLDOWN_AUTH_MS;
    case "model_unavailable": return COOLDOWN_MODEL_MS;
    case "rate_limit": return COOLDOWN_RATE_LIMIT_MS;
    case "server_error": return COOLDOWN_SERVER_MS;
    case "network": return COOLDOWN_NETWORK_MS;
    default: return PROVIDER_COOLDOWN_MS;
  }
}

function isProviderAvailable(provider, model) {
  const key = getCircuitKey(provider.name, model);
  const circuit = getCircuit(key);
  const now = Date.now();

  if (circuit.state === CircuitState.OPEN) {
    if (now >= circuit.cooldownUntil) {
      // Move to HALF_OPEN for controlled test
      if (!circuit.halfOpenTesting) {
        circuit.state = CircuitState.HALF_OPEN;
        circuit.halfOpenTesting = true;
        return true;
      }
      // Another test already in progress — reject to prevent hammering
      return false;
    }
    return false;
  }

  if (circuit.state === CircuitState.HALF_OPEN) {
    if (circuit.halfOpenTesting) return false;
    circuit.halfOpenTesting = true;
    return true;
  }

  return true;
}

function markProviderFailure(provider, model, category) {
  const key = getCircuitKey(provider.name, model);
  const circuit = getCircuit(key);
  const now = Date.now();

  circuit.failures += 1;
  circuit.lastFailure = now;
  circuit.category = category || "unknown";
  circuit.halfOpenTesting = false;

  // Billing, auth, model errors: open immediately with long cooldown
  if (
    category === "billing" ||
    category === "auth" ||
    category === "model_unavailable"
  ) {
    circuit.state = CircuitState.OPEN;
    circuit.cooldownUntil = now + getCooldownForCategory(category);
    return;
  }

  // Rate limit: open immediately with short cooldown
  if (category === "rate_limit") {
    circuit.state = CircuitState.OPEN;
    circuit.cooldownUntil = now + getCooldownForCategory(category);
    return;
  }

  // Transient errors: open after threshold
  if (circuit.failures >= PROVIDER_FAILURE_THRESHOLD) {
    circuit.state = CircuitState.OPEN;
    circuit.cooldownUntil = now + getCooldownForCategory(category);
  }
}

function markProviderSuccess(provider, model) {
  const key = getCircuitKey(provider.name, model);
  circuitBreakers.set(key, {
    state: CircuitState.CLOSED,
    failures: 0,
    lastFailure: 0,
    cooldownUntil: 0,
    halfOpenTesting: false,
    category: null,
  });
}

function getProviderHealthStatus() {
  const status = {};
  for (const provider of activeProviders) {
    const sampleModel = provider.models.balanced;
    const key = getCircuitKey(provider.name, sampleModel);
    const circuit = getCircuit(key);
    status[provider.name] = circuit.state.toLowerCase();
  }
  return status;
}

/* =========================================================
   ERROR CLASSIFICATION
========================================================= */

/**
 * Classifies a provider error and decides if fallback should occur.
 * NEVER returns fallback:false for provider-side availability issues.
 */
function classifyProviderError(error) {
  if (!error) {
    return {
      fallback: true,
      category: "unknown",
      retryProvider: false,
      message: "Unknown provider error",
    };
  }

  const status = error.status || error.statusCode || 0;
  const rawMessage = (error.message || "").toLowerCase();
  const originalMessage = error.originalError?.message || "";
  const combined = `${rawMessage} ${originalMessage}`.toLowerCase();

  /* ---------------- BILLING / CREDITS ---------------- */
  const billingPatterns = [
    "insufficient balance",
    "insufficient_balance",
    "insufficient quota",
    "insufficient_quota",
    "insufficient funds",
    "insufficient credit",
    "no credits",
    "credit balance is too low",
    "credit balance too low",
    "billing",
    "payment required",
    "quota exceeded",
    "quota exhausted",
    "exceeded your current quota",
    "account is not active",
    "account suspended",
    "please add credits",
    "please add funds",
  ];
  if (billingPatterns.some(p => combined.includes(p))) {
    return {
      fallback: true,
      category: "billing",
      retryProvider: false,
      message: "Provider has no available balance or credits",
    };
  }

  /* ---------------- MODEL UNAVAILABLE ---------------- */
  const modelPatterns = [
    "model not found",
    "model_not_found",
    "does not exist",
    "not supported",
    "unsupported model",
    "is not found for api version",
    "model is unavailable",
    "model has been retired",
    "model retired",
    "no longer available",
    "invalid model",
    "unknown model",
  ];
  if (modelPatterns.some(p => combined.includes(p))) {
    return {
      fallback: true,
      category: "model_unavailable",
      retryProvider: false,
      message: "Provider model is not available",
    };
  }

  /* ---------------- RATE LIMIT ---------------- */
  if (status === 429 || combined.includes("rate limit") || combined.includes("too many requests")) {
    return {
      fallback: true,
      category: "rate_limit",
      retryProvider: false,
      message: "Provider rate limited",
    };
  }

  /* ---------------- AUTH ---------------- */
  if (status === 401 || status === 403) {
    return {
      fallback: true,
      category: "auth",
      retryProvider: false,
      message: "Provider authentication failed",
    };
  }

  /* ---------------- NETWORK ---------------- */
  const networkCodes = ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "EAI_AGAIN", "ECONNABORTED"];
  if (networkCodes.some(c => error.code === c)) {
    return {
      fallback: true,
      category: "network",
      retryProvider: false,
      message: "Provider network error",
    };
  }
  if (error.name === "AbortError" || status === 408) {
    return {
      fallback: true,
      category: "network",
      retryProvider: false,
      message: "Provider timeout",
    };
  }
  if (combined.includes("fetch failed") || combined.includes("network error")) {
    return {
      fallback: true,
      category: "network",
      retryProvider: false,
      message: "Provider network failure",
    };
  }

  /* ---------------- SERVER ERROR ---------------- */
  if (status >= 500 && status <= 599) {
    return {
      fallback: true,
      category: "server_error",
      retryProvider: false,
      message: "Provider server error",
    };
  }

  /* ---------------- EMPTY / MALFORMED ---------------- */
  if (
    combined.includes("empty response") ||
    combined.includes("malformed") ||
    combined.includes("invalid response")
  ) {
    return {
      fallback: true,
      category: "unknown",
      retryProvider: false,
      message: "Provider returned empty or malformed response",
    };
  }

  /* ---------------- INVALID REQUEST (400) ---------------- */
  if (status === 400) {
    // Some 400s are provider-side (bad model), some are user-side
    // Default to fallback=true to be resilient, but flag as invalid_request
    return {
      fallback: true,
      category: "invalid_request",
      retryProvider: false,
      message: "Provider rejected the request",
    };
  }

  /* ---------------- UNKNOWN ---------------- */
  return {
    fallback: true,
    category: "unknown",
    retryProvider: false,
    message: "Provider failed with unknown error",
  };
}

/* =========================================================
   PROVIDER FAILURE RECORDING
========================================================= */

function recordProviderFailure(providerName, model, category) {
  const key = `${providerName}:${model}`;
  if (!circuitBreakers.has(key)) {
    circuitBreakers.set(key, {
      state: CircuitState.CLOSED,
      failures: 0,
      lastFailure: 0,
      cooldownUntil: 0,
      halfOpenTesting: false,
      category: null,
    });
  }
  const circuit = circuitBreakers.get(key);
  circuit.failures += 1;
  circuit.lastFailure = Date.now();
  circuit.category = category;
}

/* =========================================================
   PROVIDER SELECTION
========================================================= */

function getProvidersForRoute(route) {
  const ordered = [...primaryProviders, ...fallbackProviders]
    .sort((a, b) => a.routePriority[route] - b.routePriority[route]);
  return ordered;
}

/* =========================================================
   AI CALL WITH FALLBACK (ROBUST)
========================================================= */

async function callAIWithFallback(messages, route, maxTokens, requestId) {
  const allProviders = getProvidersForRoute(route);
  if (allProviders.length === 0) {
    throw new Error("No providers configured");
  }

  const attemptedProviders = [];
  const totalStartTime = Date.now();
  let lastError = null;
  let lastCategory = "unknown";

  for (const provider of allProviders) {
    // Check total time budget
    const elapsed = Date.now() - totalStartTime;
    const remaining = TOTAL_AI_REQUEST_TIMEOUT_MS - elapsed;
    if (remaining <= 1000) {
      console.log(`[${requestId}] ⏱️ Total timeout reached`);
      break;
    }

    const model = provider.models[route] || provider.models.balanced;

    // Check circuit availability for this provider+model
    if (!isProviderAvailable(provider, model)) {
      console.log(`[${requestId}] ⏭️ ${provider.name} circuit OPEN for ${model}, skipping`);
      continue;
    }

    attemptedProviders.push(provider.name);

    try {
      const providerTimeout = Math.min(PROVIDER_TIMEOUT_MS, remaining);

      console.log(`[${requestId}] 🤖 ${provider.name} | ${model} | ${route}`);

      const result = await provider.call(messages, model, maxTokens, {
        timeoutMs: providerTimeout,
      });

      if (!result || !result.reply) {
        throw new Error("Provider returned empty response");
      }

      markProviderSuccess(provider, model);
      console.log(`[${requestId}] ✅ ${provider.name} succeeded`);
      return {
        ...result,
        attemptedProviders,
        fallbackUsed: attemptedProviders.length > 1,
      };
    } catch (error) {
      // Handle client abort — do not mark unhealthy
      if (error?.name === "AbortError" && error?.isClientAbort) {
        throw error;
      }

      const classification = classifyProviderError(error);
      lastError = error;
      lastCategory = classification.category;

      console.error(
        `[${requestId}] ⚠️ ${provider.name} failed | category=${classification.category} | fallback=${classification.fallback}`
      );

      // Mark circuit failure
      markProviderFailure(provider, model, classification.category);

      // Always continue to next provider for provider-side errors
      if (classification.fallback) {
        console.log(`[${requestId}] ↪️ Trying next provider`);
        continue;
      }

      // Non-fallback only for genuinely unexpected cases
      console.log(`[${requestId}] ❌ Non-fallback error, aborting chain`);
      throw error;
    }
  }

  // All providers failed or unavailable
  const err = new Error("All AI providers unavailable or failed");
  err.category = lastCategory;
  err.attemptedProviders = attemptedProviders;
  err.isProviderExhaustion = true;
  err.originalError = lastError;
  throw err;
}

/* =========================================================
   MIDDLEWARE
========================================================= */

app.set("trust proxy", TRUST_PROXY);

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));

app.use((req, res, next) => {
  const start = Date.now();
  const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  req.requestId = requestId;

  res.on("finish", () => {
    console.log(
      `${new Date().toISOString()} [${requestId}] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`
    );
  });

  next();
});

const allowedOrigins = CLIENT_URL.split(",").map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS origin not allowed"));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"],
  maxAge: 86400,
}));

app.use(express.json({ limit: "200kb" }));

const chatLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  message: { error: "Too many requests. Please wait." },
  standardHeaders: true,
  legacyHeaders: false,
});

/* =========================================================
   SYSTEM PROMPT
========================================================= */

const SYSTEM_PROMPT = `You are an AI Security Assistant specializing in cloud security, cybersecurity operations, detection engineering, DevSecOps, incident response, and modern security engineering.

PRIMARY EXPERTISE:
- Cloud Security (AWS, Azure, GCP)
- Kubernetes Security
- IAM, WAF, SIEM, SOC
- Detection Engineering
- Incident Response
- Threat Hunting
- DevSecOps
- Security Architecture
- Compliance (NIST, CIS, ISO 27001)

IMPORTANT RULES:
- Never invent cloud services, features, APIs, or commands
- If uncertain, explicitly say so
- Correct false security assumptions respectfully
- Prioritize secure-by-default recommendations
- Never encourage illegal or unauthorized access
- Focus on authorized testing, detection, and defense
- Do not expose secrets, API keys, credentials, or tokens
- Distinguish confirmed evidence from assumptions
- For incidents: Evidence → Observation → Interpretation → Confidence → Action`;

/* =========================================================
   INTENT DETECTION
========================================================= */

function detectIntent(text) {
  const patterns = {
    code_request: /\b(code|implement|write|function|script|configure|deploy|terraform|cloudformation|yaml|json|policy)\b/i,
    explanation: /\b(explain|what is|how does|why|describe|difference|understand|meaning)\b/i,
    troubleshooting: /\b(error|issue|problem|bug|fix|debug|failing|failed|broken|not working|exception)\b/i,
    architecture: /\b(architecture|design|system design|scalable|microservices|vpc|network|diagram|topology)\b/i,
    security: /\b(security|vulnerability|attack|protect|threat|compliance|iam|waf|incident|breach|hack|credential)\b/i,
    optimization: /\b(optimize|performance|improve|best practice|harden|secure|tune|optimization)\b/i,
    detection: /\b(detect|monitor|alert|siem|soc|log|investigate|forensics|kql|query|threat hunting|ioc|indicator)\b/i,
    devsecops: /\b(devsecops|pipeline|ci\/cd|automation|scan|sast|dast|sca|trivy|snyk|semgrep|gitleaks)\b/i,
    forensics: /\b(forensic|timeline|reconstruct|correlate|root cause|attack chain|privilege escalation|persistence)\b/i,
    cloud: /\b(aws|azure|gcp|cloud|s3|ec2|iam|cloudtrail|guardduty|security hub)\b/i,
    kubernetes: /\b(kubernetes|k8s|pod|container|rbac|network policy|service account)\b/i,
    compliance: /\b(compliance|nist|cis|iso 27001|pci dss|gdpr|hipaa|audit)\b/i,
  };

  const detected = [];
  for (const [intent, pattern] of Object.entries(patterns)) {
    if (pattern.test(text)) detected.push(intent);
  }
  return detected;
}

/* =========================================================
   MODEL ROUTER
========================================================= */

function routeIntent(intents, text) {
  const normalized = text.toLowerCase();

  const powerfulPatterns = [
    /\banalyze\b.*\b(logs|events|timeline|attack|incident)\b/i,
    /\binvestigate\b.*\b(incident|breach|attack|compromise)\b/i,
    /\breconstruct\b.*\b(timeline|attack|chain|events)\b/i,
    /\bthreat hunting\b/i,
    /\bforensic\b/i,
    /\bprivilege escalation\b/i,
    /\broot cause\b/i,
    /\battack chain\b/i,
    /\bcorrelate\b.*\b(events|logs|alerts|findings)\b/i,
    /\bincident response\b/i,
    /\bdesign\b.*\b(secure|multi-account|architecture)\b/i,
  ];

  if (powerfulPatterns.some(p => p.test(normalized))) return "powerful";
  if (text.length > 3000 && (intents.includes("security") || intents.includes("detection"))) return "powerful";
  if (intents.includes("forensics")) return "powerful";

  if (
    intents.includes("code_request") ||
    intents.includes("devsecops") ||
    intents.includes("optimization") ||
    intents.includes("troubleshooting") ||
    intents.includes("architecture") ||
    intents.includes("detection") ||
    intents.includes("kubernetes") ||
    intents.includes("compliance")
  ) {
    return "balanced";
  }

  if (text.length < 150 && (intents.includes("explanation") || intents.includes("cloud") || intents.length === 0)) {
    return "fast";
  }

  if (intents.includes("security")) return "balanced";
  return "fast";
}

/* =========================================================
   VALIDATION
========================================================= */

function validateMessages(req, res, next) {
  const { messages } = req.body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: "Messages required" });
  }
  if (messages.length > 50) {
    return res.status(400).json({ error: "Too many messages" });
  }

  const validRoles = ["user", "assistant", "system"];
  for (const msg of messages) {
    if (!msg || typeof msg !== "object") {
      return res.status(400).json({ error: "Invalid message" });
    }
    if (!msg.role || !validRoles.includes(msg.role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    if (typeof msg.content !== "string" || !msg.content.trim()) {
      return res.status(400).json({ error: "Empty content" });
    }
    if (msg.content.length > 4000) {
      return res.status(400).json({ error: "Message too long" });
    }
  }
  next();
}

/* =========================================================
   CONVERSATION PREPARATION
========================================================= */

function prepareConversation(messages, systemPrompt) {
  const safe = messages.filter(m => m.role !== "system").slice(-MAX_HISTORY_MESSAGES);
  const selected = [];
  let totalChars = systemPrompt.length;

  for (let i = safe.length - 1; i >= 0; i--) {
    if (totalChars + safe[i].content.length > MAX_CONTEXT_CHARACTERS) break;
    selected.unshift({ role: safe[i].role, content: safe[i].content });
    totalChars += safe[i].content.length;
  }

  return [{ role: "system", content: systemPrompt }, ...selected];
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    environment: NODE_ENV,
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    providers: getProviderHealthStatus(),
  });
});

/* =========================================================
   CHAT ENDPOINT
========================================================= */

app.post("/api/chat", chatLimiter, validateMessages, async (req, res) => {
  const startTime = Date.now();

  try {
    const { messages } = req.body;
    const lastUserMessage = [...messages].reverse().find(m => m.role === "user");
    if (!lastUserMessage) {
      return res.status(400).json({ error: "User message required" });
    }

    const intents = detectIntent(lastUserMessage.content);
    const route = routeIntent(intents, lastUserMessage.content);
    const maxTokens =
      route === "fast" ? FAST_MAX_TOKENS :
      route === "balanced" ? BALANCED_MAX_TOKENS :
      POWERFUL_MAX_TOKENS;

    console.log(
      `🧠 [${req.requestId}] Intent: ${intents.join(",") || "general"} | Route: ${route} | MaxTokens: ${maxTokens}`
    );

    let enhancedPrompt = SYSTEM_PROMPT;
    if (intents.length > 0) {
      enhancedPrompt += `\n\nDetected intent: ${intents.join(", ")}`;
    }

    const preparedMessages = prepareConversation(messages, enhancedPrompt);
    const result = await callAIWithFallback(preparedMessages, route, maxTokens, req.requestId);

    const responseTimeMs = Date.now() - startTime;

    return res.json({
      reply: result.reply,
      intents,
      metadata: {
        timestamp: new Date().toISOString(),
        provider: result.provider,
        model: result.model,
        route,
        responseTimeMs,
        usage: result.usage,
        fallbackUsed: result.fallbackUsed,
        attemptedProviders: result.attemptedProviders,
        requestId: req.requestId,
      },
    });
  } catch (error) {
    const responseTimeMs = Date.now() - startTime;

    /* Client abort: don't log as error, don't return 500 */
    if (error?.name === "AbortError" && error?.isClientAbort) {
      console.log(`[${req.requestId}] Client aborted request`);
      return;
    }

    /* Provider exhaustion → 503, not 500 */
    if (error?.isProviderExhaustion) {
      console.error(`❌ [${req.requestId}] All providers unavailable`);
      return res.status(503).json({
        error: "AI services are temporarily unavailable. Please try again shortly.",
        ...(NODE_ENV === "development" ? {
          requestId: req.requestId,
          attemptedProviders: error.attemptedProviders,
          category: error.category,
        } : {}),
      });
    }

    /* Genuine internal errors → 500 */
    console.error(`❌ [${req.requestId}] Internal error:`, error.message);
    return res.status(500).json({
      error: "AI request failed. Please try again.",
      ...(NODE_ENV === "development" ? { details: error.message, requestId: req.requestId } : {}),
    });
  }
});

/* =========================================================
   CLEAR CONVERSATION
========================================================= */

app.post("/api/clear-conversation", (req, res) => {
  const { conversationId } = req.body;
  if (!conversationId) {
    return res.status(400).json({ error: "conversationId required" });
  }
  console.log(`🗑️ [${req.requestId}] Cleared: ${conversationId}`);
  return res.json({ status: "cleared", conversationId });
});

/* =========================================================
   404 & ERROR HANDLING
========================================================= */

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.use((error, req, res, next) => {
  console.error("❌ Server error:", error.message);
  if (error.message === "CORS origin not allowed") {
    return res.status(403).json({ error: "CORS blocked" });
  }
  res.status(500).json({ error: "Internal server error" });
});

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

let isShuttingDown = false;

async function shutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\n${signal} received. Shutting down gracefully...`);

  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });

  setTimeout(() => {
    console.log("Forced shutdown");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught exception:", error.message);
  shutdown("uncaughtException");
});

process.on("unhandledRejection", (reason) => {
  console.error("❌ Unhandled rejection:", reason?.message || reason);
});

/* =========================================================
   START
========================================================= */

const server = app.listen(PORT, () => {
  console.log("");
  console.log("========================================");
  console.log("🚀 AI Security Assistant API");
  console.log("========================================");
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🤖 Primary: ${primaryProviders.map(p => p.name).join(", ") || "None"}`);
  console.log(`🆘 Fallback: ${fallbackProviders.map(p => p.name).join(", ") || "None"}`);
  console.log(`⚡ Rate limit: ${RATE_LIMIT_MAX}/${RATE_LIMIT_WINDOW_MS}ms`);
  console.log(`⏱️ Timeout: ${PROVIDER_TIMEOUT_MS}ms per provider | ${TOTAL_AI_REQUEST_TIMEOUT_MS}ms total`);
  console.log("========================================");
});

server.timeout = TOTAL_AI