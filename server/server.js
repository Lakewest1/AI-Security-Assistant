require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT) || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

const MAX_TOKENS = Number(process.env.MAX_TOKENS) || 4096;

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 60;

const MAX_HISTORY_MESSAGES = Number(process.env.MAX_HISTORY_MESSAGES) || 20;
const MAX_CONTEXT_CHARACTERS = Number(process.env.MAX_CONTEXT_CHARACTERS) || 30000;

const PROVIDER_TIMEOUT_MS = Number(process.env.PROVIDER_TIMEOUT_MS) || 30000;

/* =========================================================
   PROVIDER CONFIGURATION
   Multi-provider resilience and fallback
========================================================= */

const PROVIDERS = {
  groq: {
    name: "Groq",
    enabled: Boolean(process.env.GROQ_API_KEY),
    apiKey: process.env.GROQ_API_KEY,
    url: "https://api.groq.com/openai/v1/chat/completions",
    models: {
      fast: process.env.GROQ_FAST_MODEL || "llama-3.3-70b-versatile",
      balanced: process.env.GROQ_BALANCED_MODEL || "llama-3.3-70b-versatile",
      powerful: process.env.GROQ_POWERFUL_MODEL || "llama-3.3-70b-versatile",
    },
  },

  gemini: {
    name: "Gemini",
    enabled: Boolean(process.env.GEMINI_API_KEY),
    apiKey: process.env.GEMINI_API_KEY,
    url: "https://generativelanguage.googleapis.com/v1beta/models",
    models: {
      fast: process.env.GEMINI_FAST_MODEL || "gemini-1.5-flash",
      balanced: process.env.GEMINI_BALANCED_MODEL || "gemini-1.5-flash",
      powerful: process.env.GEMINI_POWERFUL_MODEL || "gemini-1.5-pro",
    },
  },

  openrouter: {
    name: "OpenRouter",
    enabled: Boolean(process.env.OPENROUTER_API_KEY),
    apiKey: process.env.OPENROUTER_API_KEY,
    url: "https://openrouter.ai/api/v1/chat/completions",
    models: {
      fast: process.env.OPENROUTER_FAST_MODEL || "meta-llama/llama-3.3-70b-instruct",
      balanced: process.env.OPENROUTER_BALANCED_MODEL || "meta-llama/llama-3.3-70b-instruct",
      powerful: process.env.OPENROUTER_POWERFUL_MODEL || "meta-llama/llama-3.3-70b-instruct",
    },
  },
};

/* =========================================================
   ACTIVE PROVIDERS
========================================================= */

const activeProviders = Object.values(PROVIDERS).filter((provider) => provider.enabled);

if (activeProviders.length === 0) {
  console.error("❌ No AI provider configured. Set at least one API key.");
  process.exit(1);
}

console.log(`✅ Active providers: ${activeProviders.map((p) => p.name).join(", ")}`);

/* =========================================================
   TRUST PROXY (Required for Render/Netlify)
========================================================= */

app.set("trust proxy", 1);

/* =========================================================
   SECURITY MIDDLEWARE
========================================================= */

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

/* =========================================================
   REQUEST LOGGING (No sensitive data)
========================================================= */

app.use((req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    console.log(`${new Date().toISOString()} ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });

  next();
});

/* =========================================================
   CORS (Single implementation)
========================================================= */

const allowedOrigins = CLIENT_URL.split(",").map((origin) => origin.trim()).filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests without Origin (health checks, server-to-server, mobile apps)
      if (!origin) {
        return callback(null, true);
      }

      // Allow configured origins
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      // Reject unauthorized browser origins
      console.warn(`CORS blocked origin: ${origin}`);
      return callback(new Error("CORS origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"],
    maxAge: 86400,
  })
);

/* =========================================================
   BODY PARSER
========================================================= */

app.use(express.json({ limit: "100kb" }));

/* =========================================================
   RATE LIMITING
   Application-level only. Separate from provider limits.
========================================================= */

const chatLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  message: {
    error: "Too many requests. Please wait before sending more messages.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/* =========================================================
   SYSTEM PROMPT
========================================================= */

const SYSTEM_PROMPT = `
You are an AI Security Assistant specializing in cloud security,
cybersecurity operations, detection engineering, DevSecOps,
incident response, and modern security engineering.

PRIMARY EXPERTISE:

1. Cloud Security
- AWS (IAM, CloudTrail, CloudWatch, Security Hub, GuardDuty, WAF, KMS)
- Microsoft Azure (Microsoft Defender, Sentinel, Activity Logs)
- Google Cloud (Security Command Center, Cloud Audit Logs)
- Cloud networking and Zero Trust
- Secrets management

2. Kubernetes and Containers
- Kubernetes security (RBAC, Network Policies, Pod Security)
- Container security, image scanning, runtime security
- Kubernetes audit logs

3. SOC and Detection Engineering
- SIEM, XDR, SOC operations, alert triage
- Threat hunting, detection engineering
- KQL, Sigma, MITRE ATT&CK
- Incident investigation, digital forensics
- Attack timelines, IOC analysis, log analysis

4. DevSecOps
- CI/CD security, SAST, DAST, SCA
- IaC security (Terraform, CloudFormation)
- Security tools (Trivy, Snyk, Semgrep, Gitleaks)
- Security automation

5. Security Architecture
- Secure architecture design, network security
- Authentication, Authorization, Encryption, TLS
- WAF, DDoS protection, secure APIs

6. Compliance and Governance
- NIST, CIS Controls, ISO 27001, PCI DSS, GDPR
- Security policies, risk management

IMPORTANT RULES:
- Never invent cloud services, features, APIs, or commands
- If uncertain, explicitly say so
- Correct false security assumptions respectfully
- Prioritize secure-by-default recommendations
- Never encourage illegal or unauthorized access
- Focus on authorized testing, detection, and defense
- Do not expose secrets, API keys, credentials, or tokens

RESPONSE STYLE:
- Explain clearly for junior-to-intermediate security engineers
- Give practical, actionable guidance
- Use Markdown with code blocks when necessary

For troubleshooting:
1. Likely cause
2. How to verify
3. How to fix
4. How to prevent recurrence

For security investigations:
1. Initial triage
2. Evidence
3. Indicators
4. Timeline
5. Attack technique
6. Impact
7. Root cause
8. Containment
9. Remediation
10. Detection improvements
`;

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
  };

  const detected = [];

  for (const [intent, pattern] of Object.entries(patterns)) {
    if (pattern.test(text)) {
      detected.push(intent);
    }
  }

  return detected;
}

/* =========================================================
   MODEL ROUTER (Deterministic, no AI)
========================================================= */

function routeIntent(intents, text) {
  const normalizedText = text.toLowerCase();

  // Complex security investigation patterns → POWERFUL
  const powerfulPatterns = [
    /\banalyze\b.*\b(logs|events|timeline|attack|incident|evidence)\b/i,
    /\binvestigate\b.*\b(incident|breach|attack|compromise|evidence)\b/i,
    /\breconstruct\b.*\b(timeline|attack|chain|events)\b/i,
    /\bthreat hunting\b/i,
    /\bforensic\b/i,
    /\bprivilege escalation\b/i,
    /\broot cause\b/i,
    /\battack chain\b/i,
    /\bcorrelate\b.*\b(events|logs|alerts)\b/i,
    /\bdetermine\b.*\b(attacker|attack|compromise)\b/i,
    /\bincident response\b/i,
  ];

  if (powerfulPatterns.some((pattern) => pattern.test(normalizedText))) {
    return "powerful";
  }

  // Large security investigations → POWERFUL
  if (
    text.length > 3000 &&
    (intents.includes("security") ||
      intents.includes("detection") ||
      intents.includes("troubleshooting") ||
      intents.includes("architecture"))
  ) {
    return "powerful";
  }

  // Balanced tasks
  if (
    intents.includes("code_request") ||
    intents.includes("devsecops") ||
    intents.includes("optimization") ||
    intents.includes("troubleshooting") ||
    intents.includes("architecture") ||
    intents.includes("detection")
  ) {
    return "balanced";
  }

  // Simple questions → FAST
  if (text.length < 150 && (intents.includes("explanation") || intents.length === 0)) {
    return "fast";
  }

  // Security questions → BALANCED
  if (intents.includes("security")) {
    return "balanced";
  }

  return "fast";
}

/* =========================================================
   MESSAGE VALIDATION
========================================================= */

function validateMessages(req, res, next) {
  const { messages } = req.body;

  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: "messages must be an array." });
  }

  if (messages.length === 0) {
    return res.status(400).json({ error: "At least one message is required." });
  }

  if (messages.length > 50) {
    return res.status(400).json({ error: "Too many messages. Maximum 50 allowed." });
  }

  const validRoles = ["user", "assistant", "system"];

  for (const message of messages) {
    if (!message || typeof message !== "object") {
      return res.status(400).json({ error: "Invalid message format." });
    }

    if (!message.role || !validRoles.includes(message.role)) {
      return res.status(400).json({ error: "Invalid message role." });
    }

    if (typeof message.content !== "string" || !message.content.trim()) {
      return res.status(400).json({ error: "Message content must be a non-empty string." });
    }

    if (message.content.length > 4000) {
      return res.status(400).json({ error: "Message exceeds 4000 character limit." });
    }
  }

  next();
}

/* =========================================================
   CONVERSATION PREPARATION
   Prevents system prompt injection
========================================================= */

function prepareConversation(messages, systemPrompt) {
  // Remove all client-provided system messages
  const safeMessages = messages
    .filter((message) => message.role !== "system")
    .slice(-MAX_HISTORY_MESSAGES);

  const selected = [];
  let totalChars = systemPrompt.length;

  // Work backwards but maintain chronological order
  for (let i = safeMessages.length - 1; i >= 0; i--) {
    const message = safeMessages[i];
    const messageChars = message.content.length;

    if (totalChars + messageChars > MAX_CONTEXT_CHARACTERS) {
      break;
    }

    selected.unshift({
      role: message.role,
      content: message.content,
    });

    totalChars += messageChars;
  }

  return [
    {
      role: "system",
      content: systemPrompt,
    },
    ...selected,
  ];
}

/* =========================================================
   PROVIDER CALL WITH TIMEOUT
========================================================= */

async function fetchWithTimeout(url, options, timeoutMs = PROVIDER_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });

    return response;
  } catch (error) {
    if (error.name === "AbortError") {
      const timeoutError = new Error(`Request timed out after ${timeoutMs}ms`);
      timeoutError.status = 408;
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

/* =========================================================
   OPENAI-COMPATIBLE PROVIDER (GROQ / OPENROUTER)
========================================================= */

async function callOpenAICompatibleProvider(provider, messages, model) {
  const headers = {
    Authorization: `Bearer ${provider.apiKey}`,
    "Content-Type": "application/json",
  };

  if (provider.name === "OpenRouter") {
    headers["HTTP-Referer"] = CLIENT_URL;
    headers["X-Title"] = "AI Security Assistant";
  }

  const response = await fetchWithTimeout(provider.url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.7,
      max_tokens: MAX_TOKENS,
      top_p: 1,
    }),
  });

  const responseText = await response.text();
  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = null;
  }

  if (!response.ok) {
    const error = new Error(data?.error?.message || data?.error || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }

  const reply = data?.choices?.[0]?.message?.content;

  if (!reply) {
    throw new Error(`${provider.name} returned an empty response.`);
  }

  return {
    reply,
    usage: data.usage || null,
    provider: provider.name,
    model,
  };
}

/* =========================================================
   GEMINI PROVIDER
========================================================= */

async function callGemini(provider, messages, model) {
  const systemMessage = messages.find((message) => message.role === "system");
  const conversationMessages = messages.filter((message) => message.role !== "system");

  const contents = conversationMessages.map((message) => ({
    role: message.role === "assistant" ? "model" : "user",
    parts: [{ text: message.content }],
  }));

  const requestBody = {
    contents,
    generationConfig: {
      temperature: 0.7,
      maxOutputTokens: MAX_TOKENS,
    },
  };

  if (systemMessage) {
    requestBody.systemInstruction = {
      parts: [{ text: systemMessage.content }],
    };
  }

  const url = `${provider.url}/${model}:generateContent?key=${encodeURIComponent(provider.apiKey)}`;

  const response = await fetchWithTimeout(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });

  const responseText = await response.text();
  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = null;
  }

  if (!response.ok) {
    const error = new Error(data?.error?.message || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }

  const reply = data?.candidates?.[0]?.content?.parts
    ?.map((part) => part.text || "")
    .join("")
    .trim();

  if (!reply) {
    throw new Error("Gemini returned an empty response.");
  }

  return {
    reply,
    usage: data?.usageMetadata || null,
    provider: provider.name,
    model,
  };
}

/* =========================================================
   FALLBACK DECISION
========================================================= */

function shouldFallback(error) {
  const status = error?.status;

  // Network errors (no status) → fallback
  if (!status) {
    return true;
  }

  // Rate limit / timeout / server errors → fallback
  if (status === 408 || status === 429) {
    return true;
  }

  if (status >= 500 && status <= 599) {
    return true;
  }

  // Do NOT fallback on 400, 401, 403, 404
  return false;
}

/* =========================================================
   AI PROVIDER FALLBACK
========================================================= */

async function callAIWithFallback(messages, route) {
  let lastError = null;

  for (const provider of activeProviders) {
    const model = provider.models[route] || provider.models.balanced;

    try {
      console.log(`🤖 Trying ${provider.name} | model=${model} | route=${route}`);

      let result;

      if (provider.name === "Groq" || provider.name === "OpenRouter") {
        result = await callOpenAICompatibleProvider(provider, messages, model);
      } else if (provider.name === "Gemini") {
        result = await callGemini(provider, messages, model);
      } else {
        throw new Error(`Unsupported provider: ${provider.name}`);
      }

      console.log(`✅ ${provider.name} succeeded`);
      return result;
    } catch (error) {
      lastError = error;
      console.error(`⚠️ ${provider.name} failed: ${error.message}`);

      if (!shouldFallback(error)) {
        throw error;
      }

      console.log(`↪️ Falling back from ${provider.name}...`);
    }
  }

  throw lastError || new Error("All AI providers failed.");
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    providers: activeProviders.map((provider) => ({
      name: provider.name,
      enabled: true,
    })),
    environment: NODE_ENV,
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

/* =========================================================
   CHAT ENDPOINT
========================================================= */

app.post("/api/chat", chatLimiter, validateMessages, async (req, res) => {
  const startTime = Date.now();

  try {
    const { messages } = req.body;

    const lastUserMessage = [...messages].reverse().find((message) => message.role === "user");

    if (!lastUserMessage) {
      return res.status(400).json({
        error: "At least one user message is required.",
      });
    }

    const intents = detectIntent(lastUserMessage.content);
    const route = routeIntent(intents, lastUserMessage.content);

    console.log(`🧠 Intent: ${intents.join(", ") || "general"} | Route: ${route}`);

    let enhancedSystemPrompt = SYSTEM_PROMPT;

    if (intents.length > 0) {
      enhancedSystemPrompt += `\n\nDetected user intent: ${intents.join(", ")}`;
    }

    const preparedMessages = prepareConversation(messages, enhancedSystemPrompt);
    const result = await callAIWithFallback(preparedMessages, route);

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
      },
    });
  } catch (error) {
    const responseTimeMs = Date.now() - startTime;
    console.error("❌ AI request failed:", error.message);

    if (error?.status === 401 || error?.status === 403) {
      return res.status(502).json({
        error: "AI provider authentication failed. Please check server configuration.",
      });
    }

    if (error?.status === 429) {
      return res.status(503).json({
        error: "AI providers are temporarily rate limited. Please try again shortly.",
      });
    }

    return res.status(500).json({
      error: "AI request failed. Please try again.",
      ...(NODE_ENV === "development" ? { details: error.message } : {}),
    });
  }
});

/* =========================================================
   404 HANDLER
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found.",
  });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("❌ Server error:", error.message);

  if (error.message === "CORS origin not allowed") {
    return res.status(403).json({
      error: "CORS origin not allowed.",
    });
  }

  res.status(500).json({
    error: "Internal server error.",
  });
});

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(PORT, () => {
  console.log("");
  console.log("========================================");
  console.log("🚀 AI Security Assistant API");
  console.log("========================================");
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔗 Client: ${CLIENT_URL}`);
  console.log(`🤖 Providers: ${activeProviders.map((p) => p.name).join(", ")}`);
  console.log(`⚡ Rate limit: ${RATE_LIMIT_MAX} requests / ${RATE_LIMIT_WINDOW_MS}ms`);
  console.log(`⏱️  Provider timeout: ${PROVIDER_TIMEOUT_MS}ms`);
  console.log("========================================");
  console.log("");
});

// Server timeout (does not replace per-request provider timeouts)
server.timeout = 30000;