/**
 * AI Security Assistant - Reliability Rebuild
 * 
 * Core changes:
 * 1. New FallbackEngine for sequential provider attempts
 * 2. ProviderErrorClassifier for isolated error handling
 * 3. CircuitBreakerPool for optimization (not primary failure mechanism)
 * 4. Enhanced BaseProvider with consistent error normalization
 * 5. Provider isolation - one provider failure doesn't block others
 * 
 * Contract:
 * IF ANY CONFIGURED PROVIDER SUCCEEDS → HTTP 200
 * ONLY IF ALL CONFIGURED PROVIDERS FAIL → HTTP 503
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

// New reliability components
const FallbackEngine = require('./FallbackEngine');
const { CircuitBreakerPool } = require('./CircuitBreaker');

// Providers
const {
  GroqProvider,
  DeepSeekProvider,
  GeminiProvider,
  OpenAIProvider,
  AnthropicProvider,
  OpenRouterProvider,
} = require('./providers-updated');

// ==========================================
// SETUP
// ==========================================

const app = express();
const PORT = Number(process.env.PORT) || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

// ==========================================
// PROVIDER CONFIGURATION
// ==========================================

const PROVIDERS = [
  new GroqProvider({
    name: 'Groq',
    apiKey: process.env.GROQ_API_KEY,
    url: 'https://api.groq.com/openai/v1/chat/completions',
    type: 'openai-compatible',
    models: {
      fast: process.env.GROQ_FAST_MODEL || 'llama-3.3-70b-versatile',
      balanced: process.env.GROQ_BALANCED_MODEL || 'llama-3.3-70b-versatile',
      powerful: process.env.GROQ_POWERFUL_MODEL || 'llama-3.3-70b-versatile',
    },
  }),

  new DeepSeekProvider({
    name: 'DeepSeek',
    apiKey: process.env.DEEPSEEK_API_KEY,
    url: 'https://api.deepseek.com/chat/completions',
    type: 'openai-compatible',
    models: {
      fast: process.env.DEEPSEEK_FAST_MODEL || 'deepseek-chat',
      balanced: process.env.DEEPSEEK_BALANCED_MODEL || 'deepseek-chat',
      powerful: process.env.DEEPSEEK_POWERFUL_MODEL || 'deepseek-reasoner',
    },
  }),

  new GeminiProvider({
    name: 'Gemini',
    apiKey: process.env.GEMINI_API_KEY,
    url: 'https://generativelanguage.googleapis.com/v1beta/models',
    type: 'gemini',
    models: {
      fast: process.env.GEMINI_FAST_MODEL || 'gemini-1.5-flash',
      balanced: process.env.GEMINI_BALANCED_MODEL || 'gemini-1.5-flash',
      powerful: process.env.GEMINI_POWERFUL_MODEL || 'gemini-1.5-pro',
    },
  }),

  new OpenAIProvider({
    name: 'OpenAI',
    apiKey: process.env.OPENAI_API_KEY,
    url: 'https://api.openai.com/v1/chat/completions',
    type: 'openai-compatible',
    models: {
      fast: process.env.OPENAI_FAST_MODEL || 'gpt-4o-mini',
      balanced: process.env.OPENAI_BALANCED_MODEL || 'gpt-4o',
      powerful: process.env.OPENAI_POWERFUL_MODEL || 'gpt-4-turbo',
    },
  }),

  new AnthropicProvider({
    name: 'Claude',
    apiKey: process.env.ANTHROPIC_API_KEY,
    url: 'https://api.anthropic.com/v1/messages',
    type: 'anthropic',
    models: {
      fast: process.env.ANTHROPIC_FAST_MODEL || 'claude-3-haiku-20240307',
      balanced: process.env.ANTHROPIC_BALANCED_MODEL || 'claude-3-sonnet-20240229',
      powerful: process.env.ANTHROPIC_POWERFUL_MODEL || 'claude-3-opus-20240229',
    },
  }),

  new OpenRouterProvider({
    name: 'OpenRouter',
    apiKey: process.env.OPENROUTER_API_KEY,
    url: 'https://openrouter.ai/api/v1/chat/completions',
    type: 'openai-compatible',
    models: {
      fast: process.env.OPENROUTER_FAST_MODEL || 'meta-llama/llama-3.3-70b-instruct',
      balanced: process.env.OPENROUTER_BALANCED_MODEL || 'meta-llama/llama-3.3-70b-instruct',
      powerful: process.env.OPENROUTER_POWERFUL_MODEL || 'meta-llama/llama-3.3-70b-instruct',
    },
  }),
];

// Filter to only configured providers
const CONFIGURED_PROVIDERS = PROVIDERS.filter(p => p.isConfigured());

if (CONFIGURED_PROVIDERS.length === 0) {
  console.error('❌ ERROR: No AI providers configured!');
  console.error('Set at least one of:');
  console.error('  - GROQ_API_KEY');
  console.error('  - DEEPSEEK_API_KEY');
  console.error('  - GEMINI_API_KEY');
  console.error('  - OPENAI_API_KEY');
  console.error('  - ANTHROPIC_API_KEY');
  console.error('  - OPENROUTER_API_KEY');
  process.exit(1);
}

console.log(
  '✅ Configured providers:',
  CONFIGURED_PROVIDERS.map(p => p.name).join(', ')
);

// ==========================================
// TIMEOUTS & LIMITS
// ==========================================

const PROVIDER_TIMEOUT_MS = Number(process.env.PROVIDER_TIMEOUT_MS) || 10000;
const TOTAL_AI_REQUEST_TIMEOUT_MS = 
  Number(process.env.TOTAL_AI_REQUEST_TIMEOUT_MS) || 55000;

const FAST_MAX_TOKENS = Number(process.env.FAST_MAX_TOKENS) || 2000;
const BALANCED_MAX_TOKENS = Number(process.env.BALANCED_MAX_TOKENS) || 4000;
const POWERFUL_MAX_TOKENS = Number(process.env.POWERFUL_MAX_TOKENS) || 8000;

const MAX_HISTORY_MESSAGES = 20;
const MAX_CONTEXT_CHARACTERS = 30000;

// ==========================================
// CIRCUIT BREAKER POOL
// ==========================================

const circuitBreakerPool = new CircuitBreakerPool({
  failureThreshold: 3,
  successThreshold: 2,
  cooldownMs: 30000, // 30 seconds
});

// ==========================================
// FALLBACK ENGINE
// ==========================================

const fallbackEngine = new FallbackEngine({
  providers: CONFIGURED_PROVIDERS,
  circuitBreakerPool,
  totalTimeoutMs: TOTAL_AI_REQUEST_TIMEOUT_MS,
  providerTimeoutMs: PROVIDER_TIMEOUT_MS,
});

// ==========================================
// MIDDLEWARE
// ==========================================

app.set('trust proxy', 1);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

const corsOrigins = CLIENT_URL.split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || corsOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`CORS blocked: ${origin}`);
        callback(new Error('CORS not allowed'));
      }
    },
    credentials: true,
  })
);

app.use(express.json({ limit: '100kb' }));

const chatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// ==========================================
// REQUEST ID MIDDLEWARE
// ==========================================

app.use((req, res, next) => {
  req.id = uuidv4();
  next();
});

// ==========================================
// SYSTEM PROMPT
// ==========================================

const SYSTEM_PROMPT = `You are an AI Security Assistant specializing in cloud security, cybersecurity operations, detection engineering, DevSecOps, incident response, and modern security engineering.

PRIMARY EXPERTISE:
- Cloud Security (AWS, Azure, Google Cloud, Zero Trust, Secrets)
- Kubernetes and Containers (RBAC, Security Policies, Pod Security)
- SOC and Detection Engineering (SIEM, XDR, Threat Hunting, KQL, Sigma)
- DevSecOps (CI/CD, SAST, DAST, IaC Security)
- Security Architecture (Design, Authentication, Authorization, TLS)
- Compliance (NIST, CIS, ISO 27001, PCI DSS)

IMPORTANT RULES:
- Never invent cloud services or APIs
- If uncertain, explicitly say so
- Prioritize secure-by-default recommendations
- Never encourage unauthorized access
- Focus on authorized testing and defense`;

// ==========================================
// INTENT DETECTION
// ==========================================

function detectIntent(text) {
  const patterns = {
    code: /\b(code|implement|write|configure|terraform|policy)\b/i,
    explanation: /\b(explain|what is|how does|describe)\b/i,
    troubleshooting: /\b(error|issue|problem|debug|fix)\b/i,
    architecture: /\b(architecture|design|vpc|network)\b/i,
    security: /\b(security|vulnerability|attack|threat|incident)\b/i,
    detection: /\b(detect|monitor|alert|siem|log|investigate)\b/i,
  };

  return Object.entries(patterns)
    .filter(([_, pattern]) => pattern.test(text))
    .map(([intent]) => intent);
}

// ==========================================
// ROUTE SELECTION
// ==========================================

function selectRoute(intents, text) {
  const powerfulPatterns = [
    /\binvestigate\b/i,
    /\bincident response\b/i,
    /\bthreat hunting\b/i,
    /\breconstruct.*timeline\b/i,
  ];

  if (powerfulPatterns.some(p => p.test(text)) || text.length > 3000) {
    return 'powerful';
  }

  if (intents.includes('code') || intents.includes('architecture')) {
    return 'balanced';
  }

  if (text.length < 150 && intents.includes('explanation')) {
    return 'fast';
  }

  return 'balanced';
}

// ==========================================
// PREPARE CONVERSATION
// ==========================================

function prepareConversation(messages) {
  const safeMessages = messages
    .filter(m => m.role !== 'system')
    .slice(-MAX_HISTORY_MESSAGES);

  const selected = [];
  let totalChars = SYSTEM_PROMPT.length;

  for (let i = safeMessages.length - 1; i >= 0; i--) {
    const msg = safeMessages[i];
    if (totalChars + msg.content.length > MAX_CONTEXT_CHARACTERS) break;

    selected.unshift({
      role: msg.role,
      content: msg.content,
    });

    totalChars += msg.content.length;
  }

  return [
    { role: 'system', content: SYSTEM_PROMPT },
    ...selected,
  ];
}

// ==========================================
// HEALTH ENDPOINT
// ==========================================

app.get('/api/health', (req, res) => {
  const health = fallbackEngine.getHealthStatus();

  res.json({
    status: health.healthy ? 'healthy' : 'unavailable',
    providers: health.providers,
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// ==========================================
// DIAGNOSTICS ENDPOINT (Internal)
// ==========================================

app.get('/api/diagnostics', (req, res) => {
  // Only in development
  if (NODE_ENV !== 'development') {
    return res.status(403).json({ error: 'Not available in production' });
  }

  res.json(fallbackEngine.getDiagnostics());
});

// ==========================================
// CHAT ENDPOINT - THE CORE RELIABILITY FIX
// ==========================================

app.post('/api/chat', chatLimiter, async (req, res) => {
  const requestId = req.id;
  const startTime = Date.now();

  try {
    const { messages, conversationId } = req.body;

    // Validate request
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Invalid request' });
    }

    const lastUserMessage = [...messages]
      .reverse()
      .find(m => m.role === 'user');

    if (!lastUserMessage) {
      return res.status(400).json({ error: 'No user message' });
    }

    console.log(`[${requestId}] Starting request from user`);

    // Detect intent and select route
    const intents = detectIntent(lastUserMessage.content);
    const route = selectRoute(intents, lastUserMessage.content);

    console.log(
      `[${requestId}] Intent: ${intents.join(', ') || 'general'} | Route: ${route}`
    );

    // Prepare messages for AI
    const preparedMessages = prepareConversation(messages);

    // Get max tokens for route
    const maxTokensMap = {
      fast: FAST_MAX_TOKENS,
      balanced: BALANCED_MAX_TOKENS,
      powerful: POWERFUL_MAX_TOKENS,
    };
    const maxTokens = maxTokensMap[route];

    // ========== THIS IS THE KEY FIX ==========
    // Use fallback engine to try providers sequentially
    // Stop on first success
    // Only 503 if ALL providers fail
    // =====================================

    try {
      const result = await fallbackEngine.callWithFallback(
        preparedMessages,
        route,
        maxTokens,
        requestId
      );

      const duration = Date.now() - startTime;

      console.log(
        `[${requestId}] SUCCESS: ${result.provider} | fallback=${result.fallbackUsed} | ` +
        `duration=${duration}ms`
      );

      return res.json({
        reply: result.reply,
        intents,
        metadata: {
          provider: result.provider,
          model: result.model,
          route,
          responseTimeMs: duration,
          fallbackUsed: result.fallbackUsed,
          attemptedProviders: result.attemptedProviders,
          requestId,
        },
      });

    } catch (error) {
      const duration = Date.now() - startTime;

      // Provider exhaustion error
      if (error.isProviderExhaustion) {
        console.log(
          `[${requestId}] EXHAUSTED: All providers failed | duration=${duration}ms`
        );

        return res.status(503).json({
          error: 'AI services temporarily unavailable',
          details: {
            attemptedProviders: error.attemptedProviders,
            lastError: error.originalError?.message,
          },
        });
      }

      // Other errors
      console.error(`[${requestId}] Error:`, error.message);

      return res.status(error.status || 500).json({
        error: error.message || 'Internal error',
      });
    }

  } catch (error) {
    console.error(`[${req.id}] Unexpected error:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==========================================
// CLEAR CONVERSATION ENDPOINT
// ==========================================

app.post('/api/clear-conversation', (req, res) => {
  const { conversationId } = req.body;
  res.json({ status: 'cleared', conversationId });
});

// ==========================================
// 404 & ERROR HANDLERS
// ==========================================

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Server error' });
});

// ==========================================
// STARTUP
// ==========================================

const server = app.listen(PORT, () => {
  console.log('');
  console.log('════════════════════════════════════════');
  console.log('🚀 AI Security Assistant - Reliability v2');
  console.log('════════════════════════════════════════');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔗 Client: ${CLIENT_URL}`);
  console.log(`🤖 Providers: ${CONFIGURED_PROVIDERS.map(p => p.name).join(', ')}`);
  console.log(`⏱️  Provider timeout: ${PROVIDER_TIMEOUT_MS}ms`);
  console.log(`⏱️  Total budget: ${TOTAL_AI_REQUEST_TIMEOUT_MS}ms`);
  console.log('════════════════════════════════════════');
  console.log('');
});

server.timeout = 60000;

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => process.exit(0));
});

module.exports = app;