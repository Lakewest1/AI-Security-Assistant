require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Mistral } = require("@mistralai/mistralai");

const app = express();

/* ==========================================================================
   Configuration
   ========================================================================== */

const PORT = Number(process.env.PORT) || 5000;

const CLIENT_URL =
  process.env.CLIENT_URL || "http://localhost:5173";

const NODE_ENV =
  process.env.NODE_ENV || "development";

const MISTRAL_MODEL =
  process.env.MISTRAL_MODEL || "mistral-small-latest";

const MAX_TOKENS =
  Number(process.env.MAX_TOKENS) || 4000;

const RATE_LIMIT_WINDOW_MS =
  Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;

const RATE_LIMIT_MAX =
  Number(process.env.RATE_LIMIT_MAX) || 30;

/*
 * Number of previous messages sent to Mistral.
 *
 * Keeping this smaller reduces token usage and makes the chatbot
 * less likely to hit context/token limits.
 */
const MAX_HISTORY_MESSAGES =
  Number(process.env.MAX_HISTORY_MESSAGES) || 20;

/*
 * Maximum characters allowed in the entire conversation
 * sent to the Mistral API.
 */
const MAX_CONTEXT_CHARACTERS =
  Number(process.env.MAX_CONTEXT_CHARACTERS) || 30000;


/* ==========================================================================
   Validate environment
   ========================================================================== */

if (!process.env.MISTRAL_API_KEY) {
  console.error("❌ MISTRAL_API_KEY is missing.");

  if (NODE_ENV === "production") {
    process.exit(1);
  }
}


/* ==========================================================================
   Mistral Client
   ========================================================================== */

const mistral = new Mistral({
  apiKey: process.env.MISTRAL_API_KEY,
});


/* ==========================================================================
   Security Middleware
   ========================================================================== */

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);


/* ==========================================================================
   CORS
   ========================================================================== */

const allowedOrigins = CLIENT_URL
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      /*
       * Allow requests without an Origin header.
       * This is useful for curl, health checks, etc.
       */
      if (!origin) {
        return callback(null, true);
      }

      /*
       * Development / wildcard mode.
       */
      if (
        allowedOrigins.includes("*") ||
        NODE_ENV === "development"
      ) {
        return callback(null, true);
      }

      /*
       * Production whitelist.
       */
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("CORS policy: Origin not allowed")
      );
    },

    credentials: true,

    methods: [
      "GET",
      "POST",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
    ],
  })
);


/* ==========================================================================
   Body Parser
   ========================================================================== */

app.use(
  express.json({
    limit: "200kb",
  })
);


/* ==========================================================================
   Request Logger
   ========================================================================== */

app.use((req, res, next) => {
  if (req.path !== "/api/health") {
    console.log(
      `${new Date().toISOString()} ${req.method} ${req.path}`
    );
  }

  next();
});


/* ==========================================================================
   Rate Limiting
   ========================================================================== */

const chatLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,

  max: RATE_LIMIT_MAX,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    error:
      "Too many chat requests. Please wait a moment and try again.",
  },

  handler: (req, res) => {
    console.warn(
      `⚠️ Rate limit reached for ${req.ip}`
    );

    res.status(429).json({
      error:
        "Too many chat requests. Please wait a moment and try again.",
      retryAfter:
        Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
  },
});


/* ==========================================================================
   System Prompt
   ========================================================================== */

const SYSTEM_PROMPT = `
You are an AI Security Assistant specializing in cloud security
and modern security engineering.

PRIMARY EXPERTISE:

- Cloud Security: AWS, Azure, GCP
- Kubernetes Security
- Container Security
- IAM
- WAF
- SOC Operations
- Detection Engineering
- Incident Response
- Threat Detection
- DevSecOps
- Security Automation
- Security Architecture
- Zero Trust
- Cloud Compliance
- Governance

SECONDARY KNOWLEDGE:

- DevOps
- CI/CD Security
- API Security
- Software Architecture
- React
- Node.js
- TypeScript

FACTUAL ACCURACY:

- Never invent cloud services or features.
- Never fabricate security frameworks.
- Never fabricate commands or configuration options.
- If uncertain, clearly say so.
- Distinguish official documentation from practical recommendations.
- Correct incorrect assumptions respectfully.

RESPONSE STYLE:

- Be clear and practical.
- Write for junior and intermediate security engineers.
- Avoid unnecessary repetition.
- Use Markdown.
- Use headings when useful.
- Use bullet points for lists.
- Use numbered steps for procedures.
- Use code blocks for code.
- Keep answers focused on the user's question.

SECURITY:

- Recommend least privilege.
- Prefer secure defaults.
- Explain important security risks.
- Mention common mistakes.
- Do not encourage unsafe production configurations.

For technical questions, use this structure when appropriate:

## What it is

Brief explanation.

## How it works

Step-by-step explanation.

## Example

Practical example when useful.

## Security considerations

Important security implications.

## Key takeaway

Short summary.
`;


/* ==========================================================================
   Intent Detection
   ========================================================================== */

function detectIntent(text) {
  const patterns = {
    code_request:
      /\b(code|implement|write|function|script|configure|deploy|terraform|cloudformation)\b/i,

    explanation:
      /\b(explain|what is|how does|why|describe|difference|understand)\b/i,

    troubleshooting:
      /\b(error|issue|problem|bug|fix|debug|failing|broken|not working)\b/i,

    architecture:
      /\b(architecture|design|system|scalable|vpc|network|diagram|topology)\b/i,

    security:
      /\b(security|vulnerability|attack|protect|threat|compliance|iam|waf|incident|breach|hack)\b/i,

    optimization:
      /\b(optimize|performance|improve|best practice|harden|secure|tune)\b/i,

    detection:
      /\b(detect|monitor|alert|siem|soc|log|investigate|forensics)\b/i,

    devsecops:
      /\b(devsecops|pipeline|ci\/cd|automation|scan|sast|dast)\b/i,
  };

  const detected = [];

  for (const [intent, pattern] of Object.entries(patterns)) {
    if (pattern.test(text)) {
      detected.push(intent);
    }
  }

  return detected;
}


/* ==========================================================================
   Visual Decision
   ========================================================================== */

function shouldIncludeVisual(text) {
  const visualPatterns = [
    /\barchitecture\b/i,
    /\bdiagram\b/i,
    /\bflow\b/i,
    /\btopology\b/i,
    /\bworkflow\b/i,
    /\bprocess\b/i,
    /\bpipeline\b/i,
    /\blifecycle\b/i,
    /\bcompare\b/i,
    /\bdifference\b/i,
    /\bversus\b/i,
    /\bvs\b/i,
    /\bsetup\b/i,
    /\bconfigure\b/i,
    /\bdeploy\b/i,
    /\bauthentication\b/i,
    /\bauthorization\b/i,
    /\brouting\b/i,
  ];

  const needed = visualPatterns.some((pattern) =>
    pattern.test(text)
  );

  return {
    visualNeeded: needed,
    visualType: needed ? "diagram" : "none",
    visualQuery: needed
      ? text.slice(0, 100)
      : null,
  };
}


/* ==========================================================================
   Message Validation
   ========================================================================== */

function validateMessages(req, res, next) {
  const { messages } = req.body;

  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({
      error:
        "Messages array is required and cannot be empty.",
    });
  }

  if (messages.length > 50) {
    return res.status(400).json({
      error:
        "Conversation is too long. Maximum 50 messages allowed.",
    });
  }

  const validRoles = [
    "user",
    "assistant",
    "system",
  ];

  for (const message of messages) {
    if (!message || typeof message !== "object") {
      return res.status(400).json({
        error:
          "Each message must be an object.",
      });
    }

    if (
      !message.role ||
      !validRoles.includes(message.role)
    ) {
      return res.status(400).json({
        error:
          "Invalid message role.",
      });
    }

    if (typeof message.content !== "string") {
      return res.status(400).json({
        error:
          "Message content must be a string.",
      });
    }

    if (!message.content.trim()) {
      return res.status(400).json({
        error:
          "Message content cannot be empty.",
      });
    }

    if (message.content.length > 4000) {
      return res.status(400).json({
        error:
          "Individual message is too long. Maximum 4000 characters.",
      });
    }
  }

  next();
}


/* ==========================================================================
   Limit Conversation Context
   ========================================================================== */

function prepareConversation(messages) {
  /*
   * Keep only the most recent messages.
   *
   * This prevents every request from becoming larger and larger.
   */

  let selectedMessages =
    messages.slice(-MAX_HISTORY_MESSAGES);

  /*
   * Ensure the first message isn't a system message supplied
   * by the client. Our server controls the system prompt.
   */
  selectedMessages = selectedMessages.filter(
    (message) => message.role !== "system"
  );

  /*
   * Protect against excessively large context.
   */
  let totalCharacters = 0;
  const finalMessages = [];

  for (
    let i = selectedMessages.length - 1;
    i >= 0;
    i--
  ) {
    const message = selectedMessages[i];

    const messageLength =
      message.content.length;

    if (
      totalCharacters + messageLength >
      MAX_CONTEXT_CHARACTERS
    ) {
      break;
    }

    finalMessages.unshift(message);

    totalCharacters += messageLength;
  }

  return finalMessages;
}


/* ==========================================================================
   Health Check
   ========================================================================== */

app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "AI Security Assistant API",
    model: MISTRAL_MODEL,
    environment: NODE_ENV,
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});


/* ==========================================================================
   Chat Endpoint
   ========================================================================== */

app.post(
  "/api/chat",
  chatLimiter,
  validateMessages,
  async (req, res) => {
    const requestStartedAt = Date.now();

    try {
      const { messages } = req.body;

      /*
       * Get latest user message.
       */
      const lastUserMessage =
        [...messages]
          .reverse()
          .find(
            (message) =>
              message.role === "user"
          );

      if (!lastUserMessage) {
        return res.status(400).json({
          error:
            "At least one user message is required.",
        });
      }

      /*
       * Detect intent.
       */
      const intents = detectIntent(
        lastUserMessage.content
      );

      /*
       * Visual decision.
       */
      const visualDecision =
        shouldIncludeVisual(
          lastUserMessage.content
        );

      /*
       * Prepare smaller conversation context.
       */
      const conversation =
        prepareConversation(messages);

      /*
       * Build system prompt.
       */
      let enhancedSystemPrompt =
        SYSTEM_PROMPT;

      if (intents.length > 0) {
        enhancedSystemPrompt += `

Detected intent:
${intents.join(", ")}`;
      }

      if (visualDecision.visualNeeded) {
        enhancedSystemPrompt += `

Visual context:
The user may benefit from a ${visualDecision.visualType} visualization.`;
      }

      /*
       * Final messages sent to Mistral.
       */
      const mistralMessages = [
        {
          role: "system",
          content: enhancedSystemPrompt,
        },
        ...conversation,
      ];

      console.log(
        `🤖 Mistral request | model=${MISTRAL_MODEL} | messages=${mistralMessages.length}`
      );

      /*
       * Call Mistral.
       */
      const response =
        await mistral.chat.complete({
          model: MISTRAL_MODEL,

          messages: mistralMessages,

          temperature: 0.7,

          max_tokens: MAX_TOKENS,

          top_p: 1,
        });

      /*
       * Validate response.
       */
      if (
        !response ||
        !response.choices ||
        !response.choices[0] ||
        !response.choices[0].message
      ) {
        throw new Error(
          "Invalid response structure returned by Mistral."
        );
      }

      const reply =
        response.choices[0].message.content;

      if (
        typeof reply !== "string" ||
        !reply.trim()
      ) {
        throw new Error(
          "Mistral returned an empty response."
        );
      }

      const duration =
        Date.now() - requestStartedAt;

      console.log(
        `✅ Mistral response received in ${duration}ms`
      );

      /*
       * Return response.
       */
      return res.json({
        reply,

        intents,

        visual: {
          needed:
            visualDecision.visualNeeded,

          type:
            visualDecision.visualType,

          query:
            visualDecision.visualQuery,
        },

        metadata: {
          timestamp:
            new Date().toISOString(),

          model:
            MISTRAL_MODEL,

          responseTimeMs:
            duration,
        },
      });
    } catch (error) {
      console.error(
        "❌ Mistral API error:",
        error
      );

      /*
       * Log useful information during debugging.
       */
      console.error(
        "Status:",
        error.status
      );

      console.error(
        "Code:",
        error.code
      );

      console.error(
        "Message:",
        error.message
      );


      /* ---------------------------------------------------------------
         429 - Provider rate limit / quota
         --------------------------------------------------------------- */

      if (error.status === 429) {
        return res.status(429).json({
          error:
            "The Mistral API rate limit or quota has been reached. Please try again later.",
          type:
            "MISTRAL_RATE_LIMIT",
        });
      }


      /* ---------------------------------------------------------------
         401 - Invalid API key
         --------------------------------------------------------------- */

      if (error.status === 401) {
        return res.status(401).json({
          error:
            "Invalid Mistral API key. Check MISTRAL_API_KEY on Render.",
          type:
            "MISTRAL_AUTH_ERROR",
        });
      }


      /* ---------------------------------------------------------------
         403 - Permission / account issue
         --------------------------------------------------------------- */

      if (error.status === 403) {
        return res.status(403).json({
          error:
            "Mistral rejected the request because the API key or account does not have permission.",
          type:
            "MISTRAL_PERMISSION_ERROR",
        });
      }


      /* ---------------------------------------------------------------
         400 - Bad request / context / token problem
         --------------------------------------------------------------- */

      if (error.status === 400) {
        return res.status(400).json({
          error:
            "Mistral rejected the request. The conversation may be too large or the request may be invalid.",
          type:
            "MISTRAL_BAD_REQUEST",
        });
      }


      /* ---------------------------------------------------------------
         Network errors
         --------------------------------------------------------------- */

      if (
        error.code === "ECONNREFUSED" ||
        error.code === "ENOTFOUND" ||
        error.code === "ETIMEDOUT"
      ) {
        return res.status(503).json({
          error:
            "Unable to reach the Mistral API. Please try again.",
          type:
            "MISTRAL_NETWORK_ERROR",
        });
      }


      /* ---------------------------------------------------------------
         Generic error
         --------------------------------------------------------------- */

      return res.status(500).json({
        error:
          "AI request failed. Please try again.",

        type:
          "MISTRAL_UNKNOWN_ERROR",

        ...(NODE_ENV === "development"
          ? {
              details:
                error.message,
            }
          : {}),
      });
    }
  }
);


/* ==========================================================================
   404
   ========================================================================== */

app.use((req, res) => {
  res.status(404).json({
    error: "Route not found.",
  });
});


/* ==========================================================================
   Error Handler
   ========================================================================== */

app.use(
  (err, req, res, next) => {
    console.error(
      "❌ Unhandled server error:",
      err
    );

    /*
     * CORS errors.
     */
    if (
      err.message &&
      err.message.includes("CORS")
    ) {
      return res.status(403).json({
        error:
          "CORS policy blocked this request.",
      });
    }

    res.status(500).json({
      error:
        "Internal server error.",

      ...(NODE_ENV === "development"
        ? {
            details:
              err.message,
          }
        : {}),
    });
  }
);


/* ==========================================================================
   Start Server
   ========================================================================== */

app.listen(PORT, () => {
  console.log("");
  console.log(
    "🚀 AI Security Assistant API started"
  );
  console.log(
    `📍 Port: ${PORT}`
  );
  console.log(
    `🌎 Environment: ${NODE_ENV}`
  );
  console.log(
    `🤖 Model: ${MISTRAL_MODEL}`
  );
  console.log(
    `⚡ Local rate limit: ${RATE_LIMIT_MAX} requests / ${RATE_LIMIT_WINDOW_MS / 60000} minutes`
  );
  console.log(
    `🧠 Max history: ${MAX_HISTORY_MESSAGES} messages`
  );
  console.log(
    `📦 Max context: ${MAX_CONTEXT_CHARACTERS} characters`
  );
  console.log("");
});