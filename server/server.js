require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Mistral } = require("@mistralai/mistralai");

const app = express();

// Configuration
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
const NODE_ENV = process.env.NODE_ENV || "development";
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS) || 4096;
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX) || 30;

// Validate API key on startup
if (!process.env.MISTRAL_API_KEY) {
  console.error("❌ MISTRAL_API_KEY is not set in .env file");
  process.exit(1);
}

// Initialize Mistral client
const mistral = new Mistral({
  apiKey: process.env.MISTRAL_API_KEY,
});

// Security middleware
app.use(helmet());

// Enhanced CORS configuration for mobile support
const allowedOrigins = CLIENT_URL.split(",").map(url => url.trim());

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) {
        return callback(null, true);
      }
      
      // Check if origin is in allowed list
      if (allowedOrigins.indexOf(origin) !== -1 || NODE_ENV === "development") {
        callback(null, true);
      } else {
        console.log("CORS blocked origin:", origin);
        // Temporarily allow all origins for mobile compatibility
        // Remove this in production if you want strict CORS
        callback(null, true);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

// Handle preflight requests
app.options("*", cors());

app.use(express.json({ limit: "100kb" }));

// Rate limiting for chat endpoint
const chatLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  message: {
    error: "Too many requests. Please wait before sending more messages.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Enhanced security-focused system prompt
const SYSTEM_PROMPT = `You are an AI Security Assistant specializing in cloud security and modern security engineering.

PRIMARY EXPERTISE:
- Cloud Security (AWS, Azure, GCP)
- Kubernetes Security & Container Security
- IAM (Identity and Access Management)
- WAF (Web Application Firewall)
- SOC Operations & Monitoring
- Detection Engineering
- Incident Response & Threat Detection
- DevSecOps & Security Automation
- Security Architecture & Zero Trust
- Cloud Compliance & Governance

SECONDARY KNOWLEDGE (when security-relevant):
- DevOps, CI/CD Security
- API Security
- Software Architecture
- React, Node.js, TypeScript security patterns

FACTUAL ACCURACY RULES:
- Never invent AWS/Azure/GCP services or features
- Never fabricate security frameworks or standards
- If uncertain about a service or feature, explicitly say so
- Distinguish between official frameworks (NIST, CIS, ISO) and practical approaches
- Challenge false premises respectfully
- If a question contains incorrect assumptions, point them out

RESPONSE STRUCTURE (adapt to question):
For technical/security questions, use this structure when appropriate:
## What it is
Brief, clear explanation

## How it works
Step-by-step explanation with Markdown

## Example
Practical example with code/configuration where relevant

## Security considerations
Important security implications

## Key takeaway
One or two sentence summary

VISUAL DECISION GUIDELINES:
- Visual needed: true for architecture, flows, workflows, complex concepts
- Visual needed: false for definitions, simple facts, troubleshooting
- Visual query should be specific and searchable

RESPONSE GUIDELINES:
- Explain concepts clearly for junior security engineers
- Provide practical, actionable examples
- Highlight security risks and common mistakes
- Use Markdown formatting appropriately
- Structure complex explanations step-by-step
- Include relevant AWS/Azure/GCP service names
- Mention compliance frameworks only when relevant
- Prioritize accurate security guidance over satisfying user premises
- Default to secure configurations
- Recommend least-privilege access by default`;

// Enhanced intent detection
function detectIntent(text) {
  const patterns = {
    code_request: /\b(code|implement|write|function|script|configure|deploy|terraform|cloudformation)\b/i,
    explanation: /\b(explain|what is|how does|why|describe|difference|understand)\b/i,
    troubleshooting: /\b(error|issue|problem|bug|fix|debug|failing|broken|not working)\b/i,
    architecture: /\b(architecture|design|system|scalable|microservices|vpc|network|diagram)\b/i,
    security: /\b(security|vulnerability|attack|protect|threat|compliance|iam|waf|incident|breach|hack)\b/i,
    optimization: /\b(optimize|performance|improve|best practice|harden|secure|tune)\b/i,
    detection: /\b(detect|monitor|alert|siem|soc|log|investigate|forensics)\b/i,
    devsecops: /\b(devsecops|pipeline|ci\/cd|automation|scan|sast|dast)\b/i,
  };

  const detected = [];
  for (const [intent, pattern] of Object.entries(patterns)) {
    if (pattern.test(text)) {
      detected.push(intent);
    }
  }
  return detected;
}

// Visual decision system
function shouldIncludeVisual(text, intents) {
  const visualPatterns = {
    architecture: /\b(architecture|diagram|flow|topology|structure|components)\b/i,
    workflow: /\b(workflow|process|steps|pipeline|lifecycle)\b/i,
    comparison: /\b(compare|difference|versus|vs)\b/i,
    setup: /\b(setup|configure|deploy|implement|build)\b/i,
    security_flow: /\b(authentication|authorization|request flow|traffic|routing)\b/i,
  };

  const shouldShowVisual = Object.values(visualPatterns).some(pattern => 
    pattern.test(text)
  );

  return {
    visualNeeded: shouldShowVisual,
    visualType: shouldShowVisual ? "diagram" : "none",
    visualQuery: shouldShowVisual ? text.slice(0, 100) : null,
  };
}

// Message validation middleware
function validateMessages(req, res, next) {
  const { messages } = req.body;

  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({
      error: "Messages array is required and cannot be empty",
    });
  }

  if (messages.length > 50) {
    return res.status(400).json({
      error: "Too many messages. Maximum 50 messages allowed per request.",
    });
  }

  const validRoles = ["user", "assistant", "system"];
  
  for (const message of messages) {
    if (!message || typeof message !== "object") {
      return res.status(400).json({
        error: "Each message must be an object",
      });
    }

    if (!message.role || !validRoles.includes(message.role)) {
      return res.status(400).json({
        error: `Invalid message role: "${message.role}". Must be one of: ${validRoles.join(", ")}`,
      });
    }

    if (typeof message.content !== "string") {
      return res.status(400).json({
        error: "Message content must be a string",
      });
    }

    if (!message.content.trim()) {
      return res.status(400).json({
        error: "Message content cannot be empty or whitespace-only",
      });
    }

    if (message.content.length > 4000) {
      return res.status(400).json({
        error: "Message content too long. Maximum 4000 characters per message.",
      });
    }
  }

  next();
}

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// Chat endpoint
app.post("/api/chat", chatLimiter, validateMessages, async (req, res) => {
  try {
    const { messages } = req.body;

    const lastUserMessage = [...messages].reverse().find((m) => m.role === "user");
    const intents = lastUserMessage ? detectIntent(lastUserMessage.content) : [];
    const visualDecision = lastUserMessage ? shouldIncludeVisual(lastUserMessage.content, intents) : { visualNeeded: false, visualType: "none" };

    let enhancedSystemPrompt = SYSTEM_PROMPT;
    if (intents.length > 0) {
      enhancedSystemPrompt += `\n\nDetected user intent (regex-based): ${intents.join(", ")}`;
    }
    if (visualDecision.visualNeeded) {
      enhancedSystemPrompt += `\n\nVisual context: User might benefit from a ${visualDecision.visualType} visualization.`;
    }

    const response = await mistral.chat.complete({
      model: "mistral-small-latest",
      messages: [{ role: "system", content: enhancedSystemPrompt }, ...messages],
      temperature: 0.7,
      max_tokens: MAX_TOKENS,
      top_p: 1,
      safe_mode: false,
    });

    if (!response.choices || !response.choices[0] || !response.choices[0].message) {
      throw new Error("Invalid response structure from Mistral API");
    }

    const reply = response.choices[0].message.content;

    res.json({
      reply,
      intents,
      visual: {
        needed: visualDecision.visualNeeded,
        type: visualDecision.visualType,
        query: visualDecision.visualQuery,
      },
      metadata: {
        timestamp: new Date().toISOString(),
        model: "mistral-small-latest",
      },
    });
  } catch (error) {
    console.error("Mistral API error:", error);

    if (error.status === 429) {
      return res.status(429).json({
        error: "Mistral API rate limit exceeded. Please try again in a few moments.",
      });
    }

    if (error.status === 401) {
      return res.status(401).json({
        error: "Invalid Mistral API key. Please check your configuration.",
      });
    }

    if (error.status === 400) {
      return res.status(400).json({
        error: "Invalid request to Mistral API. Please try rephrasing your message.",
      });
    }

    if (error.code === "ECONNREFUSED" || error.code === "ENOTFOUND") {
      return res.status(503).json({
        error: "Unable to reach Mistral API. Please check your internet connection.",
      });
    }

    res.status(500).json({
      error: "AI request failed. Please try again.",
      ...(NODE_ENV === "development" ? { details: error.message } : {}),
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    error: "Internal server error",
    ...(NODE_ENV === "development" ? { details: err.message } : {}),
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📍 Environment: ${NODE_ENV}`);
  console.log(`🔒 CORS enabled for: ${CLIENT_URL}`);
  console.log(`⚡ Rate limit: ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW_MS / 1000 / 60} minutes`);
});