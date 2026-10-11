"use strict";

const express = require("express");
const rateLimit = require("express-rate-limit");
const { createSupabaseAuthMiddleware, isVerifiedSupabaseIdentity } = require("../auth/SupabaseAuth");
const { createTavilyMcpManager, McpWorkflowError } = require("./tavilyMcpClient");
const { createResearchHandler, validateResearchOptions } = require("./researchWorkflow");
const { checkResearchPrivacy } = require("./researchPrivacy");
const { createResearchConfirmationStore } = require("./researchConfirmation");

const SUPPORTED_MODES = new Set([
  "research",
  "code",
  "build",
  "structure_learn",
]);
const MAX_INPUT_BYTES = 12 * 1024;
const MAX_OPTIONS_BYTES = 16 * 1024;
const MAX_OPTIONS_DEPTH = 8;
const MAX_OPTIONS_NODES = 512;
const RESEARCH_PROVIDER = "Tavily";

function responseEnvelope({ mode = null, status, result = null, sources = [], limitations = [], metadata = {}, error } = {}) {
  const envelope = {
    schemaVersion: 1,
    mode,
    status,
    result,
    sources,
    limitations,
    metadata,
  };
  if (error) envelope.error = error;
  return envelope;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isBoundedJsonObject(value) {
  if (!isPlainObject(value)) return false;

  const pending = [[value, 0]];
  let visited = 0;
  while (pending.length) {
    const [current, depth] = pending.pop();
    if (depth > MAX_OPTIONS_DEPTH) return false;
    visited += 1;
    if (visited > MAX_OPTIONS_NODES) return false;

    const values = Array.isArray(current) ? current : Object.values(current);
    for (const child of values) {
      visited += 1;
      if (visited > MAX_OPTIONS_NODES) return false;
      if (child === null || typeof child === "string" || typeof child === "boolean") continue;
      if (typeof child === "number") {
        if (!Number.isFinite(child)) return false;
        continue;
      }
      if (Array.isArray(child) || isPlainObject(child)) {
        pending.push([child, depth + 1]);
        continue;
      }
      return false;
    }
  }

  try {
    return Buffer.byteLength(JSON.stringify(value), "utf8") <= MAX_OPTIONS_BYTES;
  } catch (_) {
    return false;
  }
}

function validateWorkflowRequest(body) {
  if (!isPlainObject(body)) return { ok: false, code: "INVALID_REQUEST", message: "Request body must be a JSON object." };

  const allowedKeys = new Set(["schemaVersion", "mode", "input", "options"]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key))) {
    return { ok: false, code: "INVALID_REQUEST", message: "Request contains unsupported fields." };
  }
  if (body.schemaVersion !== 1) {
    return { ok: false, code: "INVALID_SCHEMA_VERSION", message: "schemaVersion must be 1." };
  }
  if (typeof body.mode !== "string" || !SUPPORTED_MODES.has(body.mode)) {
    return { ok: false, code: "UNSUPPORTED_MODE", message: "mode must be one of the supported workflow identifiers." };
  }
  if (typeof body.input !== "string" || body.input.trim().length === 0) {
    return { ok: false, code: "INVALID_INPUT", message: "input must be a non-empty string." };
  }
  if (Buffer.byteLength(body.input, "utf8") > MAX_INPUT_BYTES) {
    return { ok: false, status: 413, code: "INPUT_TOO_LARGE", message: "input exceeds the maximum size." };
  }
  if (Object.hasOwn(body, "options")) {
    if (!isPlainObject(body.options)) {
      return { ok: false, code: "INVALID_OPTIONS", message: "options must be a JSON object." };
    }
    if (!isBoundedJsonObject(body.options)) {
      return { ok: false, status: 413, code: "OPTIONS_TOO_LARGE", message: "options exceed the allowed size or structure." };
    }
  }

  return { ok: true, mode: body.mode };
}

function createWorkflowRouter({
  authMiddleware = createSupabaseAuthMiddleware(),
  rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler(_req, res) {
      return res.status(429).json(responseEnvelope({
        status: "error",
        metadata: { executionStatus: "not_started" },
        error: { code: "WORKFLOW_RATE_LIMITED", message: "Too many workflow requests. Try again later." },
      }));
    },
  }),
  researchHandler = createResearchHandler({ manager: createTavilyMcpManager() }),
  confirmationStore = createResearchConfirmationStore(),
} = {}) {
  const router = express.Router();

  function authenticatedUserId(req) {
    return isVerifiedSupabaseIdentity(req.auth) ? req.auth.userId : null;
  }

  function researchResultEnvelope(req, research) {
    return responseEnvelope({
      mode: "research",
      status: research.status,
      result: research.result ?? null,
      sources: research.sources || [],
      limitations: research.limitations || [],
      metadata: {
        requestId: typeof req.id === "string" ? req.id : null,
        executionStatus: research.executionStatus,
      },
      error: research.error,
    });
  }

  router.post("/research/prepare", rateLimiter, authMiddleware, (req, res) => {
    const userId = authenticatedUserId(req);
    if (!userId) {
      return res.status(401).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { executionStatus: "not_started" },
        error: { code: "AUTHENTICATION_REQUIRED", message: "Authentication is required." },
      }));
    }

    const body = req.body;
    if (!isPlainObject(body) || Object.keys(body).some((key) => !["query", "options"].includes(key))
      || typeof body.query !== "string" || body.query.trim().length === 0) {
      return res.status(400).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "INVALID_RESEARCH_PREPARATION", message: "Research preparation request is invalid." },
      }));
    }

    const query = body.query.trim();
    if (Buffer.byteLength(query, "utf8") > 2048 || query.length > 1000) {
      return res.status(413).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_QUESTION_TOO_LARGE", message: "Research question exceeds the maximum size." },
      }));
    }

    const researchOptions = validateResearchOptions(Object.hasOwn(body, "options") ? body.options : {});
    if (!researchOptions.ok) {
      return res.status(400).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: researchOptions.code, message: researchOptions.message },
      }));
    }

    const privacy = checkResearchPrivacy(query, researchOptions.value);
    if (!privacy.allowed) {
      return res.status(400).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_PRIVACY_REJECTED", message: "This request may contain confidential or personal information and was not sent for research." },
      }));
    }

    const prepared = confirmationStore.prepare({
      userId,
      query,
      provider: RESEARCH_PROVIDER,
      options: researchOptions.value,
    });
    if (!prepared) {
      return res.status(503).json(responseEnvelope({
        mode: "research",
        status: "unavailable",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_CONFIRMATION_UNAVAILABLE", message: "Research confirmation could not be prepared." },
      }));
    }

    return res.status(201).json(responseEnvelope({
      mode: "research",
      status: "confirmation_required",
      result: {
        query,
        provider: RESEARCH_PROVIDER,
        maxResults: researchOptions.value.maxResults,
        confirmationId: prepared.id,
        expiresAt: new Date(prepared.expiresAt).toISOString(),
      },
      limitations: ["No provider request has been made. Review this exact query and provider before confirming."],
      metadata: {
        requestId: typeof req.id === "string" ? req.id : null,
        executionStatus: "not_started",
      },
    }));
  });

  router.post("/research/confirm", rateLimiter, authMiddleware, async (req, res) => {
    const userId = authenticatedUserId(req);
    if (!userId) {
      return res.status(401).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { executionStatus: "not_started" },
        error: { code: "AUTHENTICATION_REQUIRED", message: "Authentication is required." },
      }));
    }

    const body = req.body;
    if (!isPlainObject(body)
      || Object.keys(body).some((key) => !["confirmationId", "query", "provider", "confirmed"].includes(key))
      || typeof body.confirmationId !== "string"
      || typeof body.query !== "string"
      || body.query.trim().length === 0
      || body.provider !== RESEARCH_PROVIDER
      || body.confirmed !== true) {
      return res.status(409).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_CONFIRMATION_INVALID", message: "Research confirmation is invalid, expired, or no longer available." },
      }));
    }

    const query = body.query.trim();
    if (Buffer.byteLength(query, "utf8") > 2048 || query.length > 1000) {
      return res.status(409).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_CONFIRMATION_INVALID", message: "Research confirmation is invalid, expired, or no longer available." },
      }));
    }
    const privacy = checkResearchPrivacy(query);
    if (!privacy.allowed) {
      return res.status(409).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_CONFIRMATION_INVALID", message: "Research confirmation is invalid, expired, or no longer available." },
      }));
    }

    // The synchronous store operation checks identity, exact query/provider,
    // expiry, explicit confirmation, and consumes the ID before any await.
    const confirmation = confirmationStore.consume({
      id: body.confirmationId,
      userId,
      query,
      provider: body.provider,
      confirmed: body.confirmed,
    });
    if (!confirmation) {
      return res.status(409).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "not_started" },
        error: { code: "RESEARCH_CONFIRMATION_INVALID", message: "Research confirmation is invalid, expired, or no longer available." },
      }));
    }

    try {
      const research = await researchHandler({
        question: confirmation.query,
        options: confirmation.options,
        signal: req.workflowAbortController?.signal,
      });
      return res.status(research.httpStatus || 200).json(researchResultEnvelope(req, research));
    } catch (_) {
      return res.status(500).json(responseEnvelope({
        mode: "research",
        status: "error",
        metadata: { requestId: typeof req.id === "string" ? req.id : null, executionStatus: "failed" },
        error: { code: "WORKFLOW_REQUEST_FAILED", message: "Workflow request could not be processed." },
      }));
    }
  });

  router.post("/", rateLimiter, authMiddleware, async (req, res) => {
    try {
      const validation = validateWorkflowRequest(req.body);
      const metadata = {
        requestId: typeof req.id === "string" ? req.id : null,
        executionStatus: "not_started",
      };

      if (!validation.ok) {
        const statusCode = validation.status || 400;
        return res.status(statusCode).json(responseEnvelope({
          status: "error",
          metadata,
          error: { code: validation.code, message: validation.message },
        }));
      }

      if (validation.mode === "research") {
        return res.status(409).json(responseEnvelope({
          mode: "research",
          status: "error",
          metadata,
          error: { code: "RESEARCH_CONFIRMATION_REQUIRED", message: "Prepare and confirm a Research query before execution." },
        }));
      }

      return res.status(501).json(responseEnvelope({
        mode: validation.mode,
        status: "not_implemented",
        limitations: ["The requested workflow is not implemented. No workflow execution or external source retrieval occurred."],
        metadata,
      }));
    } catch (_) {
      return res.status(500).json(responseEnvelope({
        status: "error",
        metadata: {
          requestId: typeof req.id === "string" ? req.id : null,
          executionStatus: "not_started",
        },
        error: { code: "WORKFLOW_REQUEST_FAILED", message: "Workflow request could not be processed." },
      }));
    }
  });

  return router;
}

module.exports = {
  createWorkflowRouter,
  validateWorkflowRequest,
  responseEnvelope,
  SUPPORTED_MODES,
  MAX_INPUT_BYTES,
  MAX_OPTIONS_BYTES,
};
