/**
 * AgentAuditLogger
 *
 * Small CommonJS audit facade used by the agent layer.
 *
 * Phase 3 additions:
 * - Investigation lifecycle events
 * - Target normalization events
 * - Tool selection events
 * - Tool result/status events
 * - Reasoning metadata events
 *
 * Security:
 * - Never logs authorization headers, API keys, tokens,
 *   secrets, passwords, cookies, or secret-like fields.
 * - Payloads are recursively redacted before logging.
 * - No raw provider credentials are accepted or emitted.
 */

const SECRET_KEYS =
  /^(authorization|api[-_]?key|token|secret|password|cookie|x-api-key)$/i;

const SECRET_NAME_PATTERN =
  /(authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|password|cookie|secret)/i;

function redact(value, depth = 0) {
  if (depth > 6) {
    return "[redacted-depth]";
  }

  if (Array.isArray(value)) {
    return value.map((item) =>
      redact(item, depth + 1)
    );
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const out = {};

  for (const [key, child] of Object.entries(value)) {
    if (
      SECRET_KEYS.test(key) ||
      SECRET_NAME_PATTERN.test(key)
    ) {
      out[key] = "[REDACTED]";
      continue;
    }

    out[key] = redact(
      child,
      depth + 1
    );
  }

  return out;
}

function safePayload(payload) {
  if (
    payload === undefined ||
    payload === null
  ) {
    return {};
  }

  if (
    typeof payload !== "object"
  ) {
    return {
      value: payload,
    };
  }

  return redact(payload);
}

class AgentAuditLogger {
  constructor({
    enabled = true,
    prefix = "agent",
    logger = console,
  } = {}) {
    this.enabled = enabled;
    this.prefix = prefix;
    this.logger = logger;
  }

  _emit(event, payload = {}) {
    if (!this.enabled) {
      return;
    }

    const record = {
      ts: new Date().toISOString(),
      event,
      ...safePayload(payload),
    };

    const line =
      `[${this.prefix}] ` +
      JSON.stringify(record);

    if (
      this.logger &&
      typeof this.logger.log === "function"
    ) {
      this.logger.log(line);
    }
  }

  /*
   * -------------------------------------------------------
   * EXISTING AGENT EVENTS
   * -------------------------------------------------------
   */

  agentStarted(payload) {
    this._emit(
      "agent_started",
      payload
    );
  }

  iteration(payload) {
    this._emit(
      "agent_iteration",
      payload
    );
  }

  policyDecision(payload) {
    this._emit(
      "policy_decision",
      payload
    );
  }

  validationFailed(payload) {
    this._emit(
      "tool_validation",
      {
        ...payload,
        valid: false,
      }
    );
  }

  toolRequested(payload) {
    this._emit(
      "agent_tool_requested",
      payload
    );
  }

  toolStarted(payload) {
    this._emit(
      "agent_tool_started",
      payload
    );
  }

  toolCompleted(payload) {
    this._emit(
      "tool_completed",
      payload
    );
  }

  toolFailed(payload) {
    this._emit(
      "agent_tool_failed",
      payload
    );
  }

  agentError(payload) {
    this._emit(
      "agent_error",
      payload
    );
  }

  agentFinished(payload) {
    this._emit(
      "agent_finished",
      payload
    );
  }

  /*
   * -------------------------------------------------------
   * PHASE 3 — INVESTIGATION EVENTS
   * -------------------------------------------------------
   */

  investigationStarted(payload) {
    this._emit(
      "investigation_started",
      payload
    );
  }

  investigationTargetNormalized(payload) {
    this._emit(
      "investigation_target_normalized",
      payload
    );
  }

  investigationPlanCreated(payload) {
    this._emit(
      "investigation_plan_created",
      payload
    );
  }

  investigationToolsSelected(payload) {
    this._emit(
      "investigation_tools_selected",
      payload
    );
  }

  investigationToolRequested(payload) {
    this._emit(
      "investigation_tool_requested",
      payload
    );
  }

  investigationToolStarted(payload) {
    this._emit(
      "investigation_tool_started",
      payload
    );
  }

  investigationToolCompleted(payload) {
    this._emit(
      "investigation_tool_completed",
      payload
    );
  }

  investigationToolFailed(payload) {
    this._emit(
      "investigation_tool_failed",
      payload
    );
  }

  investigationEvidenceNormalized(payload) {
    this._emit(
      "investigation_evidence_normalized",
      payload
    );
  }

  investigationReasoning(payload) {
    this._emit(
      "investigation_reasoning",
      payload
    );
  }

  investigationCompleted(payload) {
    this._emit(
      "investigation_completed",
      payload
    );
  }

  investigationError(payload) {
    this._emit(
      "investigation_error",
      payload
    );
  }

  /*
   * -------------------------------------------------------
   * PHASE 3 — SECURITY REASONING
   * -------------------------------------------------------
   *
   * These events should contain structured metadata only.
   * They must not contain hidden chain-of-thought.
   */

  reasoningStarted(payload) {
    this._emit(
      "security_reasoning_started",
      payload
    );
  }

  reasoningCompleted(payload) {
    this._emit(
      "security_reasoning_completed",
      payload
    );
  }

  /*
   * -------------------------------------------------------
   * GENERIC INVESTIGATION STATUS
   * -------------------------------------------------------
   */

  investigationStatus(payload) {
    this._emit(
      "investigation_status",
      payload
    );
  }
}

module.exports = AgentAuditLogger;