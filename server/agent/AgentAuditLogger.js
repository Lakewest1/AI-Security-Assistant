/**
 * AgentAuditLogger
 *
 * Small CommonJS audit facade used by the agent layer. It never accepts or
 * prints authorization headers, API keys, tokens, or secret-like fields.
 */

const SECRET_KEYS = /^(authorization|api[-_]?key|token|secret|password|cookie|x-api-key)$/i;

function redact(value, depth = 0) {
  if (depth > 6) return "[redacted-depth]";
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    out[key] = SECRET_KEYS.test(key) ? "[REDACTED]" : redact(child, depth + 1);
  }
  return out;
}

class AgentAuditLogger {
  constructor({ enabled = true, prefix = "agent", logger = console } = {}) {
    this.enabled = enabled;
    this.prefix = prefix;
    this.logger = logger;
  }

  _emit(event, payload = {}) {
    if (!this.enabled) return;
    const record = { ts: new Date().toISOString(), event, ...redact(payload) };
    const line = `[${this.prefix}] ${JSON.stringify(record)}`;
    if (this.logger && typeof this.logger.log === "function") this.logger.log(line);
  }

  agentStarted(p) { this._emit("agent_started", p); }
  iteration(p) { this._emit("agent_iteration", p); }
  policyDecision(p) { this._emit("policy_decision", p); }
  validationFailed(p) { this._emit("tool_validation", { ...p, valid: false }); }
  toolRequested(p) { this._emit("agent_tool_requested", p); }
  toolStarted(p) { this._emit("agent_tool_started", p); }
  toolCompleted(p) { this._emit("tool_completed", p); }
  toolFailed(p) { this._emit("agent_tool_failed", p); }
  agentError(p) { this._emit("agent_error", p); }
  agentFinished(p) { this._emit("agent_finished", p); }
}

module.exports = AgentAuditLogger;
