/**
 * ToolPolicy
 *
 * Central authorization gate.
 *
 * Phase 1 permits only read-only tools. Controller-enforced execution
 * is therefore also restricted to tools with riskLevel === "read".
 */

class ToolPolicy {
  constructor(options = {}) {
    this.allowedRiskLevels = Array.isArray(
      options.allowedRiskLevels
    )
      ? options.allowedRiskLevels
      : ["read"];
  }

  check({ tool, userContext, input }) {
    if (!tool) {
      return {
        allowed: false,
        reason: "tool not registered",
      };
    }

    if (!this.allowedRiskLevels.includes(tool.riskLevel)) {
      return {
        allowed: false,
        reason: `risk level "${tool.riskLevel}" not permitted`,
      };
    }

    if (tool.requiresApproval) {
      return {
        allowed: false,
        reason: "tool requires explicit approval",
      };
    }

    return {
      allowed: true,
      reason: `read-only ${tool.category || "security"} tool`,
    };
  }
}

module.exports = ToolPolicy;
