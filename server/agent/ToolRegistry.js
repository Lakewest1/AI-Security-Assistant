/**
 * ToolRegistry
 *
 * Central source of truth for agent tools.
 * Provider adapters receive only provider-neutral public definitions.
 * Tool implementations remain server-side.
 */

class ToolRegistry {
  constructor() {
    this.tools = new Map();
  }

  register(tool) {
    if (!tool || typeof tool !== "object") {
      throw new Error(
        "ToolRegistry.register: tool must be an object"
      );
    }

    if (!tool.name || typeof tool.name !== "string") {
      throw new Error(
        "ToolRegistry.register: tool.name is required"
      );
    }

    if (typeof tool.execute !== "function") {
      throw new Error(
        `ToolRegistry.register: tool "${tool.name}" must have an execute() function`
      );
    }

    if (this.tools.has(tool.name)) {
      throw new Error(
        `ToolRegistry.register: tool "${tool.name}" already registered`
      );
    }

    const inputSchema =
      tool.inputSchema ||
      tool.input_schema || {
        type: "object",
        properties: {},
        additionalProperties: false,
      };

    const normalized = {
      name: tool.name,
      description: tool.description || "",
      inputSchema,
      category: tool.category || "general",
      targetTypes: Array.isArray(tool.targetTypes) ? [...tool.targetTypes] : [],
      readOnly: (tool.riskLevel || "read") === "read",
      destructive: (tool.riskLevel || "read") === "destructive",
      riskLevel: tool.riskLevel || "read",
      requiresApproval: Boolean(tool.requiresApproval),
      timeout: Number(tool.timeout) || null,
      retryable: tool.retryable !== false,
      execute: tool.execute,
    };

    if (
      !["read", "write", "destructive"].includes(
        normalized.riskLevel
      )
    ) {
      throw new Error(
        `ToolRegistry.register: invalid riskLevel for "${tool.name}"`
      );
    }

    this.tools.set(normalized.name, normalized);
    return normalized;
  }

  get(name) {
    return this.tools.get(name) || null;
  }

  has(name) {
    return this.tools.has(name);
  }

  list() {
    return Array.from(this.tools.values());
  }

  getDefinitions() {
    return this.list().map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.inputSchema,
    }));
  }
}

module.exports = ToolRegistry;
