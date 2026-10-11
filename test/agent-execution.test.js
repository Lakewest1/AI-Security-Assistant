const test = require("node:test");
const assert = require("node:assert/strict");

const AgentLoop = require("../server/agent/AgentLoop");
const AgentOrchestrator = require("../server/agent/AgentOrchestrator");
const ToolRegistry = require("../server/agent/ToolRegistry");
const ToolPolicy = require("../server/agent/ToolPolicy");
const ToolValidator = require("../server/agent/ToolValidator");
const {
  extractIPv4,
  resolveRequiredTools,
} = require("../server/agent/RequiredToolResolver");

function logger() {
  return {
    events: [],
    _emit(event, payload) {
      this.events.push({ event, payload });
    },
    agentStarted(payload) {
      this._emit("agent_started", payload);
    },
    iteration(payload) {
      this._emit("agent_iteration", payload);
    },
    policyDecision(payload) {
      this._emit("agent_tool_policy", payload);
    },
    validationFailed(payload) {
      this._emit("agent_tool_denied", payload);
    },
    toolStarted(payload) {
      this._emit("agent_tool_started", payload);
    },
    toolCompleted(payload) {
      this._emit("agent_tool_succeeded", payload);
    },
    toolFailed(payload) {
      this._emit("agent_tool_failed", payload);
    },
  };
}

function buildLoop(toolExecute) {
  const registry = new ToolRegistry();

  registry.register({
    name: "virustotal_ip_lookup",
    description:
      "Look up threat-intelligence information for an IPv4 address using VirusTotal.",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IPv4 address to investigate",
          format: "ipv4",
        },
      },
      required: ["ip"],
      additionalProperties: false,
    },
    category: "threat-intelligence",
    riskLevel: "read",
    requiresApproval: false,
    execute: toolExecute,
  });

  return {
    registry,
    logger: logger(),
    loop: new AgentLoop({
      toolRegistry: registry,
      toolPolicy: new ToolPolicy(),
      toolValidator: new ToolValidator(),
      auditLogger: logger(),
      maxIterations: 8,
      agentTimeoutMs: 45000,
      toolTimeoutMs: 1000,
      maxToolCalls: 12,
      maxSameToolCalls: 3,
    }),
  };
}

test("extractIPv4 extracts an arbitrary valid IPv4", () => {
  assert.equal(
    extractIPv4(
      "investigate this ip: 185.220.101.34"
    ),
    "185.220.101.34"
  );
});

test("required-tool resolver identifies an IP investigation", () => {
  const result = resolveRequiredTools([
    {
      role: "user",
      content:
        "investigate this ip : 185.220.101.34",
    },
  ]);

  assert.ok(result.requiredTools.includes("virustotal_ip_lookup"));
  assert.deepEqual(
    result.requiredToolArguments.virustotal_ip_lookup,
    { ip: "185.220.101.34" }
  );
});

test("controller recovery prevents generic end_turn from succeeding", async () => {
  let calls = 0;

  const { registry } = buildLoop(async (input) => {
    calls += 1;
    return {
      ok: true,
      evidence: {
        ip: input.ip,
        malicious: 0,
        suspicious: 0,
        harmless: 90,
        undetected: 10,
        reputation: 0,
        lastAnalysis: "test",
      },
    };
  });

  const audit = logger();

  const loop = new AgentLoop({
    toolRegistry: registry,
    toolPolicy: new ToolPolicy(),
    toolValidator: new ToolValidator(),
    auditLogger: audit,
    maxIterations: 8,
    agentTimeoutMs: 45000,
    toolTimeoutMs: 1000,
    maxToolCalls: 12,
    maxSameToolCalls: 3,
  });

  let providerCalls = 0;

  const provider = {
    name: "Groq",
    type: "openai-compatible",
    async callWithTools() {
      providerCalls += 1;

      if (providerCalls <= 2) {
        return {
          reply:
            "I’m ready to help. Please provide the IP address.",
          content: [
            {
              type: "text",
              text:
                "I’m ready to help. Please provide the IP address.",
            },
          ],
          provider: "Groq",
          model: "openai/gpt-oss-120b",
          stopReason: "end_turn",
        };
      }

      return {
        reply: "Investigation completed from the supplied evidence.",
        content: [
          {
            type: "text",
            text:
              "Investigation completed from the supplied evidence.",
          },
        ],
        provider: "Groq",
        model: "openai/gpt-oss-120b",
        stopReason: "end_turn",
      };
    },
  };

  const state = {
    conversation: [
      {
        role: "user",
        content:
          "investigate this ip : 185.220.101.34",
      },
    ],
    messages: null,
    providerAttempts: [],
    toolsUsed: [],
    toolResults: [],
    executedToolCalls: [],
    iteration: 0,
    toolCallCount: 0,
    requiredTools: ["virustotal_ip_lookup"],
    requiredToolArguments: {
      virustotal_ip_lookup: {
        ip: "185.220.101.34",
      },
    },
    completedRequiredTools: [],
    toolExpectedButNotCalled: false,
    startedAt: Date.now(),
    deadline: Date.now() + 45000,
    terminationReason: null,
    executedToolFingerprints: new Set(),
    sameToolCounts: new Map(),
    requiredToolRetryUsed: false,
  };
  state.messages = state.conversation;

  const result = await loop.run({
    sharedState: state,
    systemPrompt: "Use tools for investigations.",
    agentProvider: provider,
    providerOptions: {
      model: "openai/gpt-oss-120b",
      maxTokens: 1000,
    },
    requestId: "test-request",
  });

  assert.equal(calls, 1);
  assert.equal(
    state.toolExpectedButNotCalled,
    false
  );
  assert.deepEqual(state.toolsUsed, [
    "virustotal_ip_lookup",
  ]);
  assert.deepEqual(
    state.completedRequiredTools,
    ["virustotal_ip_lookup"]
  );
  assert.equal(result.stopReason, "end_turn");
});

test("Claude invalid-key authentication failure fails over to Groq using the same state", async () => {
  let toolCalls = 0;

  const registry = new ToolRegistry();
  registry.register({
    name: "virustotal_ip_lookup",
    description:
      "Look up threat-intelligence information for an IPv4 address using VirusTotal.",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          format: "ipv4",
        },
      },
      required: ["ip"],
      additionalProperties: false,
    },
    riskLevel: "read",
    execute: async (input) => {
      toolCalls += 1;
      return {
        ok: true,
        evidence: {
          ip: input.ip,
          malicious: 1,
        },
      };
    },
  });

  const loop = new AgentLoop({
    toolRegistry: registry,
    toolPolicy: new ToolPolicy(),
    toolValidator: new ToolValidator(),
    auditLogger: logger(),
  });

  let groqReceivedToolResult = false;

  const claude = {
    name: "Claude",
    type: "anthropic",
    models: { balanced: "claude-3-5-sonnet-latest" },
    async callWithTools() {
      throw Object.assign(
        new Error("API key is invalid"),
        {
          status: 401,
          category: "authentication",
        }
      );
    },
  };

  const groq = {
    name: "Groq",
    type: "openai-compatible",
    models: { balanced: "openai/gpt-oss-120b" },
    async callWithTools({ messages }) {
      groqReceivedToolResult = messages.some(
        (message) =>
          message.role === "tool" &&
          message.tool_call_id
      );

      if (!groqReceivedToolResult) {
        return {
          reply: "",
          content: [
            {
              type: "tool_use",
              id: "call_test",
              name: "virustotal_ip_lookup",
              input: {
                ip: "185.220.101.34",
              },
            },
          ],
          provider: "Groq",
          model: "openai/gpt-oss-120b",
          stopReason: "tool_use",
        };
      }

      return {
        reply: "Final investigation response.",
        content: [
          {
            type: "text",
            text: "Final investigation response.",
          },
        ],
        provider: "Groq",
        model: "openai/gpt-oss-120b",
        stopReason: "end_turn",
      };
    },
  };

  const orchestrator = new AgentOrchestrator({
    toolRegistry: registry,
    toolPolicy: new ToolPolicy(),
    toolValidator: new ToolValidator(),
    auditLogger: logger(),
    agentLoop: loop,
    agentProviders: [claude, groq],
    agentProviderOptions: {
      model: "claude-3-5-sonnet-latest",
      maxTokens: 1000,
    },
  });

  const result = await orchestrator.run({
    messages: [
      {
        role: "user",
        content:
          "investigate this ip : 185.220.101.34",
      },
    ],
    systemPrompt: "Investigate security targets using tools.",
    requestId: "failover-test",
  });

  assert.equal(result.provider, "Groq");
  assert.deepEqual(result.metadata.toolsUsed, [
    "virustotal_ip_lookup",
  ]);
  assert.equal(toolCalls, 1);
});

test("partial required-provider availability returns a scoped investigation instead of failing", async () => {
  const requiredTools = [
    "virustotal_ip_lookup",
    "abuseipdb_ip_lookup",
    "shodan_ip_lookup",
    "ipinfo_ip_lookup",
    "censys_ip_lookup",
    "viewdns_lookup",
  ];
  const availableTools = requiredTools.slice(0, 3);
  const orchestrator = new AgentOrchestrator({
    auditLogger: logger(),
    requiredToolResolver: () => ({
      requiredTools,
      targets: [{ type: "ipv4", value: "197.210.29.24", valid: true }],
      investigationType: "ipv4",
      requiredToolArguments: {},
    }),
    agentLoop: {
      async run({ sharedState }) {
        sharedState.attemptedRequiredTools.push(...availableTools);
        sharedState.completedRequiredTools.push(...availableTools);
        sharedState.rawToolEvidence.push({
          ok: true,
          toolName: "virustotal_ip_lookup",
          output: { status: "success", findings: { malicious: 0, suspicious: 0 } },
        });
        return {
          reply: "Partial provider coverage; available evidence was assessed.",
          provider: "Groq",
          model: "openai/gpt-oss-120b",
          stopReason: "end_turn",
          iterations: 1,
          toolsUsed: availableTools,
        };
      },
    },
    agentProviders: [{
      name: "Groq",
      models: { balanced: "openai/gpt-oss-120b" },
      async callWithTools() { throw new Error("The mocked loop owns provider execution"); },
    }],
  });

  const result = await orchestrator.run({
    messages: [{ role: "user", content: "Investigate 197.210.29.24" }],
    systemPrompt: "Investigate the current target.",
    requestId: "partial-provider-test",
  });

  assert.equal(result.provider, "Groq");
  assert.equal(result.investigation.target, "197.210.29.24");
  assert.equal(result.investigation.risk.environmentalRisk, "unknown");
  assert.deepEqual(result.completedRequiredTools, availableTools);
  assert.deepEqual(result.missingRequiredTools, requiredTools.slice(3));
  assert.ok(result.investigation.limitations.some((line) => line.includes("not attempted")));
});

test("all LLM providers may fail after collection and still return deterministic investigation evidence", async () => {
  const tools = ["virustotal_ip_lookup", "abuseipdb_ip_lookup"];
  let evidenceRecorded = false;
  const orchestrator = new AgentOrchestrator({
    auditLogger: logger(),
    requiredToolResolver: () => ({
      requiredTools: tools,
      targets: [{ type: "ipv4", value: "94.240.240.229", valid: true }],
      investigationType: "ipv4",
      requiredToolArguments: {},
    }),
    agentLoop: {
      async run({ sharedState }) {
        if (!evidenceRecorded) {
          sharedState.attemptedRequiredTools.push(...tools);
          sharedState.completedRequiredTools.push("virustotal_ip_lookup");
          sharedState.rawToolEvidence.push({
            ok: true,
            toolName: "virustotal_ip_lookup",
            output: { status: "success", findings: { malicious: 3, suspicious: 0 } },
          });
          evidenceRecorded = true;
        }
        throw Object.assign(new Error("Mock LLM authentication failure"), { status: 401, category: "authentication" });
      },
    },
    agentProviders: ["Claude", "Groq"].map((name) => ({
      name,
      models: { balanced: name === "Groq" ? "openai/gpt-oss-120b" : "claude-test" },
      async callWithTools() { throw new Error("AgentLoop mock should handle this call"); },
    })),
  });

  const result = await orchestrator.run({
    messages: [{ role: "user", content: "Investigate 94.240.240.229" }],
    systemPrompt: "Investigate the current target.",
    requestId: "llm-fallback-test",
  });

  assert.equal(result.reasoningStatus, "fallback");
  assert.equal(result.investigation.target, "94.240.240.229");
  assert.equal(result.investigation.risk.environmentalRisk, "unknown");
  assert.equal(result.rawToolEvidence.length, 1);
  assert.match(result.reply, /AI reasoning was unavailable/);
  assert.equal(result.metadata.aiAnalysis, "unavailable");
});

test("ToolValidator rejects invalid IPv4 values", () => {
  const validator = new ToolValidator();

  const tool = {
    name: "virustotal_ip_lookup",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          format: "ipv4",
        },
      },
      required: ["ip"],
      additionalProperties: false,
    },
  };

  assert.equal(
    validator.validate(tool, {
      ip: "999.999.999.999",
    }).valid,
    false
  );

  assert.equal(
    validator.validate(tool, {
      ip: "185.220.101.34",
    }).valid,
    true
  );
});

test("unknown tools are denied and never executed", async () => {
  const { loop } = buildLoop(async () => {
    throw new Error("must not execute");
  });

  const state = {
    conversation: [
      {
        role: "user",
        content: "investigate this ip: 185.220.101.34",
      },
    ],
    messages: null,
    providerAttempts: [],
    toolsUsed: [],
    toolResults: [],
    executedToolCalls: [],
    iteration: 0,
    toolCallCount: 0,
    requiredTools: ["virustotal_ip_lookup"],
    requiredToolArguments: {
      virustotal_ip_lookup: {
        ip: "185.220.101.34",
      },
    },
    completedRequiredTools: [],
    toolExpectedButNotCalled: false,
    startedAt: Date.now(),
    deadline: Date.now() + 45000,
    terminationReason: null,
    executedToolFingerprints: new Set(),
    sameToolCounts: new Map(),
    requiredToolRetryUsed: false,
  };
  state.messages = state.conversation;

  const provider = {
    name: "Groq",
    type: "openai-compatible",
    async callWithTools() {
      return {
        reply: "",
        content: [
          {
            type: "tool_use",
            id: "unknown-1",
            name: "delete_everything",
            input: {},
          },
        ],
        provider: "Groq",
        model: "openai/gpt-oss-120b",
        stopReason: "tool_use",
      };
    },
  };

  await assert.rejects(
    loop.run({
      sharedState: state,
      systemPrompt: "",
      agentProvider: provider,
      providerOptions: {
        model: "openai/gpt-oss-120b",
        maxTokens: 1000,
      },
      requestId: "unknown-tool-test",
    }),
    {
      category: "agent_iteration_limit",
    }
  );
});

test("model tool calls for a previous target are denied and do not satisfy the current provider requirement", async () => {
  let providerCalls = 0;
  const { loop } = buildLoop(async () => {
    providerCalls += 1;
    return { ok: true, findings: { malicious: 0, suspicious: 0 } };
  });
  const state = {
    requiredTools: ["virustotal_ip_lookup"],
    requiredToolArguments: { virustotal_ip_lookup: { ip: "197.210.29.24" } },
    attemptedRequiredTools: [],
    completedRequiredTools: [],
    rawToolEvidence: [],
    toolResults: [],
    target: { type: "ipv4", value: "197.210.29.24" },
    startedAt: Date.now(),
  };
  const result = await loop._executeTool({
    state,
    toolName: "virustotal_ip_lookup",
    input: { ip: "185.220.101.34" },
    toolCallId: "old-target-call",
    requestId: "investigation-current",
    userContext: {},
    iteration: 0,
  });
  assert.equal(result.ok, false);
  assert.equal(providerCalls, 0);
  assert.deepEqual(state.attemptedRequiredTools, []);
  assert.equal(state.rawToolEvidence.length, 0, "a rejected model proposal is not provider evidence");
});
