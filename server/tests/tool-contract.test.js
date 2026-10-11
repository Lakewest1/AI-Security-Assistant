const test = require("node:test");
const assert = require("node:assert/strict");

const ToolRegistry = require("../agent/ToolRegistry");
const ToolValidator = require("../agent/ToolValidator");
const ToolPolicy = require("../agent/ToolPolicy");
const AgentLoop = require("../agent/AgentLoop");
const { createTrustedCapabilityContext } = require("../agent/CapabilityContext");
const securityToolFactories = [
  ["virustotal_ip_lookup", () => require("../tools/external/virustotal").createVirusTotalTool({})],
  ["abuseipdb_ip_lookup", () => require("../tools/external/abuseipdb").createAbuseIPDBTool({})],
  ["urlscan_lookup", () => require("../tools/external/urlscan").createURLScanTool({})],
  ["shodan_ip_lookup", () => require("../tools/external/shodan").createShodanTool({})],
  ["ipinfo_ip_lookup", () => require("../tools/external/ipinfo").createIPInfoTool({})],
  ["censys_ip_lookup", () => require("../tools/external/censys").createCensysTool({})],
  ["securitytrails_lookup", () => require("../tools/external/securitytrails").createSecurityTrailsTool({})],
  ["mozilla_observatory_scan", () => require("../tools/external/mozilla-observatory").createMozillaObservatoryTool({})],
  ["viewdns_lookup", () => require("../tools/external/viewdns").createViewDNSTool({})],
  ["hibp_lookup", () => require("../tools/external/hibp").createHIBPTool({})],
  ["google_web_risk_lookup", () => require("../tools/external/google-web-risk").createGoogleWebRiskTool({})],
  ["urlhaus_lookup", () => require("../tools/external/urlhaus").createURLhausTool({})],
  ["phishing_database", () => require("../tools/external/phishing-database").createPhishingDatabaseTool({})],
  ["threatfox_lookup", () => require("../tools/external/threatfox").createThreatFoxTool({})],
];

function makeState(overrides = {}) {
  return {
    requiredTools: [],
    requiredToolArguments: {},
    attemptedRequiredTools: [],
    completedRequiredTools: [],
    rawToolEvidence: [],
    toolResults: [],
    toolsUsed: [],
    executedToolCalls: [],
    executedToolFingerprints: new Set(),
    sameToolCounts: new Map(),
    toolCallCount: 0,
    deadline: Date.now() + 1000,
    startedAt: Date.now(),
    ...overrides,
  };
}

function makeLoop({ tool, toolTimeoutMs = 100 } = {}) {
  const toolRegistry = new ToolRegistry();
  if (tool) toolRegistry.register(tool);
  return new AgentLoop({
    toolRegistry,
    toolValidator: new ToolValidator(),
    toolPolicy: new ToolPolicy(),
    toolTimeoutMs,
  });
}

const schema = {
  type: "object",
  properties: { query: { type: "string", minLength: 1, maxLength: 20 } },
  required: ["query"],
  additionalProperties: false,
};

test("registry registers and resolves a valid tool with normalized defaults", () => {
  const registry = new ToolRegistry();
  const execute = async () => ({ ok: true, status: "success" });
  const tool = registry.register({ name: "fixture_lookup", inputSchema: schema, execute });
  assert.equal(registry.get("fixture_lookup"), tool);
  assert.equal(registry.has("fixture_lookup"), true);
  assert.equal(tool.riskLevel, "read");
  assert.equal(tool.execute, execute);
  assert.equal(registry.getDefinitions()[0].input_schema, schema);
});

test("registry rejects duplicate and invalid tool identifiers", () => {
  const registry = new ToolRegistry();
  registry.register({ name: "fixture_lookup", execute: async () => ({}) });
  assert.throws(() => registry.register({ name: "fixture_lookup", execute: async () => ({}) }), /already registered/);
  assert.throws(() => registry.register({ name: "bad risk", riskLevel: "admin", execute: async () => ({}) }), /invalid riskLevel/);
});

test("Security provider factories retain their canonical factory IDs and input schemas", () => {
  for (const [registeredId, makeTool] of securityToolFactories) {
    const tool = makeTool();
    assert.equal(tool.name, registeredId);
    assert.equal(typeof tool.execute, "function");
    if (registeredId === "mozilla_observatory_scan") {
      assert.equal(tool.riskLevel, "write");
      assert.equal(tool.requiredCapability, "security_remote_scan");
      assert.equal(tool.requiresApproval, true);
    } else {
      assert.equal(tool.riskLevel, "read");
    }
    assert.equal(tool.inputSchema?.type, "object");
    assert.equal(typeof tool.inputSchema.properties, "object");
    if (registeredId === "phishing_database") {
      assert.equal(Array.isArray(tool.inputSchema.required), false);
      assert.equal(Number.isInteger(tool.inputSchema.minProperties), false);
    }
    assert.doesNotThrow(() => new ToolRegistry().register(tool));
  }
});

test("unknown and invalid tools do not execute", async () => {
  let executions = 0;
  const loop = makeLoop({ tool: { name: "fixture_lookup", inputSchema: schema, execute: async () => { executions += 1; return {}; } } });
  const unknown = await loop._executeTool({ state: makeState(), toolName: "not_registered", input: {}, toolCallId: "unknown", requestId: "fixture", userContext: {} });
  const invalid = await loop._executeTool({ state: makeState(), toolName: "fixture_lookup", input: { query: "", extra: true }, toolCallId: "invalid", requestId: "fixture", userContext: {} });
  assert.equal(unknown.evidence.error.code, "UNKNOWN_TOOL");
  assert.equal(invalid.evidence.error.code, "INVALID_TOOL_ARGUMENTS");
  assert.equal(executions, 0);
});

test("policy denies disallowed risk levels and approval-required tools", () => {
  const policy = new ToolPolicy();
  assert.equal(policy.check({ tool: { riskLevel: "write" }, userContext: {}, input: {} }).allowed, false);
  assert.equal(policy.check({ tool: { riskLevel: "read", requiresApproval: true }, userContext: {}, input: {} }).allowed, false);
});

test("required capabilities fail closed for missing, malformed, or ungranted context", () => {
  const policy = new ToolPolicy();
  const tool = { riskLevel: "read", requiredCapability: "web_search" };
  for (const userContext of [undefined, {}, { capabilities: null }, { capabilities: "web_search" }, { capabilities: [] }]) {
    assert.equal(policy.check({ tool, userContext, input: {} }).allowed, false);
  }
  assert.equal(policy.check({
    tool,
    userContext: createTrustedCapabilityContext({
      principalId: "trusted-fixture",
      capabilities: ["web_search"],
      expiresAt: Date.now() + 60_000,
    }),
    input: {},
  }).allowed, true);
});

test("execution preserves structured provider results as Security evidence", async () => {
  const output = { ok: true, success: true, provider: "fixture", status: "success", collectedAt: "2026-01-01T00:00:00.000Z", findings: { malicious: 2 }, evidence: [{ source: "fixture", url: "https://example.invalid/report" }] };
  const loop = makeLoop({ tool: { name: "fixture_lookup", inputSchema: schema, riskLevel: "read", execute: async () => output } });
  const state = makeState();
  const result = await loop._executeTool({ state, toolName: "fixture_lookup", input: { query: "sample" }, toolCallId: "ok", requestId: "fixture", userContext: {} });
  assert.equal(result.ok, true);
  assert.deepEqual(result.evidence.output, output);
  assert.deepEqual(JSON.parse(result.toolResult.content), output);
  assert.equal(state.rawToolEvidence[0], result.evidence);
});

test("duplicate successful calls reuse the original evidence", async () => {
  let executions = 0;
  const loop = makeLoop({ tool: { name: "fixture_lookup", inputSchema: schema, execute: async () => { executions += 1; return { ok: true, status: "success", findings: { count: 1 } }; } } });
  const state = makeState();
  const args = { state, toolName: "fixture_lookup", input: { query: "same" }, requestId: "fixture", userContext: {} };
  await loop._executeTool({ ...args, toolCallId: "one" });
  const duplicate = await loop._executeTool({ ...args, toolCallId: "two" });
  assert.equal(duplicate.reused, true);
  assert.equal(executions, 1);
  assert.equal(state.rawToolEvidence.length, 1);
});

test("timeout and provider failure become bounded, structured evidence errors", async () => {
  const timeoutLoop = makeLoop({ toolTimeoutMs: 5, tool: { name: "fixture_lookup", inputSchema: schema, execute: async () => new Promise(() => {}) } });
  const timeout = await timeoutLoop._executeTool({ state: makeState(), toolName: "fixture_lookup", input: { query: "wait" }, toolCallId: "timeout", requestId: "fixture", userContext: {} });
  assert.equal(timeout.ok, false);
  assert.equal(timeout.evidence.error.code, "TIMEOUT");
  assert.equal(timeout.toolResult.is_error, true);

  const failureLoop = makeLoop({ tool: { name: "fixture_lookup", inputSchema: schema, execute: async () => { throw Object.assign(new Error("fixture unavailable"), { status: 503 }); } } });
  const failed = await failureLoop._executeTool({ state: makeState(), toolName: "fixture_lookup", input: { query: "fail" }, toolCallId: "failure", requestId: "fixture", userContext: {} });
  assert.equal(failed.ok, false);
  assert.equal(failed.evidence.error.code, "UPSTREAM_ERROR");
});

test("failure-shaped provider results preserve status without claiming success", async () => {
  const output = { ok: false, success: false, provider: "fixture", status: "rate_limited", message: "Try later", findings: {}, evidence: [] };
  const loop = makeLoop({ tool: { name: "fixture_lookup", inputSchema: schema, execute: async () => output } });
  const result = await loop._executeTool({ state: makeState(), toolName: "fixture_lookup", input: { query: "limit" }, toolCallId: "rate-limit", requestId: "fixture", userContext: {} });
  assert.equal(result.ok, false);
  assert.equal(result.evidence.error.code, "RATE_LIMITED");
  assert.equal(result.evidence.error.message, "Try later");
});
