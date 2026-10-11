const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ToolRegistry = require("../agent/ToolRegistry");
const ToolValidator = require("../agent/ToolValidator");
const ToolPolicy = require("../agent/ToolPolicy");
const AgentLoop = require("../agent/AgentLoop");
const {
  createTrustedCapabilityContext,
  createRequestCapabilityResolver,
  getRequestCapabilityContext,
} = require("../agent/CapabilityContext");
const { createSupabaseAuthMiddleware } = require("../auth/SupabaseAuth");
const { createMozillaObservatoryTool } = require("../tools/external/mozilla-observatory");

function invokeMiddleware(middleware, req) {
  const result = { status: 200, body: null, nextCalled: false };
  const res = {
    status(status) { result.status = status; return this; },
    json(body) { result.body = body; return this; },
  };
  return Promise.resolve(middleware(req, res, () => { result.nextCalled = true; })).then(() => result);
}

function makeState() {
  return {
    requiredTools: [], requiredToolArguments: {}, attemptedRequiredTools: [],
    completedRequiredTools: [], rawToolEvidence: [], toolResults: [], toolsUsed: [],
    executedToolCalls: [], executedToolFingerprints: new Set(), sameToolCounts: new Map(),
    toolCallCount: 0, deadline: Date.now() + 1000, startedAt: Date.now(),
  };
}

function makeLoop({ policy = new ToolPolicy(), calls } = {}) {
  const registry = new ToolRegistry();
  const tool = createMozillaObservatoryTool({ timeoutMs: 5 });
  tool.execute = async () => { calls.count += 1; return { ok: true, status: "success" }; };
  registry.register(tool);
  return new AgentLoop({ toolRegistry: registry, toolValidator: new ToolValidator(), toolPolicy: policy, toolTimeoutMs: 50 });
}

async function attempt(loop, { name = "mozilla_observatory_scan", context, id = name } = {}) {
  return loop._executeTool({
    state: makeState(), toolName: name, input: { domain: "example.test" },
    toolCallId: id, requestId: "offline-observatory-test", userContext: context,
  });
}

function grant() {
  return createTrustedCapabilityContext({
    principalId: "authorized-test-principal",
    capabilities: ["security_remote_scan"],
    expiresAt: Date.now() + 60_000,
  });
}

test("Observatory declares write risk, an exact capability, and an unavailable approval prerequisite", () => {
  const tool = createMozillaObservatoryTool();
  assert.equal(tool.riskLevel, "write");
  assert.equal(tool.requiredCapability, "security_remote_scan");
  assert.equal(tool.requiresApproval, true);
});

test("default active policy blocks unauthorized Observatory execution before the side effect", async () => {
  const calls = { count: 0 };
  const loop = makeLoop({ calls });
  const contexts = [
    undefined,
    { capabilities: ["security_remote_scan"], trusted: true },
    { capabilities: "security_remote_scan", consent: true },
    getRequestCapabilityContext({ body: {
      userId: "client-user", role: "admin", capabilities: ["security_remote_scan"], consent: true,
    } }),
  ];

  for (const [index, context] of contexts.entries()) {
    const result = await attempt(loop, { context, id: `unauthorized-${index}` });
    assert.equal(result.evidence.error.code, "TOOL_DENIED");
  }
  assert.equal(calls.count, 0);
});

test("verified Supabase users without an explicit grant cannot initiate a scan", async () => {
  const middleware = createSupabaseAuthMiddleware({ verifyAccessToken: async () => ({ userId: "verified-test-user" }) });
  const req = {
    headers: { authorization: "Bearer fixture-token" },
    body: { userId: "client-user", role: "admin", capabilities: ["security_remote_scan"], consent: true },
  };
  const auth = await invokeMiddleware(middleware, req);
  assert.equal(auth.nextCalled, true);

  const noGrantContext = createRequestCapabilityResolver({ allowlistJson: "{}" })(req);
  const calls = { count: 0 };
  const result = await attempt(makeLoop({ calls }), { context: noGrantContext, id: "authenticated-no-grant" });
  assert.equal(result.evidence.error.code, "TOOL_DENIED");
  assert.equal(calls.count, 0);
});

test("missing, malformed, and ungranted contexts fail closed even if write risk is enabled in a test policy", async () => {
  const calls = { count: 0 };
  const loop = makeLoop({ policy: new ToolPolicy({ allowedRiskLevels: ["read", "write"] }), calls });
  for (const [index, context] of [
    undefined,
    { capabilities: ["security_remote_scan"], trusted: true },
    createTrustedCapabilityContext({ principalId: "test", capabilities: ["other"], expiresAt: Date.now() + 1000 }),
  ].entries()) {
    const result = await attempt(loop, { context, id: `bad-context-${index}` });
    assert.equal(result.evidence.error.code, "TOOL_DENIED");
  }
  assert.equal(calls.count, 0);
});

test("an exact trusted grant passes the capability gate in an offline policy fixture, but Observatory remains approval-blocked", () => {
  const tool = createMozillaObservatoryTool();
  const context = grant();
  const policy = new ToolPolicy({ allowedRiskLevels: ["read", "write"] });

  // Isolate the existing capability gate in a test-only approval-free fixture.
  // This does not enable or execute the registered Observatory operation.
  assert.equal(policy.check({ tool: { ...tool, requiresApproval: false }, userContext: context }).allowed, true);
  assert.equal(policy.check({ tool, userContext: context }).allowed, false);
});

test("an alias cannot bypass Observatory metadata; no alias is registered in the active backend", async () => {
  const calls = { count: 0 };
  const loop = makeLoop({ calls });
  const result = await attempt(loop, { name: "mozilla_observatory_scan_alias", context: grant(), id: "alias-attempt" });
  assert.equal(result.evidence.error.code, "UNKNOWN_TOOL");
  assert.equal(calls.count, 0);

  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.equal((source.match(/toolRegistry\.register\(\s*mozillaObservatoryTool\s*\)/g) || []).length, 1);
  assert.doesNotMatch(source, /name:\s*["'][^"']*mozilla[^"']*["']/i);
  assert.match(source, /new ToolPolicy\(\s*\{\s*allowedRiskLevels:\s*\['read'\]/);
});
