const test = require("node:test");
const assert = require("node:assert/strict");

const ToolRegistry = require("../agent/ToolRegistry");
const ToolValidator = require("../agent/ToolValidator");
const ToolPolicy = require("../agent/ToolPolicy");
const AgentLoop = require("../agent/AgentLoop");
const {
  createTrustedCapabilityContext,
  createRequestCapabilityResolver,
  getRequestCapabilityContext,
  isTrustedCapabilityContext,
  parseCapabilityAllowlist,
} = require("../agent/CapabilityContext");
const { createSupabaseAuthMiddleware } = require("../auth/SupabaseAuth");

function createRestrictedLoop(executionCounter) {
  const registry = new ToolRegistry();
  registry.register({
    name: "restricted_web_lookup",
    description: "Offline authorization fixture",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    riskLevel: "read",
    requiredCapability: "web_search",
    execute: async () => {
      executionCounter.count += 1;
      return { ok: true, status: "success" };
    },
  });
  return new AgentLoop({
    toolRegistry: registry,
    toolValidator: new ToolValidator(),
    toolPolicy: new ToolPolicy(),
    toolTimeoutMs: 50,
  });
}

function makeState() {
  return {
    requiredTools: [], requiredToolArguments: {}, attemptedRequiredTools: [],
    completedRequiredTools: [], rawToolEvidence: [], toolResults: [], toolsUsed: [],
    executedToolCalls: [], executedToolFingerprints: new Set(), sameToolCounts: new Map(),
    toolCallCount: 0, deadline: Date.now() + 1000, startedAt: Date.now(),
  };
}

async function attempt(loop, userContext, callId = "auth-test") {
  return loop._executeTool({
    state: makeState(), toolName: "restricted_web_lookup", input: {},
    toolCallId: callId, requestId: "offline-auth-test", userContext,
  });
}

function invokeMiddleware(middleware, req) {
  const result = { status: 200, body: null, nextCalled: false };
  const res = {
    status(status) { result.status = status; return this; },
    json(body) { result.body = body; return this; },
  };
  return Promise.resolve(middleware(req, res, () => { result.nextCalled = true; })).then(() => result);
}

test("capability-required tool is denied when context is absent", async () => {
  const counter = { count: 0 };
  const result = await attempt(createRestrictedLoop(counter), undefined);
  assert.equal(result.evidence.error.code, "TOOL_DENIED");
  assert.equal(counter.count, 0);
});

test("malformed, untrusted, and expired capability contexts are denied", async () => {
  const counter = { count: 0 };
  const loop = createRestrictedLoop(counter);
  const malformed = [
    { capabilities: "web_search", trusted: true },
    { capabilities: ["web_search"], trusted: true },
    createTrustedCapabilityContext({ principalId: "fixture", capabilities: ["web_search"], expiresAt: "tomorrow" }),
  ];
  const expired = createTrustedCapabilityContext({ principalId: "fixture", capabilities: ["web_search"], expiresAt: Date.now() - 1000 });
  assert.equal(isTrustedCapabilityContext(expired), false);
  for (const context of [...malformed, expired]) {
    const result = await attempt(loop, context);
    assert.equal(result.evidence.error.code, "TOOL_DENIED");
  }
  assert.equal(counter.count, 0);
});

test("a valid server-issued context permits only the exact granted capability", async () => {
  const counter = { count: 0 };
  const loop = createRestrictedLoop(counter);
  const granted = createTrustedCapabilityContext({
    principalId: "authenticated-fixture",
    capabilities: ["web_search"],
    expiresAt: Date.now() + 60_000,
  });
  assert.equal(isTrustedCapabilityContext(granted), true);
  const allowed = await attempt(loop, granted, "granted");
  assert.equal(allowed.ok, true);
  assert.equal(counter.count, 1);

  const wrongCapability = createTrustedCapabilityContext({
    principalId: "authenticated-fixture",
    capabilities: ["artifact_create"],
    expiresAt: Date.now() + 60_000,
  });
  const denied = await attempt(loop, wrongCapability, "not-granted");
  assert.equal(denied.evidence.error.code, "TOOL_DENIED");
  assert.equal(counter.count, 1);
});

test("verified Supabase identity receives only the server allowlist grants", async () => {
  const middleware = createSupabaseAuthMiddleware({
    verifyAccessToken: async () => ({ userId: "verified-user", role: "admin", capabilities: ["artifact_create"] }),
  });
  const req = {
    headers: { authorization: "Bearer verified-token" },
    body: { userId: "attacker", role: "admin", capabilities: ["code_execute", "artifact_create"] },
  };
  await invokeMiddleware(middleware, req);
  const resolver = createRequestCapabilityResolver({
    allowlistJson: JSON.stringify({ "verified-user": ["web_search"], attacker: ["code_execute"] }),
  });
  const context = resolver(req);
  assert.equal(isTrustedCapabilityContext(context), true);
  assert.deepEqual(context.capabilities, ["web_search"]);
  assert.equal(context.principalId, "verified-user");
  const policy = new ToolPolicy();
  assert.equal(policy.check({ tool: { riskLevel: "read", requiredCapability: "web_search" }, userContext: context }).allowed, true);
  assert.equal(policy.check({ tool: { riskLevel: "read", requiredCapability: "code_execute" }, userContext: context }).allowed, false);
});

test("authenticated users without explicit grants and anonymous requests remain denied", async () => {
  const middleware = createSupabaseAuthMiddleware({ verifyAccessToken: async () => ({ userId: "verified-user" }) });
  const authenticated = { headers: { authorization: "Bearer valid" } };
  await invokeMiddleware(middleware, authenticated);
  const noGrantResolver = createRequestCapabilityResolver({ allowlistJson: "{}" });
  const forged = { auth: { userId: "verified-user" }, body: { capabilities: ["web_search"] } };
  const loopCounter = { count: 0 };
  const loop = createRestrictedLoop(loopCounter);

  for (const request of [authenticated, forged, {}]) {
    const context = noGrantResolver(request);
    assert.deepEqual(context.capabilities, []);
    assert.equal(isTrustedCapabilityContext(context), false);
    const result = await attempt(loop, context, `no-grant-${loopCounter.count}`);
    assert.equal(result.evidence.error.code, "TOOL_DENIED");
  }
  assert.equal(loopCounter.count, 0);
});

test("malformed or missing allowlist configuration fails closed", async () => {
  assert.equal(parseCapabilityAllowlist("not-json"), null);
  assert.equal(parseCapabilityAllowlist(JSON.stringify({ "verified-user": "web_search" })), null);
  assert.equal(parseCapabilityAllowlist(JSON.stringify({ "verified-user": ["web_search", " "] })), null);

  const middleware = createSupabaseAuthMiddleware({ verifyAccessToken: async () => ({ userId: "verified-user" }) });
  const req = { headers: { authorization: "Bearer valid" } };
  await invokeMiddleware(middleware, req);
  for (const config of [undefined, "not-json"]) {
    const context = createRequestCapabilityResolver({ allowlistJson: config })(req);
    assert.deepEqual(context.capabilities, []);
    assert.equal(isTrustedCapabilityContext(context), false);
  }
});

test("capability policy is enforced for model and controller execution paths", async () => {
  const counter = { count: 0 };
  const loop = createRestrictedLoop(counter);
  for (const controllerExecuted of [false, true]) {
    const result = await loop._executeTool({
      state: makeState(), toolName: "restricted_web_lookup", input: {},
      toolCallId: `path-${controllerExecuted}`, requestId: "offline-auth-test",
      userContext: { capabilities: ["web_search"], trusted: true }, controllerExecuted,
    });
    assert.equal(result.evidence.error.code, "TOOL_DENIED");
  }
  assert.equal(counter.count, 0);
});

test("public and anonymous request data cannot create or grant a capability context", async () => {
  const counter = { count: 0 };
  const loop = createRestrictedLoop(counter);
  const forgedRequest = {
    body: { capabilities: ["web_search"], userContext: { capabilities: ["web_search"], trusted: true } },
    query: { capabilities: "web_search" },
    headers: { authorization: "Bearer forged", "x-capabilities": "web_search" },
  };
  const publicContext = getRequestCapabilityContext(forgedRequest);
  assert.deepEqual(publicContext.capabilities, []);
  assert.equal(isTrustedCapabilityContext(publicContext), false);
  const forged = await attempt(loop, publicContext, "forged-client-grant");
  assert.equal(forged.evidence.error.code, "TOOL_DENIED");

  const anonymousContext = getRequestCapabilityContext({});
  const anonymous = await attempt(loop, anonymousContext, "anonymous");
  assert.equal(anonymous.evidence.error.code, "TOOL_DENIED");
  assert.equal(counter.count, 0);
});

test("server context factory rejects missing identity and malformed grants", () => {
  assert.equal(createTrustedCapabilityContext({ capabilities: ["web_search"], expiresAt: Date.now() + 1000 }), null);
  assert.equal(createTrustedCapabilityContext({ principalId: "user", capabilities: "web_search", expiresAt: Date.now() + 1000 }), null);
  assert.equal(createTrustedCapabilityContext({ principalId: "user", capabilities: [""], expiresAt: Date.now() + 1000 }), null);
  assert.equal(createTrustedCapabilityContext({ principalId: "user", capabilities: ["web_search"] }), null);
});
