const { after, before, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const ToolPolicy = require("../agent/ToolPolicy");
const { getRequestCapabilityContext } = require("../agent/CapabilityContext");
const { createSupabaseAuthMiddleware, createSupabaseTokenVerifier } = require("../auth/SupabaseAuth");

process.env.SUPABASE_URL = "https://auth-fixture.supabase.co";
process.env.SUPABASE_PUBLISHABLE_KEY = "sb_publishable_test-only";
process.env.NODE_ENV = "development";
const originalFetch = global.fetch;
const originalConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error };
const authCalls = [];
let server;
let baseUrl;
global.fetch = async (input, options = {}) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  if (url.hostname === "127.0.0.1" || url.hostname === "localhost") return originalFetch(input, options);
  if (url.hostname === "auth-fixture.supabase.co") {
    authCalls.push({ url: url.toString(), options });
    return new Response(JSON.stringify({ message: "Invalid token" }), { status: 401 });
  }
  throw new Error("Unexpected network request in offline authentication test");
};
console.log = () => {};
console.info = () => {};
console.warn = () => {};
console.error = () => {};
const activeApp = require("../agent-server");
console.log = originalConsole.log;
console.info = originalConsole.info;
console.warn = originalConsole.warn;
console.error = originalConsole.error;

before(async () => {
  server = activeApp.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server?.listening) {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections?.();
    });
  }
  global.fetch = originalFetch;
});

function invokeMiddleware(middleware, req) {
  const result = { status: 200, body: null, nextCalled: false };
  const res = {
    status(status) { result.status = status; return this; },
    json(body) { result.body = body; return this; },
  };
  return Promise.resolve(middleware(req, res, () => { result.nextCalled = true; })).then(() => result);
}

test("Supabase verifier checks the bearer token remotely and returns only verified principal identity", async () => {
  const requests = [];
  const verify = createSupabaseTokenVerifier({
    supabaseUrl: "https://lakewest-project.supabase.co",
    publishableKey: "sb_publishable_test-only",
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return new Response(JSON.stringify({ id: "verified-user", email: "ignored@example.test", role: "admin", capabilities: ["web_search"] }), { status: 200 });
    },
  });
  const identity = await verify("fixture.access.token");
  assert.deepEqual(identity, { userId: "verified-user" });
  assert.equal(requests[0].url, "https://lakewest-project.supabase.co/auth/v1/user");
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.headers.Authorization, "Bearer fixture.access.token");
  assert.equal(requests[0].options.headers.apikey, "sb_publishable_test-only");
});

test("agent authentication rejects missing, malformed, invalid, and expired tokens", async () => {
  const middleware = createSupabaseAuthMiddleware({
    verifyAccessToken: async (token) => {
      if (token === "invalid" || token === "expired") {
        const error = new Error("provider details must not be returned");
        error.status = 401;
        throw error;
      }
      return { userId: "verified-user" };
    },
  });
  for (const [authorization, expectedCode] of [
    [undefined, "missing_token"],
    ["Basic credential", "malformed_authorization"],
    ["Bearer", "malformed_authorization"],
    ["Bearer two tokens", "malformed_authorization"],
    ["Bearer invalid", "invalid_token"],
    ["Bearer expired", "invalid_token"],
  ]) {
    const result = await invokeMiddleware(middleware, { headers: { authorization } });
    assert.equal(result.status, 401);
    assert.equal(result.body.code, expectedCode);
    assert.equal(result.nextCalled, false);
  }
});

test("valid verified identity reaches the protected handler without accepting request identity or grants", async () => {
  const middleware = createSupabaseAuthMiddleware({
    verifyAccessToken: async () => ({ userId: "verified-user", capabilities: ["web_search"] }),
  });
  const req = {
    headers: { authorization: "Bearer valid-token" },
    body: { userId: "client-user", capabilities: ["web_search"], userContext: { trusted: true } },
  };
  const result = await invokeMiddleware(middleware, req);
  assert.equal(result.status, 200);
  assert.equal(result.nextCalled, true);
  assert.deepEqual(req.auth, { userId: "verified-user" });
  assert.deepEqual(getRequestCapabilityContext(req).capabilities, []);

  const policy = new ToolPolicy();
  const decision = policy.check({
    tool: { name: "restricted", riskLevel: "read", requiredCapability: "web_search" },
    userContext: getRequestCapabilityContext(req),
  });
  assert.equal(decision.allowed, false);
});

test("missing backend configuration and Supabase service errors fail closed", async () => {
  const missingConfig = createSupabaseTokenVerifier({ supabaseUrl: "", publishableKey: "", fetchImpl: async () => { throw new Error("must not call"); } });
  await assert.rejects(missingConfig("fixture-token"), (error) => error.status === 503);
  const serviceRoleConfig = createSupabaseTokenVerifier({ supabaseUrl: "https://lakewest-project.supabase.co", publishableKey: "sb_secret_never-use-this", fetchImpl: async () => { throw new Error("must not call"); } });
  await assert.rejects(serviceRoleConfig("fixture-token"), (error) => error.status === 503);

  const serviceUnavailable = createSupabaseAuthMiddleware({
    verifyAccessToken: async () => { throw new Error("service detail and fixture-token"); },
  });
  const result = await invokeMiddleware(serviceUnavailable, { headers: { authorization: "Bearer fixture-token" } });
  assert.equal(result.status, 503);
  assert.equal(result.body.code, "auth_unavailable");
  assert.doesNotMatch(JSON.stringify(result.body), /fixture-token|service detail/);
});

test("authentication errors do not log bearer tokens or passwords", async () => {
  const messages = [];
  const originals = { log: console.log, warn: console.warn, error: console.error };
  console.log = (...args) => messages.push(args.join(" "));
  console.warn = (...args) => messages.push(args.join(" "));
  console.error = (...args) => messages.push(args.join(" "));
  try {
    const middleware = createSupabaseAuthMiddleware({ verifyAccessToken: async () => { throw new Error("fixture-bearer-password"); } });
    await invokeMiddleware(middleware, { headers: { authorization: "Bearer fixture-bearer-password" } });
  } finally {
    console.log = originals.log;
    console.warn = originals.warn;
    console.error = originals.error;
  }
  assert.equal(messages.length, 0);
  assert.doesNotMatch(messages.join(" "), /fixture-bearer-password/);
});

test("only /api/agent is protected; /api/chat and health routes remain public", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.match(source, /app\.post\(\s*['"]\/api\/agent['"]\s*,\s*chatLimiter\s*,\s*requireAuthenticatedSupabaseUser\s*,/);
  assert.match(source, /app\.post\(\s*['"]\/api\/chat['"]\s*,\s*chatLimiter\s*,\s*async/);
  assert.match(source, /app\.get\(\s*['"]\/api\/health['"]/);
});

test("active /api/agent route rejects unauthenticated and invalid tokens while health stays public", async () => {
  authCalls.length = 0;
  const body = { messages: [{ role: "user", content: "Investigate 198.51.100.77" }] };
  const postAgent = (authorization) => originalFetch(`${baseUrl}/api/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(authorization ? { authorization } : {}),
    },
    body: JSON.stringify(body),
  });

  const missing = await postAgent();
  assert.equal(missing.status, 401);
  assert.equal((await missing.json()).code, "missing_token");
  const malformed = await postAgent("Basic secret");
  assert.equal(malformed.status, 401);
  assert.equal((await malformed.json()).code, "malformed_authorization");
  for (const token of ["invalid", "expired"]) {
    const response = await postAgent(`Bearer ${token}`);
    assert.equal(response.status, 401);
    assert.equal((await response.json()).code, "invalid_token");
  }
  assert.equal(authCalls.length, 2);
  assert.ok(authCalls.every((call) => call.url.endsWith("/auth/v1/user")));

  const health = await originalFetch(`${baseUrl}/api/health`);
  assert.equal(health.status, 200);
  assert.ok(["healthy", "unavailable"].includes((await health.json()).status));

  const preflight = await originalFetch(`${baseUrl}/api/agent`, {
    method: "OPTIONS",
    headers: {
      origin: "http://localhost:5173",
      "access-control-request-method": "POST",
      "access-control-request-headers": "authorization,content-type",
    },
  });
  assert.equal(preflight.status, 204);
  assert.match(preflight.headers.get("access-control-allow-headers") || "", /authorization/i);
});
