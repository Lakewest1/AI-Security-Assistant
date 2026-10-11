"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const express = require("express");
const rateLimit = require("express-rate-limit");
const {
  TAVILY_ENDPOINT, TAVILY_SEARCH_TOOL, MAX_MCP_RESPONSE_BYTES,
  McpWorkflowError, isSupportedRuntime, isLiveEnablementSatisfied,
  createBoundedMcpFetch, createTransportOptions, validateToolSchema,
  validateInventory, safePublicUrl, normalizeSearchResult, createTavilyMcpManager,
  defaultClientFactory,
} = require("../workflows/tavilyMcpClient");
const { createResearchHandler, validateResearchOptions } = require("../workflows/researchWorkflow");
const { checkResearchPrivacy } = require("../workflows/researchPrivacy");
const { createWorkflowRouter } = require("../workflows/workflowRouter");
const { createSupabaseAuthMiddleware } = require("../auth/SupabaseAuth");

const SYNTHETIC_KEY = "synthetic-tavily-key-only-for-offline-test";
const SCHEMA = {
  type: "object",
  properties: {
    query: { type: "string" },
    search_depth: { type: "string", enum: ["basic", "advanced"] },
    topic: { type: "string", enum: ["general"] },
    max_results: { type: "integer", minimum: 1, maximum: 20 },
  },
  required: ["query"],
};

function makeClient({ inventory = { tools: [{ name: TAVILY_SEARCH_TOOL, inputSchema: SCHEMA }] }, response = { structuredContent: { results: [] } }, hooks = {} } = {}) {
  return {
    listTools: async (...args) => hooks.listTools ? hooks.listTools(...args) : inventory,
    callTool: async (...args) => hooks.callTool ? hooks.callTool(...args) : response,
    close: async () => { hooks.closed?.(); },
  };
}

function withApiKey(callback) {
  const old = process.env.TAVILY_API_KEY;
  process.env.TAVILY_API_KEY = SYNTHETIC_KEY;
  return Promise.resolve().then(callback).finally(() => {
    if (old === undefined) delete process.env.TAVILY_API_KEY;
    else process.env.TAVILY_API_KEY = old;
  });
}

test("official SDK runtime gate preserves Node 18 compatibility without activating live research", () => {
  assert.equal(isSupportedRuntime("18.20.0"), false);
  assert.equal(isSupportedRuntime("20.0.0"), true);
  assert.equal(isSupportedRuntime("invalid"), false);
  assert.equal(isLiveEnablementSatisfied({ RESEARCH_MCP_ENABLED: "true", RESEARCH_MCP_LIVE_CALLS_ALLOWED: "true" }), false);
  assert.equal(TAVILY_ENDPOINT, "https://mcp.tavily.com/mcp/");
});

test("official MCP client v2 entry point loads through CommonJS-compatible dynamic import", async (t) => {
  if (!isSupportedRuntime()) return t.skip("official MCP client requires Node 20+");
  const sdk = await import("@modelcontextprotocol/client");
  assert.equal(typeof sdk.Client, "function");
  assert.equal(typeof sdk.StreamableHTTPClientTransport, "function");
});

test("disabled default manager never loads an SDK client or opens a connection, even if flags are set", async () => {
  let clientFactoryCalls = 0;
  const previous = {
    enabled: process.env.RESEARCH_MCP_ENABLED,
    allowed: process.env.RESEARCH_MCP_LIVE_CALLS_ALLOWED,
  };
  process.env.RESEARCH_MCP_ENABLED = "true";
  process.env.RESEARCH_MCP_LIVE_CALLS_ALLOWED = "true";
  try {
    const manager = createTavilyMcpManager({ clientFactory: async () => { clientFactoryCalls += 1; } });
    await withApiKey(async () => {
      await assert.rejects(manager.search("Synthetic query"), (error) => error.code === "PROVIDER_DISABLED");
    });
    assert.equal(clientFactoryCalls, 0);
    let defaultFetchCalls = 0;
    const explicitlyEnabledDefault = createTavilyMcpManager({
      enabled: true,
      fetchImpl: async () => { defaultFetchCalls += 1; return new Response("unexpected"); },
    });
    await withApiKey(async () => {
      await assert.rejects(explicitlyEnabledDefault.search("Synthetic query"), (error) => error.code === "PROVIDER_DISABLED");
    });
    assert.equal(defaultFetchCalls, 0, "explicit enablement must not bypass the offline-only default-client gate");
  } finally {
    if (previous.enabled === undefined) delete process.env.RESEARCH_MCP_ENABLED;
    else process.env.RESEARCH_MCP_ENABLED = previous.enabled;
    if (previous.allowed === undefined) delete process.env.RESEARCH_MCP_LIVE_CALLS_ALLOWED;
    else process.env.RESEARCH_MCP_LIVE_CALLS_ALLOWED = previous.allowed;
  }
});

test("fixed transport config keeps the key in Authorization and rejects alternate destinations", async () => {
  const options = createTransportOptions(SYNTHETIC_KEY, { fetchImpl: async () => new Response("ok") });
  assert.equal(options.requestInit.headers.Authorization, `Bearer ${SYNTHETIC_KEY}`);
  assert.equal(options.reconnectionOptions.maxRetries, 0);
  assert.equal(options.maxStepUpRetries, 0);
  let fetchCalls = 0;
  const fetcher = createBoundedMcpFetch({ fetchImpl: async () => { fetchCalls += 1; return new Response("ok"); } });
  await assert.rejects(fetcher("https://attacker.example/mcp", {}), (error) => error.code === "PROVIDER_UNAVAILABLE");
  assert.equal(fetchCalls, 0);
});

test("bounded MCP fetch enforces redirect rejection, timeout, cancellation, and byte ceilings", async (t) => {
  await t.test("passes redirect:error and rejects redirect responses without following them", async () => {
    let fetchCalls = 0;
    const fetcher = createBoundedMcpFetch({ fetchImpl: async (_url, init) => {
      fetchCalls += 1;
      assert.equal(init.redirect, "error");
      return new Response(null, { status: 302, headers: { location: "http://127.0.0.1/private" } });
    } });
    await assert.rejects(fetcher(TAVILY_ENDPOINT, {}), (error) => error.code === "PROVIDER_UNAVAILABLE");
    assert.equal(fetchCalls, 1);
  });

  await t.test("body below the limit is consumed successfully", async () => {
    const fetcher = createBoundedMcpFetch({ fetchImpl: async () => new Response("synthetic-small-response") });
    const response = await fetcher(TAVILY_ENDPOINT, {});
    assert.equal(await response.text(), "synthetic-small-response");
    const exact = createBoundedMcpFetch({ maxBytes: 4, fetchImpl: async () => new Response("1234") });
    assert.equal(await (await exact(TAVILY_ENDPOINT, {})).text(), "1234");
  });

  await t.test("a stalled body is aborted after response headers", async () => {
    let aborted = false;
    const fetcher = createBoundedMcpFetch({ timeoutMs: 25, fetchImpl: async (_url, init) => {
      const body = new ReadableStream({ start(controller) {
        init.signal.addEventListener("abort", () => { aborted = true; controller.error(new Error("synthetic abort")); }, { once: true });
      } });
      return new Response(body);
    } });
    const response = await fetcher(TAVILY_ENDPOINT, {});
    await assert.rejects(response.text(), (error) => error.category === "tool_timeout");
    assert.equal(aborted, true);
  });

  await t.test("oversized streamed responses fail and cancel their source", async () => {
    let cancelled = false;
    const body = new ReadableStream({
      pull(controller) { controller.enqueue(new Uint8Array(12)); },
      cancel() { cancelled = true; },
    });
    const fetcher = createBoundedMcpFetch({ maxBytes: 8, fetchImpl: async () => new Response(body) });
    const response = await fetcher(TAVILY_ENDPOINT, {});
    await assert.rejects(response.arrayBuffer(), /size limit/i);
    assert.equal(cancelled, true);
    assert.ok(MAX_MCP_RESPONSE_BYTES <= 256 * 1024);
  });
});

test("approved tool inventory and required argument schema fail closed on drift", () => {
  assert.equal(validateToolSchema({ name: TAVILY_SEARCH_TOOL, inputSchema: SCHEMA }), true);
  assert.throws(() => validateInventory({ tools: [{ name: "tavily_research", inputSchema: SCHEMA }] }), (error) => error.code === "TOOL_SCHEMA_MISMATCH");
  assert.throws(() => validateInventory({ tools: [{ name: TAVILY_SEARCH_TOOL, inputSchema: { ...SCHEMA, required: ["query", "mode"] } }] }), (error) => error.code === "TOOL_SCHEMA_MISMATCH");
  assert.throws(() => validateInventory({ tools: [{ name: TAVILY_SEARCH_TOOL, inputSchema: { ...SCHEMA, properties: { ...SCHEMA.properties, endpoint: { type: "string" } } } }] }), (error) => error.code === "TOOL_SCHEMA_MISMATCH");
  assert.throws(() => validateInventory({ tools: [{ name: TAVILY_SEARCH_TOOL, inputSchema: SCHEMA }, { name: "unknown_write_tool", inputSchema: SCHEMA }] }), (error) => error.code === "TOOL_SCHEMA_MISMATCH");
});

test("manager validates inventory, bounds arguments and calls only the approved search once", async () => {
  let toolCalls = 0;
  let receivedArgs;
  let receivedName;
  let closeCalls = 0;
  await withApiKey(async () => {
    const manager = createTavilyMcpManager({
      enabled: true,
      clientFactory: async (configuration) => {
        assert.equal(configuration.endpoint, TAVILY_ENDPOINT);
        assert.equal(configuration.apiKey, SYNTHETIC_KEY);
        return makeClient({ response: { structuredContent: { results: [] } }, hooks: {
          callTool: async (params, options) => { toolCalls += 1; receivedName = params.name; receivedArgs = params.arguments; assert.ok(options.signal); return { structuredContent: { results: [] } }; },
          closed: () => { closeCalls += 1; },
        } });
      },
    });
    const response = await manager.search("Synthetic research question", { maxResults: 2 });
    assert.ok(response.structuredContent);
  });
  assert.equal(receivedName, TAVILY_SEARCH_TOOL);
  assert.deepEqual(receivedArgs, { query: "Synthetic research question", search_depth: "basic", topic: "general", max_results: 2 });
  assert.equal(toolCalls, 1);
  assert.equal(closeCalls, 1);
});

test("manager distinguishes timeout, concurrency, cancellation, and oversize errors without leaking provider text", async (t) => {
  await t.test("timeout", async () => withApiKey(async () => {
    const manager = createTavilyMcpManager({ enabled: true, timeoutMs: 20, clientFactory: async () => makeClient({ hooks: {
      callTool: (_params, options) => new Promise((_resolve, reject) => options.signal.addEventListener("abort", () => reject(new Error("SYNTHETIC_PROVIDER_SECRET")), { once: true })),
    } }) });
    await assert.rejects(manager.search("Synthetic query"), (error) => error.code === "REQUEST_TIMEOUT" && !error.message.includes("SYNTHETIC_PROVIDER_SECRET"));
  }));

  await t.test("caller cancellation reaches the MCP request and closes the client", async () => withApiKey(async () => {
    let started;
    let closed = false;
    const callStarted = new Promise((resolve) => { started = resolve; });
    const manager = createTavilyMcpManager({ enabled: true, clientFactory: async () => makeClient({ hooks: {
      callTool: (_params, options) => new Promise((_resolve, reject) => {
        started();
        options.signal.addEventListener("abort", () => reject(new Error("synthetic abort")), { once: true });
      }),
      closed: () => { closed = true; },
    } }) });
    const controller = new AbortController();
    const operation = manager.search("Synthetic query", { signal: controller.signal });
    await callStarted;
    controller.abort();
    await assert.rejects(operation, (error) => error.code === "REQUEST_TIMEOUT");
    assert.equal(closed, true);
  }));

  await t.test("concurrency cap", async () => withApiKey(async () => {
    let entered;
    const waitForCall = new Promise((resolve) => { entered = resolve; });
    let release;
    const blocked = new Promise((resolve) => { release = resolve; });
    const manager = createTavilyMcpManager({ enabled: true, maxConcurrent: 1, clientFactory: async () => makeClient({ hooks: {
      callTool: async () => { entered(); await blocked; return { structuredContent: { results: [] } }; },
    } }) });
    const first = manager.search("Synthetic query");
    await waitForCall;
    await assert.rejects(manager.search("Another synthetic query"), (error) => error.code === "CONCURRENCY_LIMIT");
    release();
    await first;
  }));

  await t.test("oversized parsed output", async () => withApiKey(async () => {
    const manager = createTavilyMcpManager({ enabled: true, maxBytes: 10, clientFactory: async () => makeClient({ hooks: {
      callTool: async () => ({ structuredContent: { results: [{ url: "https://example.org", content: "SYNTHETIC_LARGE_PROVIDER_RESPONSE" }] } }),
    } }) });
    await assert.rejects(manager.search("Synthetic query"), (error) => error.code === "RESPONSE_TOO_LARGE" && !error.message.includes("SYNTHETIC_LARGE_PROVIDER_RESPONSE"));
  }));
});

test("public-information gate blocks recognizable identifiers and ambiguous investigation requests", () => {
  const rejected = [
    "Please check example.com",
    "Find public information about +1 (212) 555-0100",
    "Analyze 203.0.113.42",
    "Investigate this host 2001:db8::1",
    "Use Bearer synthetic-token-123456",
    "api_key=synthetic-test-key",
    "Search for synthetic.person@example.invalid",
    "Email alex [at] example [dot] invalid",
    "Explain https://internal.example.test/path",
    "Check the domain example[.]com",
    "What happened in this confidential security incident?",
    "AWS key AKIA1234567890ABCDEF",
    "-----BEGIN PRIVATE KEY----- synthetic fixture -----END PRIVATE KEY-----",
    "Check this host's reputation",
    "What is the status of this target?",
  ];
  for (const question of rejected) assert.equal(checkResearchPrivacy(question).allowed, false, question);
  assert.equal(checkResearchPrivacy("Compare the history of astronomy and physics").allowed, true);
  assert.equal(checkResearchPrivacy("Summarize publicly documented Artemis mission milestones").allowed, true);
  assert.equal(checkResearchPrivacy("General synthetic query", { containsPersonalData: true }).allowed, false);
  assert.equal(checkResearchPrivacy("General synthetic query", { containsConfidentialData: true }).allowed, false);
});

test("research validation permits only bounded options and rejects invalid tool arguments", () => {
  assert.deepEqual(validateResearchOptions({ maxResults: 5 }), { ok: true, value: { maxResults: 5, containsPersonalData: false, containsConfidentialData: false } });
  assert.equal(validateResearchOptions({ maxResults: 6 }).ok, false);
  assert.equal(validateResearchOptions({ arbitraryUrl: "https://example.org" }).ok, false);
  assert.equal(validateResearchOptions({ containsPersonalData: "false" }).ok, false);
});

test("source normalization keeps only real metadata, rejects unsafe URLs, and distinguishes partial, empty, and malformed results", () => {
  const success = normalizeSearchResult({ structuredContent: { results: [
    { id: "provider-source-1", title: "Synthetic title", url: "https://example.org/page", content: "Synthetic excerpt", retrieved_at: "2026-01-02T03:04:05Z" },
    { title: "No identifier", url: "https://example.net" },
  ] } });
  assert.equal(success.status, "success");
  assert.equal(success.sources[0].id, "provider-source-1");
  assert.equal(success.sources[0].retrievedAt, "2026-01-02T03:04:05.000Z");
  assert.equal(Object.hasOwn(success.sources[1], "id"), false);
  assert.equal(success.result.evidence.length, 1);

  const partial = normalizeSearchResult({ structuredContent: { results: [
    { id: "real-id", url: "https://example.org", content: "Evidence" },
    { id: "bad", url: "http://127.0.0.1/admin", content: "Unsafe" },
  ] } });
  assert.equal(partial.status, "partial");
  assert.equal(partial.sources.length, 1);
  assert.equal(normalizeSearchResult({ structuredContent: { results: [] } }).status, "empty");
  assert.throws(() => normalizeSearchResult({ structuredContent: { results: [{ url: "file:///etc/passwd" }] } }), (error) => error.code === "INVALID_PROVIDER_RESPONSE");
  assert.throws(() => normalizeSearchResult({ content: [{ type: "text", text: "not json" }] }), (error) => error.code === "INVALID_PROVIDER_RESPONSE");
  assert.equal(safePublicUrl("http://10.0.0.4/private"), null);
  assert.equal(safePublicUrl("http://[::1]/private"), null);
  assert.equal(safePublicUrl("https://example.com/path"), "https://example.com/path");
});

test("research handler never logs rejected input and maps typed provider outcomes to truthful envelopes", async (t) => {
  let calls = 0;
  const sensitive = "Synthetic bearer token Bearer secret-token-123456";
  const handler = createResearchHandler({ manager: { search: async () => { calls += 1; return {}; } } });
  const captured = [];
  const originalWarn = console.warn;
  console.warn = (...args) => captured.push(args.join(" "));
  try {
    const rejected = await handler({ question: sensitive, options: {} });
    assert.equal(rejected.error.code, "RESEARCH_PRIVACY_REJECTED");
    assert.equal(JSON.stringify(rejected).includes(sensitive), false);
    assert.equal(calls, 0);
  } finally { console.warn = originalWarn; }
  assert.deepEqual(captured, []);

  await t.test("disabled provider", async () => {
    const disabled = createResearchHandler({ manager: createTavilyMcpManager({ enabled: false, clientFactory: async () => { calls += 1; } }) });
    const result = await disabled({ question: "Synthetic safe research question" });
    assert.equal(result.status, "unavailable");
    assert.equal(result.error.code, "RESEARCH_PROVIDER_DISABLED");
    assert.equal(result.executionStatus, "not_started");
    assert.equal(calls, 0);
  });

  await t.test("typed timeout", async () => {
    const timeout = createResearchHandler({ manager: { search: async () => { throw new McpWorkflowError("REQUEST_TIMEOUT"); } } });
    assert.equal((await timeout({ question: "Synthetic safe research question" })).status, "timeout");
  });
});

test("every privacy rejection is omitted from provider calls, logs, and public response bodies", async () => {
  const cases = [
    "Please check example.com",
    "Call +1 (212) 555-0100",
    "Analyze 203.0.113.42",
    "Investigate 2001:db8::1",
    "Bearer synthetic-token-123456",
    "api_key=synthetic-fake-key",
    "-----BEGIN PRIVATE KEY----- synthetic fixture -----END PRIVATE KEY-----",
    "Email pat [at] corp [dot] invalid",
    "Check this host's reputation",
    "What is the status of this target?",
  ];
  const sent = [];
  const written = [];
  const originals = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  for (const method of Object.keys(originals)) console[method] = (...args) => written.push(args.join(" "));
  const handler = createResearchHandler({ manager: { search: async (query) => { sent.push(query); return {}; } } });
  try {
    for (const question of cases) {
      const result = await handler({ question });
      assert.equal(result.error.code, "RESEARCH_PRIVACY_REJECTED");
      assert.equal(JSON.stringify(result).includes(question), false);
    }
  } finally {
    Object.assign(console, originals);
  }
  assert.deepEqual(sent, []);
  assert.deepEqual(written, []);
});

test("legacy workflow Research route cannot bypass explicit confirmation", async () => {
  let calls = 0;
  const researchHandler = createResearchHandler({ manager: { search: async () => {
    calls += 1;
    return { structuredContent: { results: [{ id: "provider-id", title: "Synthetic source", url: "https://example.org", content: "Synthetic evidence" }] } };
  } } });
  const testApp = express();
  testApp.use(express.json({ limit: "1mb" }));
  testApp.use((req, _res, next) => { req.id = "synthetic-request-id"; next(); });
  const auth = createSupabaseAuthMiddleware({ verifyAccessToken: async (token) => {
    if (token !== "synthetic-valid-token") { const error = new Error("invalid"); error.status = 401; throw error; }
    return { userId: "synthetic-user" };
  } });
  testApp.use("/api/workflows", createWorkflowRouter({ authMiddleware: auth, researchHandler }));
  const server = testApp.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); });
  const url = `http://127.0.0.1:${server.address().port}/api/workflows`;
  const send = (body, token = "synthetic-valid-token") => fetch(url, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
  try {
    assert.equal((await send({ schemaVersion: 1, mode: "research", input: "Synthetic bearer Bearer token-secret-123456" })).status, 409);
    assert.equal((await send({ schemaVersion: 1, mode: "research", input: "Safe synthetic research question" }, null)).status, 401);
    assert.equal((await send({ schemaVersion: 1, mode: "research", input: "Safe synthetic research question" }, "synthetic-invalid-token")).status, 401);
    assert.equal((await send({ schemaVersion: 1, mode: "research", input: "" })).status, 400);
    assert.equal((await send({ schemaVersion: 1, mode: "research", input: "x".repeat(12 * 1024 + 1) })).status, 413);
    assert.equal(calls, 0);
    const direct = await send({ schemaVersion: 1, mode: "research", input: "Safe synthetic research question" });
    assert.equal(direct.status, 409);
    assert.equal((await direct.json()).error.code, "RESEARCH_CONFIRMATION_REQUIRED");
    assert.equal(calls, 0);
    const code = await send({ schemaVersion: 1, mode: "code", input: "Synthetic code request" });
    assert.equal(code.status, 501);
    assert.equal(calls, 0);
  } finally { await new Promise((resolve) => { server.close(resolve); server.closeAllConnections?.(); }); }
});

test("workflow-specific rate limiting rejects a request before Research handling", async () => {
  let calls = 0;
  const testApp = express();
  testApp.use(express.json());
  const auth = createSupabaseAuthMiddleware({ verifyAccessToken: async () => ({ userId: "synthetic-user" }) });
  const limiter = rateLimit({ windowMs: 60_000, max: 1, standardHeaders: true, legacyHeaders: false,
    handler(_req, res) { return res.status(429).json({ code: "WORKFLOW_RATE_LIMITED" }); },
  });
  testApp.use("/api/workflows", createWorkflowRouter({ authMiddleware: auth, rateLimiter: limiter, researchHandler: async () => { calls += 1; return { status: "empty", executionStatus: "completed", sources: [], result: { summary: null, evidence: [] } }; } }));
  const server = testApp.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); });
  const url = `http://127.0.0.1:${server.address().port}/api/workflows`;
  const send = () => fetch(url, { method: "POST", headers: { authorization: "Bearer synthetic-token", "content-type": "application/json" }, body: JSON.stringify({ schemaVersion: 1, mode: "research", input: "Safe synthetic query" }) });
  try {
    assert.equal((await send()).status, 409);
    const limited = await send();
    assert.equal(limited.status, 429);
    assert.equal((await limited.json()).code, "WORKFLOW_RATE_LIMITED");
    assert.equal(calls, 0);
  } finally { await new Promise((resolve) => { server.close(resolve); server.closeAllConnections?.(); }); }
});

test("workflow middleware order is limiter, authentication, then Research execution", async () => {
  const order = [];
  const testApp = express();
  testApp.use(express.json());
  const rateLimiter = (_req, _res, next) => { order.push("rate-limit"); next(); };
  const authMiddleware = (_req, _res, next) => { order.push("auth"); next(); };
  const researchHandler = async () => {
    order.push("research");
    return { status: "empty", executionStatus: "completed", sources: [], result: { summary: null, evidence: [] } };
  };
  testApp.use("/api/workflows", createWorkflowRouter({ rateLimiter, authMiddleware, researchHandler }));
  const server = testApp.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workflows`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ schemaVersion: 1, mode: "research", input: "Public astronomy history" }),
    });
    assert.equal(response.status, 409);
    assert.deepEqual(order, ["rate-limit", "auth"]);
  } finally { await new Promise((resolve) => { server.close(resolve); server.closeAllConnections?.(); }); }
});

test("/api/agent remains separate from MCP and unauthenticated access cannot start investigation work", async () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.match(source, /app\.post\(\s*['"]\/api\/agent['"]\s*,\s*chatLimiter\s*,\s*requireAuthenticatedSupabaseUser\s*,/);
  assert.doesNotMatch(source, /app\.post\(\s*['"]\/api\/agent['"][\s\S]{0,250}createTavilyMcpManager/);
});
