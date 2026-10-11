"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const { test } = require("node:test");
const {
  TAVILY_ENDPOINT,
  TAVILY_SEARCH_TOOL,
  createTransportOptions,
  createTavilyMcpManager,
  isSupportedRuntime,
  normalizeSearchResult,
} = require("../workflows/tavilyMcpClient");

const SYNTHETIC_KEY = "offline-mcp-fixture-key";
const SEARCH_SCHEMA = {
  type: "object",
  properties: {
    query: { type: "string" },
    search_depth: { type: "string", enum: ["basic", "advanced"] },
    topic: { type: "string", enum: ["general"] },
    max_results: { type: "integer", minimum: 1, maximum: 5 },
  },
  required: ["query"],
};

function createProtocolFixture() {
  let resolveToolAbort;
  const state = {
    requests: [],
    toolCalls: [],
    unknownTools: false,
    invalidSchema: false,
    hangToolCall: false,
    abortedToolCalls: 0,
    closedClients: 0,
    waitForToolAbort: new Promise((resolve) => { resolveToolAbort = resolve; }),
  };

  const server = http.createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== "/mcp/") {
      response.writeHead(404).end();
      return;
    }
    let message;
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      response.writeHead(400).end();
      return;
    }
    state.requests.push({ method: message.method, authorization: request.headers.authorization || null });

    if (!Object.hasOwn(message, "id")) {
      response.writeHead(202).end();
      return;
    }

    if (message.method === "tools/call") {
      state.toolCalls.push(message.params);
      if (state.hangToolCall) {
        response.on("close", () => {
          if (!response.writableEnded) {
            state.abortedToolCalls += 1;
            resolveToolAbort();
          }
        });
        return;
      }
    }

    let result;
    if (message.method === "initialize") {
      result = {
        protocolVersion: message.params.protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: "offline-fixture", version: "1.0.0" },
      };
    } else if (message.method === "tools/list") {
      const name = state.unknownTools ? "unexpected_tool" : TAVILY_SEARCH_TOOL;
      const inputSchema = state.invalidSchema
        ? { ...SEARCH_SCHEMA, properties: { query: { type: "integer" } } }
        : SEARCH_SCHEMA;
      result = { tools: [{ name, description: "Synthetic search tool", inputSchema }] };
    } else if (message.method === "tools/call") {
      result = {
        content: [{ type: "text", text: "Synthetic MCP response" }],
        structuredContent: {
          results: [{ id: "fixture-source", title: "Public source", url: "https://example.org/public", content: "Synthetic public evidence" }],
        },
      };
    } else {
      response.writeHead(400).end();
      return;
    }

    response.writeHead(200, {
      "content-type": "application/json",
      "mcp-session-id": "offline-fixture-session",
    });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
  });

  return { server, state };
}

function makeLoopbackOnlyFetch(port, state) {
  return async (input, init = {}) => {
    const requestedUrl = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    // The production client must still ask for the fixed Tavily URL. This test
    // adapter maps that URL only to the local fixture and rejects every other
    // destination before any fetch can occur.
    assert.equal(requestedUrl.href, TAVILY_ENDPOINT);
    assert.equal(init.redirect, "error");
    const headers = new Headers(init.headers);
    assert.equal(headers.get("authorization"), `Bearer ${SYNTHETIC_KEY}`);
    const loopbackUrl = new URL(requestedUrl.pathname, `http://127.0.0.1:${port}`);
    assert.equal(loopbackUrl.hostname, "127.0.0.1");
    state.loopbackFetches = (state.loopbackFetches || 0) + 1;
    return fetch(loopbackUrl, { ...init, headers, redirect: "error" });
  };
}

test("official MCP SDK completes the Research protocol against a loopback-only fixture", async (t) => {
  if (!isSupportedRuntime()) return t.skip("official MCP SDK requires Node 20+");

  const fixture = createProtocolFixture();
  fixture.server.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    fixture.server.once("listening", resolve);
    fixture.server.once("error", reject);
  });
  const { port, address } = fixture.server.address();
  assert.equal(address, "127.0.0.1");

  const oldKey = process.env.TAVILY_API_KEY;
  process.env.TAVILY_API_KEY = SYNTHETIC_KEY;
  const fetchImpl = makeLoopbackOnlyFetch(port, fixture.state);
  const recordingClientFactory = async (configuration) => {
    const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
    const client = new Client({ name: "lakewest-offline-test", version: "1.0.0", listMaxPages: 2 });
    const transport = new StreamableHTTPClientTransport(
      new URL(TAVILY_ENDPOINT),
      createTransportOptions(configuration.apiKey, {
        fetchImpl: configuration.fetchImpl,
        timeoutMs: configuration.timeoutMs,
        signal: configuration.signal,
      }),
    );
    try {
      await client.connect(transport);
    } catch (error) {
      await client.close().catch(() => {});
      throw error;
    }
    const previousOnClose = client.onclose;
    client.onclose = () => {
      fixture.state.closedClients += 1;
      previousOnClose?.();
    };
    return client;
  };
  const makeManager = (timeoutMs = 1000) => createTavilyMcpManager({
    enabled: true,
    clientFactory: recordingClientFactory,
    fetchImpl,
    timeoutMs,
  });

  try {
    const manager = makeManager();
    const raw = await manager.search("Public astronomy history", { maxResults: 1 });
    const normalized = normalizeSearchResult(raw);
    assert.equal(normalized.status, "success");
    assert.equal(normalized.sources[0].id, "fixture-source");
    assert.deepEqual(fixture.state.requests.map(({ method }) => method), [
      "initialize", "notifications/initialized", "tools/list", "tools/call",
    ]);
    assert.deepEqual(fixture.state.toolCalls, [{
      name: TAVILY_SEARCH_TOOL,
      arguments: { query: "Public astronomy history", search_depth: "basic", topic: "general", max_results: 1 },
    }]);
    assert.equal(fixture.state.closedClients, 1, "manager must close the SDK client after success");
    assert.ok(fixture.state.requests.every(({ authorization }) => authorization === `Bearer ${SYNTHETIC_KEY}`));

    fixture.state.unknownTools = true;
    await assert.rejects(makeManager().search("Public astronomy history"), (error) => error.code === "TOOL_SCHEMA_MISMATCH");
    assert.equal(fixture.state.toolCalls.length, 1, "unknown inventory must fail before tool invocation");
    assert.equal(fixture.state.closedClients, 2, "manager must close the SDK client after inventory rejection");

    fixture.state.unknownTools = false;
    fixture.state.invalidSchema = true;
    await assert.rejects(makeManager().search("Public astronomy history"), (error) => error.code === "TOOL_SCHEMA_MISMATCH");
    assert.equal(fixture.state.toolCalls.length, 1, "incompatible schema must fail before tool invocation");
    assert.equal(fixture.state.closedClients, 3, "manager must close the SDK client after schema rejection");

    fixture.state.invalidSchema = false;
    fixture.state.hangToolCall = true;
    await assert.rejects(makeManager(40).search("Public astronomy history"), (error) => error.code === "REQUEST_TIMEOUT");
    await Promise.race([
      fixture.state.waitForToolAbort,
      new Promise((resolve) => setTimeout(resolve, 500)),
    ]);
    assert.equal(fixture.state.abortedToolCalls, 1, "the timed-out loopback response must be aborted");
    assert.equal(fixture.state.closedClients, 4, "manager must close the SDK client after timeout");
    assert.ok(fixture.state.loopbackFetches > 0);
  } finally {
    if (oldKey === undefined) delete process.env.TAVILY_API_KEY;
    else process.env.TAVILY_API_KEY = oldKey;
    await new Promise((resolve) => {
      fixture.server.close(resolve);
      fixture.server.closeAllConnections?.();
    });
  }
});
