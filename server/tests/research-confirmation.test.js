"use strict";

const assert = require("node:assert/strict");
const express = require("express");
const { afterEach, test } = require("node:test");
const { createSupabaseAuthMiddleware } = require("../auth/SupabaseAuth");
const { createWorkflowRouter } = require("../workflows/workflowRouter");
const { createResearchConfirmationStore } = require("../workflows/researchConfirmation");

const originalFetch = global.fetch;
const originalConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error };
const originalHttpFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  Object.assign(console, originalConsole);
});

async function withWorkflowServer({ researchHandler, confirmationStore, guardExternalFetch = false } = {}, callback) {
  const externalCalls = [];
  if (guardExternalFetch) {
    global.fetch = async (input, init) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
      if (url.hostname === "127.0.0.1") return originalHttpFetch(input, init);
      externalCalls.push(url.hostname);
      throw new Error("Unexpected external request in offline confirmation test");
    };
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use((req, _res, next) => { req.id = "synthetic-confirmation-request"; next(); });
  const authMiddleware = createSupabaseAuthMiddleware({
    verifyAccessToken: async (token) => {
      if (token === "synthetic-user-a-token") return { userId: "verified-user-a" };
      if (token === "synthetic-user-b-token") return { userId: "verified-user-b" };
      const error = new Error("synthetic invalid token");
      error.status = 401;
      throw error;
    },
  });
  app.use("/api/workflows", createWorkflowRouter({ authMiddleware, researchHandler, confirmationStore }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });

  const send = (path, body, token = "synthetic-user-a-token") => originalHttpFetch(
    `http://127.0.0.1:${server.address().port}/api/workflows${path}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    },
  );

  try {
    await callback({ send, externalCalls });
  } finally {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections?.();
    });
  }
}

function unavailableHandler(calls) {
  return async ({ question }) => {
    calls.push(question);
    return {
      status: "unavailable",
      httpStatus: 503,
      executionStatus: "not_started",
      error: { code: "RESEARCH_PROVIDER_DISABLED", message: "Research provider access is disabled." },
    };
  };
}

test("unauthenticated prepare and confirm requests cannot create or consume confirmations", async () => {
  let calls = 0;
  await withWorkflowServer({ researchHandler: async () => { calls += 1; } }, async ({ send }) => {
    const prepare = await send("/research/prepare", { query: "Public synthetic topic" }, null);
    const confirm = await send("/research/confirm", {
      confirmationId: "A".repeat(43), query: "Public synthetic topic", provider: "Tavily", confirmed: true,
    }, null);
    assert.equal(prepare.status, 401);
    assert.equal(confirm.status, 401);
    assert.equal(calls, 0);
  });
});

test("prepare previews the exact normalized query without invoking the provider; valid confirm consumes it", async () => {
  const calls = [];
  await withWorkflowServer({ researchHandler: unavailableHandler(calls) }, async ({ send }) => {
    const preparedResponse = await send("/research/prepare", {
      query: "  Public synthetic astronomy topic  ", options: { maxResults: 2 },
    });
    assert.equal(preparedResponse.status, 201);
    const prepared = await preparedResponse.json();
    assert.equal(prepared.status, "confirmation_required");
    assert.equal(prepared.result.query, "Public synthetic astronomy topic");
    assert.equal(prepared.result.provider, "Tavily");
    assert.equal(prepared.result.maxResults, 2);
    assert.equal(typeof prepared.result.confirmationId, "string");
    assert.equal(Number.isFinite(Date.parse(prepared.result.expiresAt)), true);
    assert.equal(prepared.metadata.executionStatus, "not_started");
    assert.deepEqual(calls, []);

    const confirmedResponse = await send("/research/confirm", {
      confirmationId: prepared.result.confirmationId,
      query: prepared.result.query,
      provider: prepared.result.provider,
      confirmed: true,
    });
    assert.equal(confirmedResponse.status, 503);
    assert.equal((await confirmedResponse.json()).error.code, "RESEARCH_PROVIDER_DISABLED");
    assert.deepEqual(calls, ["Public synthetic astronomy topic"]);
  });
});

test("wrong user, changed query/provider, false confirmation, and replay are rejected", async () => {
  const calls = [];
  await withWorkflowServer({ researchHandler: unavailableHandler(calls) }, async ({ send }) => {
    const prepared = await (await send("/research/prepare", { query: "Public synthetic topic" })).json();
    const confirmationId = prepared.result.confirmationId;
    const confirm = (overrides = {}, token) => send("/research/confirm", {
      confirmationId,
      query: "Public synthetic topic",
      provider: "Tavily",
      confirmed: true,
      ...overrides,
    }, token);

    assert.equal((await confirm({}, "synthetic-user-b-token")).status, 409);
    assert.equal((await confirm({ query: "Different synthetic topic" })).status, 409);
    assert.equal((await confirm({ provider: "OtherProvider" })).status, 409);
    assert.equal((await confirm({ confirmationId: "invalid-id" })).status, 409);
    assert.equal((await confirm({ confirmed: false })).status, 409);
    assert.deepEqual(calls, []);

    assert.equal((await confirm()).status, 503);
    assert.equal((await confirm()).status, 409);
    assert.deepEqual(calls, ["Public synthetic topic"]);
  });
});

test("expired confirmations cannot reach the research handler", async () => {
  let currentTime = 1_000;
  const confirmationStore = createResearchConfirmationStore({ ttlMs: 100, now: () => currentTime });
  const calls = [];
  await withWorkflowServer({ confirmationStore, researchHandler: unavailableHandler(calls) }, async ({ send }) => {
    const prepared = await (await send("/research/prepare", { query: "Public synthetic topic" })).json();
    currentTime = 1_101;
    const response = await send("/research/confirm", {
      confirmationId: prepared.result.confirmationId,
      query: prepared.result.query,
      provider: prepared.result.provider,
      confirmed: true,
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error.code, "RESEARCH_CONFIRMATION_INVALID");
    assert.deepEqual(calls, []);
  });
});

test("concurrent confirmation attempts consume the identifier only once", async () => {
  const calls = [];
  const researchHandler = async ({ question }) => {
    calls.push(question);
    await new Promise((resolve) => setTimeout(resolve, 10));
    return {
      status: "unavailable", httpStatus: 503, executionStatus: "not_started",
      error: { code: "RESEARCH_PROVIDER_DISABLED", message: "Research provider access is disabled." },
    };
  };
  await withWorkflowServer({ researchHandler }, async ({ send }) => {
    const prepared = await (await send("/research/prepare", { query: "Public synthetic topic" })).json();
    const payload = {
      confirmationId: prepared.result.confirmationId,
      query: prepared.result.query,
      provider: prepared.result.provider,
      confirmed: true,
    };
    const results = await Promise.all([
      send("/research/confirm", payload),
      send("/research/confirm", payload),
    ]);
    const statuses = results.map((response) => response.status).sort();
    assert.deepEqual(statuses, [409, 503]);
    assert.deepEqual(calls, ["Public synthetic topic"]);
  });
});

test("privacy rejection does not echo or log the rejected query", async () => {
  const marker = "synthetic-private-api-key-value";
  const rejectedQuery = `api_key=${marker}`;
  const logged = [];
  for (const method of Object.keys(originalConsole)) console[method] = (...args) => logged.push(args.join(" "));
  const calls = [];
  await withWorkflowServer({ researchHandler: unavailableHandler(calls) }, async ({ send }) => {
    const response = await send("/research/prepare", { query: rejectedQuery });
    const body = await response.text();
    assert.equal(response.status, 400);
    assert.equal(body.includes(marker), false);
    assert.equal(body.includes(rejectedQuery), false);
    assert.deepEqual(calls, []);
  });
  assert.deepEqual(logged, []);
});

test("confirmation cannot bypass the hard offline gate or cause external network calls", async () => {
  await withWorkflowServer({ guardExternalFetch: true }, async ({ send, externalCalls }) => {
    const prepared = await (await send("/research/prepare", { query: "Public synthetic topic" })).json();
    const response = await send("/research/confirm", {
      confirmationId: prepared.result.confirmationId,
      query: prepared.result.query,
      provider: prepared.result.provider,
      confirmed: true,
    });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.error.code, "RESEARCH_PROVIDER_DISABLED");
    assert.equal(body.metadata.executionStatus, "not_started");
    assert.deepEqual(externalCalls, []);
  });
});
