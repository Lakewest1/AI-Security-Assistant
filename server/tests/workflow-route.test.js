"use strict";

const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");

const originalFetch = global.fetch;
const originalConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error };
console.log = () => {};
console.info = () => {};
console.warn = () => {};
console.error = () => {};

const externalCalls = [];
const capturedErrors = [];
let server;
let baseUrl;

global.fetch = async (input, options = {}) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  if (url.hostname === "127.0.0.1" || url.hostname === "localhost") return originalFetch(input, options);
  if (url.pathname === "/auth/v1/user") {
    return options.headers?.Authorization === "Bearer synthetic-invalid-token"
      ? new Response("{}", { status: 401 })
      : Response.json({ id: "synthetic-supabase-user" });
  }
  externalCalls.push(url.hostname);
  throw new Error("Unexpected external request in offline workflow test");
};
console.error = (...args) => capturedErrors.push(args.map((value) => String(value)).join(" "));
const app = require("../agent-server");

before(async () => {
  server = app.listen(0, "127.0.0.1");
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
  Object.assign(console, originalConsole);
});

async function postWorkflow(payload, { raw = false, token = "synthetic-valid-token" } = {}) {
  return originalFetch(`${baseUrl}/api/workflows`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: raw ? payload : JSON.stringify(payload),
  });
}

test("active workflow route requires authentication before handling any mode", async () => {
  const response = await postWorkflow({ schemaVersion: 1, mode: "research", input: "Synthetic request" }, { token: null });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).code, "missing_token");
  assert.deepEqual(externalCalls, []);
});

test("unauthenticated workflow bodies cannot reach validation or provider handling", async () => {
  const response = await postWorkflow({ schemaVersion: 1, mode: "research", input: "Synthetic" }, { token: null });
  assert.equal(response.status, 401);
  assert.deepEqual(externalCalls, []);
});

test("workflow route uses the existing Supabase missing and invalid token responses", async () => {
  const missing = await postWorkflow({ schemaVersion: 1, mode: "research", input: "Synthetic question" }, { token: null });
  assert.equal(missing.status, 401);
  assert.equal((await missing.json()).code, "missing_token");
});

test("malformed JSON and oversized parser bodies return sanitized errors without logging submitted content", async () => {
  const marker = "SYNTHETIC_PRIVATE_PROMPT_MARKER";
  const malformed = await postWorkflow(`{"schemaVersion":1,"input":"${marker}",`, { raw: true });
  assert.equal(malformed.status, 400);
  const malformedBody = await malformed.json();
  assert.equal(malformedBody.error.code, "INVALID_REQUEST_BODY");
  assert.equal(JSON.stringify(malformedBody).includes(marker), false);

  const tooLarge = await postWorkflow(`{"input":"${"x".repeat(1024 * 1024)}"}`, { raw: true });
  assert.equal(tooLarge.status, 413);
  const tooLargeBody = await tooLarge.json();
  assert.equal(tooLargeBody.error.code, "REQUEST_TOO_LARGE");
  assert.equal(JSON.stringify(tooLargeBody).includes("x".repeat(100)), false);
  assert.equal(capturedErrors.some((line) => line.includes(marker)), false);
  assert.deepEqual(externalCalls, []);
});

test("workflow requests cannot fall through into chat, the investigation API, or provider routing", async () => {
  const response = await postWorkflow({ schemaVersion: 1, mode: "code", input: "Explain this synthetic function" }, { token: null });
  assert.equal(response.status, 401);
  assert.deepEqual(externalCalls, []);
});
