const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");

// Configure fake credentials before loading the server. Provider HTTP calls
// are intercepted below; no credential value is logged or sent externally.
for (const name of ["GROQ", "DEEPSEEK", "GEMINI", "OPENAI", "ANTHROPIC", "OPENROUTER"]) {
  process.env[`${name}_API_KEY`] = "";
}
process.env.GROQ_API_KEY = "test-only-groq-key";
process.env.DEEPSEEK_API_KEY = "test-only-deepseek-key";
process.env.PROVIDER_TIMEOUT_MS = "100";
process.env.TOTAL_AI_REQUEST_TIMEOUT_MS = "2000";

const app = require("../agent-server");
const originalFetch = global.fetch;
const originalConsole = {
  log: console.log,
  warn: console.warn,
  error: console.error,
};
console.log = () => {};
console.warn = () => {};
console.error = () => {};
const providerCalls = [];
let providerBehavior = async () => jsonResponse({
  choices: [{ message: { content: "offline mock reply" } }],
});
let server;
let baseUrl;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

global.fetch = async (input, options = {}) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
    return originalFetch(input, options);
  }

  const provider = url.hostname === "api.groq.com"
    ? "Groq"
    : url.hostname === "api.deepseek.com"
      ? "DeepSeek"
      : url.hostname;
  providerCalls.push(provider);
  return providerBehavior({ provider, url, options });
};

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
  console.log = originalConsole.log;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
});

function resetProviderBehavior(behavior) {
  providerCalls.length = 0;
  providerBehavior = behavior || (async () => jsonResponse({
    choices: [{ message: { content: "offline mock reply" } }],
  }));
}

async function postRaw(body, { raw = false } = {}) {
  return originalFetch(`${baseUrl}/api/chat`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: raw ? body : JSON.stringify(body),
  });
}

async function postChat(messages, extra = {}) {
  const response = await postRaw({ messages, ...extra });
  const body = await response.json().catch(() => null);
  return { response, body };
}

test("valid chat request reaches /api/chat and returns its response contract", async () => {
  resetProviderBehavior();
  const { response, body } = await postChat(
    [{ role: "user", content: "Explain cloud security" }],
    { conversationId: "conversation-test" },
  );

  assert.equal(response.status, 200);
  assert.equal(body.reply, "offline mock reply");
  assert.equal(body.conversationId, "conversation-test");
  assert.ok(Array.isArray(body.intents));
  assert.equal(body.metadata.provider, "Groq");
  assert.equal(body.metadata.route, "fast");
  assert.deepEqual(body.metadata.attemptedProviders, ["Groq"]);
  assert.equal(typeof body.metadata.requestId, "string");
  assert.deepEqual(providerCalls, ["Groq"]);
});

test("missing, empty, non-array, and user-less message lists return 400", async () => {
  resetProviderBehavior();
  for (const payload of [
    {},
    { messages: [] },
    { messages: "not-an-array" },
    { messages: [{ role: "assistant", content: "hello" }] },
  ]) {
    const response = await postRaw(payload);
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(typeof body.error, "string");
  }
  assert.deepEqual(providerCalls, []);
});

test("malformed message entries are contained by the route error handler", async () => {
  resetProviderBehavior();
  const response = await postRaw({ messages: [null] });
  const body = await response.json();

  // The active route has no per-message validator; it currently returns 500
  // for an invalid element, but it does not crash or invoke a provider.
  assert.equal(response.status, 500);
  assert.deepEqual(body, { error: "Internal server error" });
  assert.deepEqual(providerCalls, []);
});

test("malformed JSON is rejected by the existing middleware error path", async () => {
  resetProviderBehavior();
  const response = await postRaw('{"messages":', { raw: true });
  const body = await response.json();

  // The current global Express error handler maps parser errors to 500.
  assert.equal(response.status, 500);
  assert.deepEqual(body, { error: "Server error" });
  assert.deepEqual(providerCalls, []);
});

test("provider failure falls back in the configured fast-route order", async () => {
  resetProviderBehavior(async ({ provider }) => provider === "Groq"
    ? jsonResponse({ error: { message: "mock unavailable" } }, 503)
    : jsonResponse({ choices: [{ message: { content: "fallback reply" } }] }));

  const { response, body } = await postChat([
    { role: "user", content: "Explain cloud security" },
  ]);

  assert.equal(response.status, 200);
  assert.equal(body.reply, "fallback reply");
  assert.equal(body.metadata.provider, "DeepSeek");
  assert.equal(body.metadata.fallbackUsed, true);
  assert.deepEqual(body.metadata.attemptedProviders, ["Groq", "DeepSeek"]);
  assert.deepEqual(providerCalls, ["Groq", "DeepSeek"]);
});

test("exhausting configured providers returns a controlled 503", async () => {
  resetProviderBehavior(async () => jsonResponse({
    error: { message: "mock unavailable" },
  }, 503));

  const { response, body } = await postChat([
    { role: "user", content: "Explain cloud security" },
  ]);

  assert.equal(response.status, 503);
  assert.equal(body.error, "AI services temporarily unavailable");
  assert.deepEqual(body.details.attemptedProviders, ["Groq", "DeepSeek"]);
  assert.equal(body.details.lastError, "mock unavailable");
  assert.deepEqual(providerCalls, ["Groq", "DeepSeek"]);
});

test("provider timeout aborts its fetch and proceeds to the next provider", async () => {
  let timedOutFetchAborted = false;
  resetProviderBehavior(async ({ provider, options }) => {
    if (provider !== "Groq") {
      return jsonResponse({ choices: [{ message: { content: "after timeout" } }] });
    }

    return new Promise((resolve, reject) => {
      const signal = options.signal;
      if (signal.aborted) {
        timedOutFetchAborted = true;
        reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        return;
      }
      signal.addEventListener("abort", () => {
        timedOutFetchAborted = true;
        reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
      }, { once: true });
    });
  });

  const { response, body } = await postChat([
    { role: "user", content: "Explain cloud security" },
  ]);

  assert.equal(response.status, 200);
  assert.equal(body.reply, "after timeout");
  assert.equal(timedOutFetchAborted, true);
  assert.deepEqual(providerCalls, ["Groq", "DeepSeek"]);
});

test("request body over 1 MB is rejected before provider execution", async () => {
  resetProviderBehavior();
  const content = "x".repeat(1024 * 1024 + 100);
  const { response, body } = await postChat([{ role: "user", content }]);

  // Current error middleware turns body-parser's size error into a generic 500.
  assert.equal(response.status, 500);
  assert.deepEqual(body, { error: "Server error" });
  assert.deepEqual(providerCalls, []);
});

test("chat rate limiter returns 429 after its configured request allowance", async () => {
  resetProviderBehavior();
  let limited = false;

  // Prior tests may already have used part of this IP's fixed-window quota.
  // Walk the remaining quota using response headers rather than timing.
  for (let attempt = 0; attempt < 61; attempt += 1) {
    const response = await originalFetch(`${baseUrl}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        messages: [{ role: "user", content: "Explain cloud security" }],
      }),
    });
    await response.arrayBuffer();
    if (response.status === 429) {
      limited = true;
      break;
    }
    assert.equal(response.status, 200);
  }

  assert.equal(limited, true);
});
