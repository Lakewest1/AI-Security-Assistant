const test = require("node:test");
const assert = require("node:assert/strict");
const FallbackEngine = require("../FallbackEngine");
const ProviderErrorClassifier = require("../ProviderErrorClassifier");
const ActiveOpenAI = require("../providers-updated").OpenAIProvider;
const LegacyOpenAI = require("../providers/openai");

function provider(Adapter, name = Adapter.name) {
  return new Adapter({
    name,
    apiKey: "synthetic-key",
    url: "https://provider.invalid/v1/chat",
    models: { fast: "synthetic-model", balanced: "synthetic-model" },
  });
}

const messages = [{ role: "user", content: "synthetic prompt" }];

for (const [label, Adapter] of [["active", ActiveOpenAI], ["legacy", LegacyOpenAI]]) {
  test(`${label} provider timeout stays active after headers until the body is consumed`, async () => {
    const originalFetch = global.fetch;
    let signal;
    let cancelled = false;
    global.fetch = async (_url, options) => {
      signal = options.signal;
      const body = new ReadableStream({
        start(controller) {
          options.signal.addEventListener("abort", () => {
            cancelled = true;
            controller.error(new DOMException("aborted", "AbortError"));
          }, { once: true });
        },
      });
      return new Response(body, { status: 200 });
    };
    try {
      await assert.rejects(provider(Adapter).call(messages, "synthetic-model", 16, { timeoutMs: 25 }), (error) => {
        assert.equal(error.category, "tool_timeout");
        assert.equal(error.status, 408);
        assert.equal(error.message, "Provider request timed out");
        assert.doesNotMatch(error.message, /synthetic-key|provider\.invalid|synthetic prompt/);
        return true;
      });
      assert.equal(signal.aborted, true);
      assert.equal(cancelled, true);
    } finally {
      global.fetch = originalFetch;
    }
  });

  test(`${label} provider clears the timeout after successful body consumption`, async () => {
    const originalFetch = global.fetch;
    let signal;
    global.fetch = async (_url, options) => {
      signal = options.signal;
      return new Response(JSON.stringify({ choices: [{ message: { content: "synthetic reply" } }] }), { status: 200 });
    };
    try {
      const result = await provider(Adapter).call(messages, "synthetic-model", 16, { timeoutMs: 50 });
      await new Promise((resolve) => setTimeout(resolve, 70));
      assert.equal(result.reply, "synthetic reply");
      assert.equal(signal.aborted, false);
    } finally {
      global.fetch = originalFetch;
    }
  });
}

test("oversized provider responses stop fallback without exposing response content", async () => {
  const calls = [];
  const first = {
    name: "Groq",
    models: { fast: "model" },
    isConfigured: () => true,
    logAttempt() {}, logFailure() {},
    normalizeError: (error) => error,
    classifyError: (error) => ProviderErrorClassifier.classify(error),
    async call() {
      calls.push("first");
      throw Object.assign(new Error("Provider response exceeded the size limit"), {
        category: "response_too_large", status: 500,
        responseBody: "synthetic-secret-response",
      });
    },
  };
  const second = {
    ...first,
    name: "DeepSeek",
    async call() { calls.push("second"); return { reply: "should not run" }; },
  };
  const engine = new FallbackEngine({ providers: [first, second] });
  await assert.rejects(engine.callWithFallback(messages, "fast", 16, "synthetic-request"), (error) => {
    assert.equal(error.category, "response_too_large");
    assert.equal(error.message, "Provider response exceeded the size limit");
    assert.doesNotMatch(error.message, /synthetic-secret-response|synthetic-key|provider\.invalid/);
    return true;
  });
  assert.deepEqual(calls, ["first"]);
});

test("ordinary transient provider failures retain configured fallback behavior", async () => {
  const calls = [];
  const first = {
    name: "Groq", models: { fast: "model" }, isConfigured: () => true,
    logAttempt() {}, logFailure() {}, logSuccess() {},
    normalizeError: (error) => error,
    classifyError: (error) => ProviderErrorClassifier.classify(error),
    async call() {
      calls.push("first");
      throw Object.assign(new Error("Provider unavailable"), { status: 503, category: "network_error" });
    },
  };
  const second = {
    ...first,
    name: "DeepSeek",
    async call() { calls.push("second"); return { reply: "fallback reply", provider: "DeepSeek" }; },
  };
  const engine = new FallbackEngine({ providers: [first, second] });
  const result = await engine.callWithFallback(messages, "fast", 16, "synthetic-request");
  assert.equal(result.reply, "fallback reply");
  assert.equal(result.fallbackUsed, true);
  assert.deepEqual(calls, ["first", "second"]);
});

test("malformed JSON remains a null parsed payload rather than an oversize error", async () => {
  const { readResponseBody } = require("../tools/external/provider-utils");
  const payload = await readResponseBody(new Response("{ malformed"), { maxBytes: 64 });
  assert.equal(payload, null);
  const oversized = ProviderErrorClassifier.classify(Object.assign(new Error("Provider response exceeded the size limit"), {
    category: "response_too_large", status: 500,
  }));
  const timeout = ProviderErrorClassifier.classify(Object.assign(new Error("Provider request timed out"), {
    category: "tool_timeout", status: 408,
  }));
  const ordinaryFailure = ProviderErrorClassifier.classify(Object.assign(new Error("Provider unavailable"), { status: 503 }));
  assert.equal(oversized.category, "response_too_large");
  assert.equal(oversized.shouldFallback, false);
  assert.equal(timeout.category, "timeout");
  assert.equal(timeout.shouldFallback, true);
  assert.equal(ordinaryFailure.category, "server_error");
  assert.equal(ordinaryFailure.shouldFallback, true);
});
