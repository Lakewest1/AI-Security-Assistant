const test = require("node:test");
const assert = require("node:assert/strict");

const legacyAdapters = [
  require("../providers/openai"),
  require("../providers/anthropic"),
  require("../providers/groq"),
  require("../providers/deepseek"),
  require("../providers/gemini"),
  require("../providers/openrouter"),
];
const activeAdapters = Object.values(require("../providers-updated"));

const compatiblePayload = {
  choices: [{ message: { content: "synthetic reply" }, finish_reason: "stop" }],
  usage: { total_tokens: 3 },
};
const anthropicPayload = {
  content: [{ type: "text", text: "synthetic reply" }],
  usage: { output_tokens: 2 },
  stop_reason: "end_turn",
};
const geminiPayload = {
  candidates: [{ content: { parts: [{ text: "synthetic reply" }] }, finishReason: "STOP" }],
  usageMetadata: { totalTokenCount: 3 },
};

function payloadFor(provider) {
  if (provider.constructor.name === "AnthropicProvider") return anthropicPayload;
  if (provider.constructor.name === "GeminiProvider") return geminiPayload;
  return compatiblePayload;
}

function createProvider(Adapter, maxResponseBytes = 1024) {
  return new Adapter({
    name: Adapter.name,
    apiKey: "synthetic-provider-key",
    url: "https://provider.invalid/v1/messages",
    models: { balanced: "synthetic-model" },
    maxResponseBytes,
  });
}

test("all active and legacy AI adapters retain successful parsing under the shared bound", async () => {
  const originalFetch = global.fetch;
  try {
    for (const Adapter of [...legacyAdapters, ...activeAdapters]) {
      const provider = createProvider(Adapter);
      // Native adapter headers do not carry test metadata; use class shape to
      // choose a compatible response in the mock without changing requests.
      global.fetch = async (url, options) => {
        assert.match(String(url), /^https:\/\/provider\.invalid\//);
        assert.equal(options.method, "POST");
        return new Response(JSON.stringify(payloadFor(provider)), { status: 200 });
      };
      const result = await provider.call(
        [{ role: "user", content: "synthetic prompt" }],
        "synthetic-model",
        16,
        { timeoutMs: 1000 }
      );
      assert.equal(result.reply, "synthetic reply", Adapter.name);
      assert.equal(result.provider, Adapter.name, Adapter.name);
    }
  } finally {
    global.fetch = originalFetch;
  }
});

test("active and legacy provider adapters reject oversized responses with bounded errors", async () => {
  const originalFetch = global.fetch;
  try {
    for (const Adapter of [...legacyAdapters, ...activeAdapters]) {
      const provider = createProvider(Adapter, 32);
      global.fetch = async () => new Response("x".repeat(128), { status: 200 });
      await assert.rejects(
        provider.call(
          [{ role: "user", content: "synthetic prompt" }],
          "synthetic-model",
          16,
          { timeoutMs: 1000 }
        ),
        (error) => {
          assert.equal(error.category, "response_too_large");
          assert.equal(error.message, "Provider response exceeded the size limit");
          assert.doesNotMatch(error.message, /synthetic-provider-key|provider\.invalid|synthetic prompt/);
          return true;
        }
      );
    }
  } finally {
    global.fetch = originalFetch;
  }
});

test("raw streaming responses are bounded and cancel after crossing the limit", async () => {
  const originalFetch = global.fetch;
  try {
    for (const Adapter of legacyAdapters.filter((item) => item.name !== "GeminiProvider")) {
      let cancelled = false;
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("1234"));
          controller.enqueue(new TextEncoder().encode("5678"));
          controller.enqueue(new TextEncoder().encode("never-needed"));
        },
        cancel() { cancelled = true; },
      });
      global.fetch = async () => new Response(stream, { status: 200 });
      const provider = createProvider(Adapter, 5);
      const response = await provider.call(
        [{ role: "user", content: "synthetic prompt" }],
        "synthetic-model",
        16,
        { timeoutMs: 1000, stream: true }
      );
      assert.equal(response.status, 200, Adapter.name);
      await assert.rejects(response.text(), (error) => {
        assert.equal(error.category, "response_too_large", Adapter.name);
        assert.equal(error.message, "Provider response exceeded the size limit", Adapter.name);
        return true;
      });
      assert.equal(cancelled, true, Adapter.name);
    }
  } finally {
    global.fetch = originalFetch;
  }
});
