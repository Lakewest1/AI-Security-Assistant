const test = require("node:test");
const assert = require("node:assert/strict");
const {
  fetchWithRetry,
  readResponseBody,
  limitResponseStream,
  createResponseTimeout,
  MAX_PROVIDER_RESPONSE_BYTES,
} = require("../tools/external/provider-utils");
const { createVirusTotalTool } = require("../tools/external/virustotal");

function responseFromChunks(chunks, headers = {}) {
  let index = 0;
  let cancelled = false;
  return {
    headers: new Headers(headers),
    status: 200,
    get cancelled() { return cancelled; },
    body: {
      getReader() {
        return {
          async read() {
            if (index >= chunks.length) return { done: true };
            return { done: false, value: new TextEncoder().encode(chunks[index++]) };
          },
          async cancel() { cancelled = true; },
          releaseLock() {},
        };
      },
      async cancel() { cancelled = true; },
    },
  };
}

test("bounded reader accepts bodies below and exactly at the byte limit", async () => {
  assert.deepEqual(await readResponseBody(responseFromChunks(["{}"]), { maxBytes: 3 }), {});
  assert.deepEqual(await readResponseBody(responseFromChunks(['{"a":1}']), { maxBytes: 7 }), { a: 1 });
});

test("oversized streamed body is cancelled, fails once, and exposes only a bounded safe error", async () => {
  let calls = 0;
  const oversized = responseFromChunks(["1234", "5678", "provider secret https://user:pass@private/?token=secret"]);
  const originalFetch = global.fetch;
  global.fetch = async () => { calls += 1; return oversized; };
  try {
    await assert.rejects(fetchWithRetry("https://provider.invalid/secret-url", {
      maxRetries: 2, retryBaseMs: 0, parse: "text", maxResponseBytes: 8,
    }), (error) => {
      assert.equal(error.category, "response_too_large");
      assert.equal(error.message, "Provider response exceeded the size limit");
      assert.doesNotMatch(error.message, /secret|user|private/);
      return true;
    });
    assert.equal(calls, 1, "oversize failures must not be retried");
    assert.equal(oversized.cancelled, true);
  } finally {
    global.fetch = originalFetch;
  }
});

test("missing, malformed, and misleading content-length headers are handled by streamed byte counts", async () => {
  assert.equal(await readResponseBody(responseFromChunks(["ok"], { "content-length": "invalid" }), { maxBytes: 2, parse: "text" }), "ok");
  assert.equal(await readResponseBody(responseFromChunks(["ok"]), { maxBytes: 2, parse: "text" }), "ok");
  const misleading = responseFromChunks(["123", "456"], { "content-length": "1" });
  await assert.rejects(readResponseBody(misleading, { maxBytes: 5 }), { category: "response_too_large" });
  assert.equal(misleading.cancelled, true);
  const declaredOversize = responseFromChunks(["not-read"], { "content-length": "99" });
  await assert.rejects(readResponseBody(declaredOversize, { maxBytes: 5 }), { category: "response_too_large" });
  assert.equal(declaredOversize.cancelled, true);
});

test("malformed JSON retains the existing null-payload behavior", async () => {
  assert.equal(await readResponseBody(responseFromChunks(["not-json"])), null);
});

test("stream limiter rejects a single oversized chunk and cancels/releases the reader", async () => {
  let cancelled = false;
  const source = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(64 * 1024)); },
    cancel() { cancelled = true; },
  });
  const upstream = new Response(source);
  const bounded = limitResponseStream(upstream, { maxBytes: 1024, highWaterMark: 0 });
  await assert.rejects(bounded.arrayBuffer(), { category: "response_too_large" });
  assert.equal(cancelled, true);
  assert.equal(upstream.body.locked, false);
});

test("stream limiter counts repeated chunks cumulatively and stops at overflow", async () => {
  let reads = 0;
  let cancelled = false;
  const source = new ReadableStream({
    pull(controller) {
      reads += 1;
      controller.enqueue(new Uint8Array(4));
    },
    cancel() { cancelled = true; },
  });
  const upstream = new Response(source);
  const bounded = limitResponseStream(upstream, { maxBytes: 6, highWaterMark: 0 });
  await assert.rejects(bounded.arrayBuffer(), { category: "response_too_large" });
  // The native Response stream can prefetch one item from its source before
  // cancellation reaches that source; the limiter itself rejects at item 2.
  assert.ok(reads >= 2 && reads <= 3, `unexpected upstream prefetch count: ${reads}`);
  assert.equal(cancelled, true);
  assert.equal(upstream.body.locked, false);
});

test("stream limiter aborts stalled reads on timeout and releases the upstream reader", async () => {
  const controller = new AbortController();
  let sourceAborted = false;
  const source = new ReadableStream({
    start(streamController) {
      controller.signal.addEventListener("abort", () => {
        sourceAborted = true;
        streamController.error(new Error("synthetic stalled source"));
      }, { once: true });
    },
  });
  const upstream = new Response(source);
  const timeout = createResponseTimeout(controller, 20);
  timeout.bind(upstream);
  const bounded = limitResponseStream(upstream, { maxBytes: 64, highWaterMark: 0 });
  await assert.rejects(bounded.text(), { category: "tool_timeout" });
  assert.equal(controller.signal.aborted, true);
  assert.equal(sourceAborted, true);
  assert.equal(upstream.body.locked, false);
});

test("stream limiter releases its reader after an upstream reader error", async () => {
  const source = new ReadableStream({
    pull(controller) { controller.error(new Error("synthetic reader failure")); },
  });
  const upstream = new Response(source);
  const bounded = limitResponseStream(upstream, { maxBytes: 64, highWaterMark: 0 });
  await assert.rejects(bounded.text(), /synthetic reader failure/);
  assert.equal(upstream.body.locked, false);
});

test("direct-fetch VirusTotal adapter also enforces the shared body limit", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => responseFromChunks(["x".repeat(MAX_PROVIDER_RESPONSE_BYTES + 1)]);
  try {
    const tool = createVirusTotalTool({ apiKey: "synthetic-test-key" });
    await assert.rejects(tool.execute({ ip: "8.8.8.8" }), (error) => {
      assert.equal(error.category, "response_too_large");
      assert.equal(error.message, "Provider response exceeded the size limit");
      assert.doesNotMatch(error.message, /synthetic-test-key|8\.8\.8\.8/);
      return true;
    });
  } finally {
    global.fetch = originalFetch;
  }
});

test("inline active-server provider adapters use the bounded reader", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.match(source, /body = await readResponseBody\(response\)/);
  assert.match(source, /payload = await readResponseBody\(response\)/);
});
