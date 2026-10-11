"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { TypeSafeClient } = require("@typesafe-ai/sdk");
const {
  MAX_RESPONSE_BYTES,
  createClient,
  createBoundedFetch,
  deriveSafeRoutingState,
  recommendRoute,
  serverSupportsSdk,
} = require("../agent/JevGeneralChatRouter");

const SYNTHETIC_API_KEY = "SYNTHETIC_JEV_KEY_DO_NOT_USE";
const SAFE_TEXT = "Explain recursion in one paragraph.";
const SAFE_MESSAGES = [{ role: "user", content: SAFE_TEXT }];
const SAFE_INTENTS = ["explanation"];

function savedEnv(name, value) {
  const previous = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  return () => {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  };
}

function enableJevForTest() {
  const restoreFlag = savedEnv("JEV_GENERAL_CHAT_ROUTING", "true");
  const restoreRuntimeApproval = savedEnv("JEV_ROUTING_RUNTIME_APPROVED", "true");
  return () => {
    restoreRuntimeApproval();
    restoreFlag();
  };
}

function sdkResponse(route = "balanced") {
  return {
    model: "jev-synthetic",
    answers: {
      route: {
        type: "choice",
        choice: route,
        confidence: 0.91,
        probabilities: { fast: 0.04, balanced: 0.91, powerful: 0.05 },
      },
    },
    usage: { input_tokens: 2, output_tokens: 1 },
  };
}

function streamResponse(body, { status = 200, headers = {} } = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const stream = new ReadableStream({
    start(controller) {
      for (let offset = 0; offset < bytes.length; offset += 2048) {
        controller.enqueue(bytes.slice(offset, offset + 2048));
      }
      controller.close();
    },
  });
  return new Response(stream, { status, headers });
}

function makeSdkClient(fetchImpl, options = {}) {
  return createClient({ apiKey: SYNTHETIC_API_KEY, fetchImpl, ...options });
}

function advisorArgs(client, extra = {}) {
  return {
    messages: SAFE_MESSAGES,
    intents: SAFE_INTENTS,
    currentUserText: SAFE_TEXT,
    deterministicRoute: "fast",
    client,
    ...extra,
  };
}

test("routing flag is off by default and unsupported runtimes preserve the deterministic route", async () => {
  const restoreFlag = savedEnv("JEV_GENERAL_CHAT_ROUTING", undefined);
  const restoreRuntimeApproval = savedEnv("JEV_ROUTING_RUNTIME_APPROVED", undefined);
  let calls = 0;
  try {
    const result = await recommendRoute(advisorArgs({ systemOne: async () => { calls += 1; } }));
    assert.deepEqual(result, { route: "fast", usedJev: false });
    assert.equal(calls, 0);
    process.env.JEV_GENERAL_CHAT_ROUTING = "true";
    const unverifiedRuntime = await recommendRoute(advisorArgs({ systemOne: async () => { calls += 1; } }));
    assert.deepEqual(unverifiedRuntime, { route: "fast", usedJev: false });
    assert.equal(calls, 0, "the feature flag alone cannot enable Jev on an unverified deployment runtime");
    assert.equal(serverSupportsSdk("18.20.0"), false);
    assert.equal(serverSupportsSdk("20.0.0"), true);
  } finally {
    restoreRuntimeApproval();
    restoreFlag();
  }
});

test("Jev remains disabled unless both routing flags are exactly true", async () => {
  const restoreFlag = savedEnv("JEV_GENERAL_CHAT_ROUTING", undefined);
  const restoreRuntimeApproval = savedEnv("JEV_ROUTING_RUNTIME_APPROVED", undefined);
  const configurations = [
    ["true", undefined],
    [undefined, "true"],
    ["TRUE", "true"],
    ["true", "TRUE"],
    ["false", "true"],
    ["true", "false"],
  ];
  let calls = 0;
  try {
    for (const [routing, approval] of configurations) {
      if (routing === undefined) delete process.env.JEV_GENERAL_CHAT_ROUTING;
      else process.env.JEV_GENERAL_CHAT_ROUTING = routing;
      if (approval === undefined) delete process.env.JEV_ROUTING_RUNTIME_APPROVED;
      else process.env.JEV_ROUTING_RUNTIME_APPROVED = approval;
      const result = await recommendRoute(advisorArgs({ systemOne: async () => { calls += 1; } }));
      assert.deepEqual(result, { route: "fast", usedJev: false });
    }
    assert.equal(calls, 0);
  } finally {
    restoreRuntimeApproval();
    restoreFlag();
  }
});

test("the server sends only fixed routing features, never the prompt or conversation history", async () => {
  const restoreFlag = enableJevForTest();
  let requestBody;
  try {
    const client = makeSdkClient(async (_url, init) => {
      requestBody = JSON.parse(init.body);
      return streamResponse(JSON.stringify(sdkResponse("balanced")), { headers: { "content-type": "application/json" } });
    });
    assert.ok(client instanceof TypeSafeClient);
    const result = await recommendRoute(advisorArgs(client, {
      messages: [
        { role: "user", content: "An earlier harmless question" },
        { role: "assistant", content: "An earlier harmless answer" },
        { role: "user", content: SAFE_TEXT },
      ],
    }));

    assert.deepEqual(result, { route: "balanced", usedJev: true });
    assert.deepEqual(requestBody.state, { taskKinds: ["explanation"], size: "short" });
    assert.equal(JSON.stringify(requestBody).includes(SAFE_TEXT), false);
    assert.equal(JSON.stringify(requestBody).includes("earlier harmless"), false);
    assert.deepEqual(client.retry.maxRetries, 0);
    assert.equal(client.logLevel, "off");
  } finally {
    restoreFlag();
  }
});

test("security, indicators, credentials, logs, and ambiguous history fail closed", async () => {
  const cases = [
    { text: "Investigate 198.51.100.23", intents: ["security"] },
    { text: "Check https://synthetic.example.test/path", intents: [] },
    { text: "Contact synthetic.person@example.test", intents: [] },
    { text: "api_key=SYNTHETIC_FAKE_KEY", intents: [] },
    { text: "Review the logs from yesterday", intents: ["troubleshooting"] },
    { text: "Check synthetic-example.test", intents: [] },
    { text: "Open hxxps[:]//synthetic[.]example[.]test", intents: [] },
    { text: "Review hash abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", intents: [] },
    { text: "Could you troubleshoot the private network setup", intents: ["troubleshooting"] },
  ];
  for (const item of cases) {
    assert.equal(deriveSafeRoutingState([{ role: "user", content: item.text }], item.intents, item.text), null);
  }

  const restoreFlag = enableJevForTest();
  let calls = 0;
  try {
    const messages = [
      { role: "user", content: SAFE_TEXT },
      { role: "assistant", content: "Previous synthetic investigation finding: malware." },
    ];
    const result = await recommendRoute(advisorArgs({ systemOne: async () => { calls += 1; } }, { messages }));
    assert.deepEqual(result, { route: "fast", usedJev: false });
    assert.equal(calls, 0);
  } finally {
    restoreFlag();
  }
});

test("the official SDK consumes a response below and exactly at the bounded byte limit", async (t) => {
  const restoreFlag = enableJevForTest();
  t.after(restoreFlag);

  for (const exact of [false, true]) {
    let attempts = 0;
    const base = Buffer.from(JSON.stringify(sdkResponse("balanced")));
    const body = exact
      ? Buffer.concat([base, Buffer.alloc(MAX_RESPONSE_BYTES - base.length, 0x20)])
      : base;
    assert.ok(body.length <= MAX_RESPONSE_BYTES);
    const client = makeSdkClient(async () => {
      attempts += 1;
      // Deliberately misleading but syntactically valid length header: the stream is counted.
      return streamResponse(body, { headers: { "content-type": "application/json", "content-length": "1" } });
    });
    const result = await recommendRoute(advisorArgs(client));
    assert.deepEqual(result, { route: "balanced", usedJev: true });
    assert.equal(attempts, 1);
  }
});

test("the official SDK rejects oversized streamed responses once and falls back without leaking body text", async (t) => {
  const restoreFlag = enableJevForTest();
  t.after(restoreFlag);
  const bytes = Buffer.from(`${JSON.stringify(sdkResponse("powerful"))}${"SYNTHETIC_RESPONSE_SECRET".repeat(3000)}`);
  for (const contentLength of [undefined, "1"]) {
    let attempts = 0;
    let offset = 0;
    let chunksPulled = 0;
    let sourceCancelled = false;
    const client = makeSdkClient(async () => {
      attempts += 1;
      const body = new ReadableStream({
        pull(controller) {
          chunksPulled += 1;
          if (offset >= bytes.length) {
            controller.close();
            return;
          }
          const next = bytes.slice(offset, offset + 2048);
          offset += next.length;
          controller.enqueue(next);
        },
        cancel() {
          sourceCancelled = true;
        },
      }, { highWaterMark: 0 });
      const headers = { "content-type": "application/json" };
      if (contentLength !== undefined) headers["content-length"] = contentLength;
      // Exercise absent and under-reported content-length; streaming must enforce both.
      return new Response(body, { headers });
    });

    const result = await recommendRoute(advisorArgs(client));
    assert.deepEqual(result, { route: "fast", usedJev: false });
    assert.equal(attempts, 1);
    assert.equal(sourceCancelled, true);
    assert.ok(offset <= MAX_RESPONSE_BYTES + 2048, `stream source advanced ${offset} bytes before cancellation`);
    assert.ok(chunksPulled < Math.ceil(bytes.length / 2048));
    assert.equal(JSON.stringify(result).includes("SYNTHETIC_RESPONSE_SECRET"), false);
  }
});

test("Jev fetch rejects redirects and redirect failures use deterministic routing", async (t) => {
  const restoreFlag = enableJevForTest();
  t.after(restoreFlag);
  let attempts = 0;
  let receivedRedirectMode;
  const fetchImpl = createBoundedFetch(async (_url, init) => {
    attempts += 1;
    receivedRedirectMode = init.redirect;
    throw new TypeError("SYNTHETIC_REDIRECT_DESTINATION_REJECTED");
  });
  const client = makeSdkClient(fetchImpl);
  const result = await recommendRoute(advisorArgs(client));
  assert.equal(receivedRedirectMode, "error");
  assert.equal(attempts, 1, "redirect failure must not retry the Jev request");
  assert.deepEqual(result, { route: "fast", usedJev: false });
  assert.equal(JSON.stringify(result).includes("SYNTHETIC_REDIRECT_DESTINATION_REJECTED"), false);
});

test("the SDK body timeout aborts a stalled response after headers and succeeds for a body completed in time", async (t) => {
  const restoreFlag = enableJevForTest();
  t.after(restoreFlag);

  let cancelled = false;
  const stalledClient = makeSdkClient(async () => {
    let stallTimer;
    const stream = new ReadableStream({
      start(controller) {
        stallTimer = setTimeout(() => controller.enqueue(new Uint8Array([123])), 60_000);
      },
      cancel() {
        cancelled = true;
        clearTimeout(stallTimer);
      },
    });
    return new Response(stream, { headers: { "content-type": "application/json" } });
  });
  const started = Date.now();
  const timeoutResult = await recommendRoute(advisorArgs(stalledClient, { timeoutMs: 30 }));
  assert.deepEqual(timeoutResult, { route: "fast", usedJev: false });
  assert.ok(Date.now() - started < 1000);
  assert.equal(cancelled, true);

  const completeClient = makeSdkClient(async () => streamResponse(JSON.stringify(sdkResponse("powerful"))));
  const successResult = await recommendRoute(advisorArgs(completeClient));
  assert.deepEqual(successResult, { route: "powerful", usedJev: true });
});

test("malformed JSON, invalid routes, and HTTP errors retain deterministic routing", async (t) => {
  const restoreFlag = enableJevForTest();
  t.after(restoreFlag);
  const responses = [
    () => streamResponse("not-json", { headers: { "content-type": "application/json" } }),
    () => streamResponse(JSON.stringify(sdkResponse("security_investigation"))),
    () => streamResponse(JSON.stringify({ error: "SYNTHETIC_PROVIDER_SECRET" }), { status: 503 }),
  ];
  for (const response of responses) {
    let attempts = 0;
    const client = makeSdkClient(async () => {
      attempts += 1;
      return response();
    });
    const result = await recommendRoute(advisorArgs(client));
    assert.deepEqual(result, { route: "fast", usedJev: false });
    assert.equal(attempts, 1, "routing retries must stay disabled");
    assert.equal(JSON.stringify(result).includes("SYNTHETIC_PROVIDER_SECRET"), false);
  }
});

test("/api/agent remains isolated from Jev routing", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  const agentRoute = /app\.post\(\s*['"]\/api\/agent['"]/m.exec(source);
  const agentRouteStart = agentRoute?.index ?? -1;
  assert.notEqual(agentRouteStart, -1);
  assert.match(source.slice(0, agentRouteStart), /JevGeneralChatRouter\.recommendRoute/);
  assert.doesNotMatch(source.slice(agentRouteStart), /JevGeneralChatRouter\.recommendRoute/);
});
