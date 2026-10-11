const test = require("node:test");
const assert = require("node:assert/strict");
const AgentAuditLogger = require("../agent/AgentAuditLogger");
const AgentOrchestrator = require("../agent/AgentOrchestrator");

function capturedLogger() {
  const lines = [];
  const audit = new AgentAuditLogger({ logger: { log: (line) => lines.push(line) } });
  return { audit, lines };
}

test("audit and orchestrator logs redact URL credentials, sensitive queries, and email indicators", async () => {
  const { audit, lines } = capturedLogger();
  const submitted = "https://alice:pw123@example.test/path?campaign=spring&ToKeN=abc%2F123&api_key=secret";
  const orchestrator = new AgentOrchestrator({
    auditLogger: audit,
    requiredToolResolver: () => ({
      requiredTools: [], targets: [{ type: "url", value: submitted }], investigationType: "url", requiredToolArguments: {},
    }),
    agentLoop: { async run() { throw Object.assign(new Error("synthetic unavailable"), { category: "network" }); } },
    agentProviders: [{ name: "SyntheticProvider", models: { balanced: "test-model" }, async callWithTools() {} }],
  });
  await assert.rejects(orchestrator.run({ messages: [{ role: "user", content: `Investigate ${submitted} and alice@example.test` }], requestId: "req-safe-1" }));
  const output = lines.join("\n");
  for (const secret of ["alice:pw123", "abc/123", "secret", "alice@example.test"]) assert.equal(output.includes(secret), false, `log exposed ${secret}`);
  assert.match(output, /req-safe-1/);
  assert.match(output, /campaign=spring/);
  assert.match(output, /SyntheticProvider/);
});

test("sanitized errors preserve diagnostics but omit nested request and provider response data", () => {
  const { audit, lines } = capturedLogger();
  const error = Object.assign(new Error("Request failed for https://u:p@api.test/x?ACCESS_TOKEN=hidden&mode=fast"), {
    category: "provider_error", status: 502,
    config: { url: "https://user:pass@api.test?key=do-not-log", headers: { Authorization: "Bearer do-not-log" } },
    response: { status: 502, data: { body: "provider secret" } },
  });
  audit.agentError({ requestId: "req-error-2", error });
  const output = lines.join("\n");
  for (const secret of ["u:p", "hidden", "do-not-log", "provider secret"]) assert.equal(output.includes(secret), false);
  assert.match(output, /provider_error/);
  assert.match(output, /502/);
  assert.match(output, /req-error-2/);
  assert.match(output, /mode=fast/);
});

test("malformed URL text is safely redacted without throwing", () => {
  const { audit, lines } = capturedLogger();
  assert.doesNotThrow(() => audit.investigationStarted({
    requestId: "req-malformed-3",
    target: "https://user:pass@host.test/%ZZ?token=still-secret&safe=yes%2",
  }));
  const output = lines.join("\n");
  assert.equal(output.includes("user:pass"), false);
  assert.equal(output.includes("still-secret"), false);
  assert.match(output, /safe=yes/);
  assert.match(output, /req-malformed-3/);
});

test("server error logging paths sanitize error objects and target metadata", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.match(source, /\[SECURITY REPORT\] Generation failed:[\s\S]{0,100}sanitizeLogValue\(error\)/);
  assert.match(source, /Unexpected error:[\s\S]{0,100}sanitizeLogValue\(error\)/);
  assert.match(source, /normalizedTarget: sanitizeLogValue\(/);
});
