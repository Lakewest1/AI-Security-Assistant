const test = require("node:test");
const assert = require("node:assert/strict");
const { createHIBPTool } = require("../tools/external/hibp");
const AgentAuditLogger = require("../agent/AgentAuditLogger");
const { buildInvestigationFromEvidence } = require("../agent/Investigation");
const AgentLoop = require("../agent/AgentLoop");
const ToolRegistry = require("../agent/ToolRegistry");

const syntheticEmail = "stage217@example.test";
const originalFetch = global.fetch;

test.afterEach(() => { global.fetch = originalFetch; });

test("HIBP queries the exact input but does not repeat it in tool findings or evidence", async () => {
  let requestedUrl;
  let requestOptions;
  global.fetch = async (url, options) => {
    requestedUrl = String(url);
    requestOptions = options;
    return new Response(JSON.stringify([{
      Name: "SyntheticBreach",
      Title: "Synthetic Breach",
      Domain: "example.test",
      BreachDate: "2024-01-02",
      AddedDate: "2024-02-03",
      DataClasses: ["Email addresses", "Passwords"],
      IsVerified: true,
    }]), { status: 200, headers: { "content-type": "application/json" } });
  };

  const tool = createHIBPTool({ apiKey: "synthetic-key" });
  const result = await tool.execute({ email: syntheticEmail });
  assert.equal(requestedUrl, `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(syntheticEmail)}?truncateResponse=false`);
  assert.equal(requestOptions.headers["hibp-api-key"], "synthetic-key");
  assert.equal(result.findings.breached, true);
  assert.equal(result.findings.breachCount, 1);
  assert.equal(result.findings.breaches[0].name, "SyntheticBreach");
  assert.equal(Object.hasOwn(result.findings, "email"), false);
  assert.equal(result.evidence.some((item) => item.value === syntheticEmail), false);

  const investigation = buildInvestigationFromEvidence({
    target: syntheticEmail,
    targetType: "email",
    investigationId: "synthetic-investigation",
    rawToolEvidence: [{ ok: true, toolName: "hibp_lookup", output: result }],
    completed: true,
  });
  assert.equal(investigation.target, syntheticEmail, "canonical target remains available for attribution");
  assert.equal(investigation.targetIdentity.raw, null, "email is not duplicated in generic raw identity metadata");
  assert.equal(investigation.targetIdentity.normalized, syntheticEmail, "canonical identity remains intact");
  assert.equal(investigation.sources[0].target, syntheticEmail, "existing source attribution contract is preserved");
  assert.equal(investigation.sources[0].findings.breaches[0].name, "SyntheticBreach");
  assert.equal(JSON.stringify(investigation.sources[0].findings).includes(syntheticEmail), false);
});

test("HIBP no-match and partial-error results do not copy the address into result messages", async () => {
  const tool = createHIBPTool({ apiKey: "synthetic-key" });
  global.fetch = async () => new Response("{}", { status: 404 });
  const noMatch = await tool.execute({ email: syntheticEmail });
  assert.equal(noMatch.findings.breached, false);
  assert.equal(noMatch.findings.breachCount, 0);
  assert.equal(JSON.stringify(noMatch).includes(syntheticEmail), false);

  global.fetch = async () => new Response("synthetic", { status: 429 });
  const partial = await tool.execute({ email: syntheticEmail });
  assert.equal(partial.status, "rate_limited");
  assert.equal(JSON.stringify(partial).includes(syntheticEmail), false);

  global.fetch = async () => { throw new Error(`synthetic fetch failure for ${syntheticEmail}`); };
  const unavailable = await tool.execute({ email: syntheticEmail });
  assert.equal(unavailable.status, "unavailable");
  assert.equal(JSON.stringify(unavailable).includes(syntheticEmail), false);
});

test("existing audit logger masks the email in HIBP-related audit metadata", () => {
  const lines = [];
  const audit = new AgentAuditLogger({ logger: { log: (line) => lines.push(line) } });
  audit.investigationStarted({ requestId: "synthetic-request", target: syntheticEmail, provider: "hibp" });
  assert.equal(lines.join("\n").includes(syntheticEmail), false);
  assert.match(lines.join("\n"), /REDACTED_EMAIL/);
});

test("email report downloads use a generic filename", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.match(source, /test\(reportTarget\)/);
  assert.ok(source.includes('? "email-investigation"'));
});

test("AgentLoop keeps the exact query input but masks duplicate HIBP inputs in stored evidence and failures", async () => {
  const registry = new ToolRegistry();
  let executedInput;
  registry.register({
    name: "hibp_lookup",
    riskLevel: "read",
    async execute(input) {
      executedInput = input;
      return { ok: true, success: true, provider: "hibp", status: "success", findings: { breached: true, breachCount: 1, breaches: [{ name: "SyntheticBreach" }] }, evidence: [] };
    },
  });
  const loop = new AgentLoop({
    toolRegistry: registry,
    toolPolicy: { check: () => ({ allowed: true }) },
    toolValidator: { validate: () => ({ valid: true }) },
  });
  const state = {
    requiredTools: ["hibp_lookup"], requiredToolArguments: { hibp_lookup: { email: syntheticEmail } },
    target: { type: "email", value: syntheticEmail }, investigationId: "synthetic-investigation",
    startedAt: Date.now(), deadline: Date.now() + 5000, sameToolCounts: new Map(), toolCallCount: 0,
    executedToolFingerprints: new Set(), rawToolEvidence: [], toolResults: [], attemptedRequiredTools: [],
    completedRequiredTools: [], toolsUsed: [], executedToolCalls: [],
  };
  const execution = await loop._executeTool({
    state, toolName: "hibp_lookup", input: { email: syntheticEmail }, toolCallId: "synthetic-call",
    requestId: "synthetic-request", userContext: {}, iteration: 0, controllerExecuted: true,
  });
  assert.equal(executedInput.email, syntheticEmail, "provider execution receives the exact input");
  assert.equal(state.rawToolEvidence[0].input.email, "[REDACTED_EMAIL]");
  assert.equal(state.executedToolCalls[0].arguments.email, "[REDACTED_EMAIL]");
  assert.equal(execution.toolResult.content.includes(syntheticEmail), false);
  assert.equal(state.investigation.target, syntheticEmail);

  const failure = loop._failedToolResult("hibp_lookup", "failed-call", { email: syntheticEmail }, "SYNTHETIC_ERROR", "Lookup unavailable", false);
  assert.equal(JSON.stringify(failure).includes(syntheticEmail), false);
  assert.equal(failure.evidence.input.email, "[REDACTED_EMAIL]");
});
