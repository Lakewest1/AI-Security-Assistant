const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("/api/agent initializes the returned investigation before reading its target", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  const investigationInitialization = source.indexOf("const investigation =\n        result.investigation");
  const targetRead = source.indexOf("investigation?.target ||", investigationInitialization);
  assert.notEqual(investigationInitialization, -1, "route must bind the investigation from the orchestrator result");
  assert.notEqual(targetRead, -1, "route must read the target from the initialized investigation");
  assert.ok(investigationInitialization < targetRead, "investigation must be initialized before target access");
});

test("/api/agent gets capability context only from the server request resolver", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "agent-server.js"), "utf8");
  assert.match(source, /userContext:\s*getRequestCapabilityContext\(req\)/);
  assert.doesNotMatch(source, /userContext:\s*req\.(?:body|query|headers)/);
});
