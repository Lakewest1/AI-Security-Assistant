const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repositoryRoot = path.join(__dirname, "..");
const packageJson = require(path.join(repositoryRoot, "package.json"));

test("start:agent targets the active backend and preserves existing start scripts", () => {
  assert.equal(packageJson.scripts["start:agent"], "node server/agent-server.js");
  assert.equal(packageJson.scripts.start, "node server.js");
  assert.equal(packageJson.scripts.dev, "nodemon server.js");
  assert.equal(fs.existsSync(path.join(repositoryRoot, "server", "agent-server.js")), true);
});
