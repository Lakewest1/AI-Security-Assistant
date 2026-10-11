const test = require("node:test");
const assert = require("node:assert/strict");
const { isAllowedOrigin } = require("../CorsPolicy");
const { resolveRequiredTools } = require("../agent/RequiredToolResolver");
const { queryFor } = require("../tools/external/urlscan");
const { toVirusTotalUrlId } = require("../tools/external/virustotal");

test("development CORS allows Vite loopback origins on alternate ports only", () => {
  assert.equal(isAllowedOrigin("http://localhost:5174", { allowedOrigins: ["http://localhost:5173"], nodeEnv: "development" }), true);
  assert.equal(isAllowedOrigin("http://127.0.0.1:5180", { allowedOrigins: [], nodeEnv: "development" }), true);
  assert.equal(isAllowedOrigin("https://localhost:5174", { allowedOrigins: [], nodeEnv: "development" }), false);
  assert.equal(isAllowedOrigin("http://evil.example:5174", { allowedOrigins: [], nodeEnv: "development" }), false);
  assert.equal(isAllowedOrigin("http://localhost:5174", { allowedOrigins: [], nodeEnv: "production" }), false);
});

test("URL by itself and URL with check wording resolve to the same preserved target and plan", () => {
  const url = "https://galaxus-survey.srhie.com/galaxus-server/Galaxus.Checkout.php";
  const direct = resolveRequiredTools([{ role: "user", content: url }]);
  const instructed = resolveRequiredTools([{ role: "user", content: `Check this link: ${url}` }]);
  assert.deepEqual(direct.targets, instructed.targets);
  assert.equal(direct.targets[0].value, url);
  assert.deepEqual(direct.requiredTools, instructed.requiredTools);
  assert.equal(direct.requiredToolArguments.urlscan_lookup.url, url);
});

test("target resolution uses the latest user message, not earlier conversation targets", () => {
  const result = resolveRequiredTools([
    { role: "user", content: "Investigate 185.220.101.34" },
    { role: "assistant", content: "Previous target was 185.220.101.34" },
    { role: "user", content: "Investigate 197.210.29.24" },
  ]);
  assert.deepEqual(result.targets, [{ type: "ipv4", value: "197.210.29.24", valid: true }]);
  assert.equal(result.requiredToolArguments.virustotal_ip_lookup.ip, "197.210.29.24");
});

test("IP, URL, and domain investigations receive fixed provider plans", () => {
  const ip = resolveRequiredTools([{ role: "user", content: "Investigate 185.220.101.34" }]);
  const url = resolveRequiredTools([{ role: "user", content: "https://webbdmail.s3.us-west-004.backblazeb2.com/ARIELAFDGEFGSKDHJEHT_" }]);
  const domain = resolveRequiredTools([{ role: "user", content: "Investigate drwglobal.com" }]);
  assert.equal(ip.requiredTools.length, 6);
  assert.equal(url.requiredTools.length, 7);
  assert.equal(domain.requiredTools.length, 7);
  assert.ok(url.requiredTools.includes("virustotal_url_lookup"));
  assert.equal(url.targets[0].value, "https://webbdmail.s3.us-west-004.backblazeb2.com/ARIELAFDGEFGSKDHJEHT_");
});

test("model-visible definitions omit internal provider aliases and required tools", () => {
  const { getModelVisibleToolDefinitions } = require("../agent/AgentLoop");
  const tools = ["google-web-risk", "google_web_risk_lookup", "urlhaus", "urlhaus_lookup", "unique_tool"]
    .map((name) => ({ name }));
  const visible = getModelVisibleToolDefinitions(tools, ["google_web_risk_lookup"]);
  assert.deepEqual(visible.map((tool) => tool.name), ["google-web-risk", "urlhaus", "unique_tool"]);
});

test("URLScan queries preserve the complete URL and VirusTotal URL ids are unpadded URL-safe base64", () => {
  const url = "https://example.com/path/a?x=one&y=two";
  assert.match(queryFor({ url }, url), /^task\.url\.keyword:/);
  assert.match(queryFor({ url }, url), /canonical\.task\.url:/);
  assert.match(queryFor({ url }, url), /path/);
  const id = toVirusTotalUrlId(url);
  assert.equal(id.includes("="), false);
  assert.equal(Buffer.from(id, "base64url").toString("utf8"), url);
});
