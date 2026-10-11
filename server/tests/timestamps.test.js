const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeTimestamp } = require("../agent/Timestamps");
const { buildInvestigationFromEvidence } = require("../agent/Investigation");
const { generateSecurityReport } = require("../reports/SecurityReportGenerator");

test("normalizes Unix seconds, Unix milliseconds, and ISO timestamps to UTC", () => {
  const expected = "2025-06-15T15:06:40.000Z";
  assert.equal(normalizeTimestamp(1750000000), expected);
  assert.equal(normalizeTimestamp(1750000000000), expected);
  assert.equal(normalizeTimestamp("2025-06-15T15:06:40Z"), expected);
});

test("returns unavailable for missing, malformed, pre-2000, and implausibly future timestamps", () => {
  for (const value of [null, undefined, "", "not-a-date", "0", 0, "1970-01-21T00:00:00Z"]) {
    assert.equal(normalizeTimestamp(value), null, String(value));
  }
  assert.equal(normalizeTimestamp("2200-01-01T00:00:00Z", { now: Date.UTC(2026, 0, 1) }), null);
});

test("invalid provider timestamps do not create fake freshness dates", () => {
  const investigation = buildInvestigationFromEvidence({
    target: "example.com",
    targetType: "domain",
    rawToolEvidence: [{
      ok: true,
      toolName: "virustotal_domain_lookup",
      output: { status: "success", findings: { lastAnalysisDate: "not-a-date" } },
    }],
  });
  assert.equal(investigation.sources[0].quality.freshness.status, "unknown");
  assert.equal(investigation.sources[0].quality.freshness.observedAt, null);
});

test("provider sources are tagged with the current investigation id and target", () => {
  const investigation = buildInvestigationFromEvidence({
    investigationId: "request-123",
    target: "197.210.29.24",
    targetType: "ip",
    rawToolEvidence: [{
      ok: true,
      toolName: "virustotal_ip_lookup",
      output: { status: "success", findings: { ip: "197.210.29.24", malicious: 0, suspicious: 0 } },
    }],
  });
  assert.equal(investigation.investigationId, "request-123");
  assert.equal(investigation.sources[0].investigationId, "request-123");
  assert.equal(investigation.sources[0].target, "197.210.29.24");
});

test("skipped required providers keep coverage partial and environmental risk unknown", () => {
  const investigation = buildInvestigationFromEvidence({
    target: "197.210.29.24",
    targetType: "ip",
    expectedTools: ["virustotal_ip_lookup", "abuseipdb_ip_lookup", "shodan_ip_lookup"],
    rawToolEvidence: [{
      ok: true,
      toolName: "virustotal_ip_lookup",
      output: { status: "success", findings: { malicious: 0, suspicious: 0 } },
    }],
  });
  assert.equal(investigation.risk.evidenceCoverage, "partial");
  assert.equal(investigation.risk.environmentalRisk, "unknown");
  assert.equal(investigation.sources.find((source) => source.provider === "shodan").status, "skipped");
  assert.deepEqual(investigation.coverage, {
    planned: 3,
    consulted: 1,
    providersConsulted: 1,
    successful: 1,
    providersSuccessful: 1,
    meaningful: 0,
    providersMeaningful: 0,
    contextual: 0,
    threatEvidence: 0,
    noMatch: 1,
    providersNoMatch: 1,
    notFound: 0,
    failed: 0,
    providersFailed: 0,
    unavailable: 0,
    coveragePercent: 0,
    executionPercent: 33,
  });
});

test("not-found is a consulted lookup, not a failure or a clean verdict", () => {
  const investigation = buildInvestigationFromEvidence({
    target: "https://example.com/path?x=1",
    targetType: "url",
    expectedTools: ["virustotal_url_lookup"],
    rawToolEvidence: [{
      ok: true,
      toolName: "virustotal_url_lookup",
      output: { status: "not_found", message: "No existing URL analysis was found", collectedAt: "2026-10-06T12:00:00Z" },
      completedAt: "2026-10-06T12:00:00Z",
    }],
  });
  assert.equal(investigation.coverage.consulted, 1);
  assert.equal(investigation.coverage.successful, 1);
  assert.equal(investigation.coverage.failed, 0);
  assert.equal(investigation.coverage.meaningful, 0);
  assert.equal(investigation.sources[0].status, "not_found");
  assert.equal(investigation.sources[0].meaningful, false);
  assert.equal(investigation.sources[0].analysisAt, null);
  assert.equal(investigation.sources[0].retrievedAt, "2026-10-06T12:00:00Z");
  assert.equal(investigation.targetIdentity.query, "?x=1");
});

test("provider authentication failures remain failed statuses and never become clean matches", () => {
  const investigation = buildInvestigationFromEvidence({
    target: "drwglobal.com",
    targetType: "domain",
    expectedTools: ["google_web_risk_lookup"],
    rawToolEvidence: [{
      ok: false,
      toolName: "google_web_risk_lookup",
      error: { code: "AUTHORIZATION_FAILED", message: "Provider credentials were rejected" },
      completedAt: "2026-10-06T12:00:00Z",
    }],
  });
  assert.equal(investigation.sources[0].status, "unauthorized");
  assert.equal(investigation.sources[0].meaningful, false);
  assert.equal(investigation.sources[0].errorCode, "AUTHORIZATION_FAILED");
  assert.equal(investigation.coverage.consulted, 1);
  assert.equal(investigation.coverage.failed, 1);
  assert.equal(investigation.risk.externalThreat, "unknown");
  assert.equal(investigation.risk.environmentalRisk, "unknown");
});

test("identical evidence produces identical deterministic risk factors and scores", () => {
  const args = {
    target: "185.220.101.34",
    targetType: "ip",
    expectedTools: ["virustotal_ip_lookup", "abuseipdb_ip_lookup"],
    rawToolEvidence: [
      { ok: true, toolName: "virustotal_ip_lookup", output: { status: "success", findings: { malicious: 5, suspicious: 1 } } },
      { ok: true, toolName: "abuseipdb_ip_lookup", output: { status: "success", findings: { abuseConfidenceScore: 90, totalReports: 20 } } },
    ],
  };
  const first = buildInvestigationFromEvidence(args);
  const second = buildInvestigationFromEvidence(args);
  assert.equal(first.risk.score, second.risk.score);
  assert.deepEqual(first.risk.factors, second.risk.factors);
  assert.equal(first.confidence.score, second.confidence.score);
  assert.deepEqual(first.confidence.confidenceFactors, second.confidence.confidenceFactors);
  assert.ok(first.correlations.some((item) => item.type === "multi_engine_corroboration"));
  assert.ok(first.correlations.some((item) => item.type === "reputation_corroboration"));
});

test("security report generation still returns a PDF buffer", async () => {
  const pdf = await generateSecurityReport({
    investigation: { target: "example.com", targetType: "domain", sources: [], findings: [], correlations: [], limitations: ["No provider evidence"] },
  });
  assert.ok(Buffer.isBuffer(pdf));
  assert.equal(pdf.subarray(0, 5).toString(), "%PDF-");
});
