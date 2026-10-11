const test = require('node:test');
const assert = require('node:assert/strict');
const { buildInvestigationFromEvidence } = require('../agent/Investigation');
const { renderInvestigationReport } = require('../agent/SecurityAssessment');
const { ProviderHealth } = require('../agent/ProviderHealth');
const { statusForHttp } = require('../tools/external/provider-utils');

function success(toolName, findings) {
  return { ok: true, toolName, output: { status: 'success', findings, collectedAt: '2026-10-07T00:00:00.000Z' } };
}
function vtCase(target, malicious, suspicious, lastAnalysisDate) {
  const isLimitedIp = target === '94.240.240.229';
  const vtTool = /^\d+\.\d+\.\d+\.\d+$/.test(target) ? 'virustotal_ip_lookup' : target.includes('/') ? 'virustotal_url_lookup' : 'virustotal_domain_lookup';
  return buildInvestigationFromEvidence({
    target, targetType: /^\d+\.\d+\.\d+\.\d+$/.test(target) ? 'ip' : target.includes('/') ? 'url' : 'domain',
    rawToolEvidence: [success(vtTool, { malicious, suspicious, ...(lastAnalysisDate ? { lastAnalysisDate } : {}) }), ...(isLimitedIp ? [success('abuseipdb_ip_lookup', { abuseConfidenceScore: 0, totalReports: 0 })] : [])],
    expectedTools: [vtTool, ...(isLimitedIp ? ['abuseipdb_ip_lookup'] : [])],
  });
}

test('Stage 3 calibrated risk: a limited 3/1 VirusTotal result is elevated, not high', () => {
  const inv = vtCase('94.240.240.229', 3, 1, '2026-10-06');
  assert.ok(inv.risk.score >= 55 && inv.risk.score <= 65, `score ${inv.risk.score}`);
  assert.equal(inv.risk.externalThreat, 'elevated');
});

test('Stage 3 calibrated risk bounds one-provider domain results and preserves stale status', () => {
  const domain = vtCase('032ii.com', 4, 0, '2026-10-06');
  assert.ok(domain.risk.score >= 65 && domain.risk.score <= 75, `score ${domain.risk.score}`);
  assert.equal(domain.risk.independentProviderCount, 1);
  assert.equal(domain.correlations.some(item => item.type === 'independent_provider_reputation_corroboration'), false);

  const drwglobal = vtCase('drwglobal.com', 5, 1, '2026-08-02');
  assert.ok(drwglobal.risk.score >= 70 && drwglobal.risk.score <= 80, `score ${drwglobal.risk.score}`);
  assert.equal(drwglobal.risk.independentProviderCount, 1);
  assert.equal(drwglobal.correlations.some(item => item.type === 'independent_provider_reputation_corroboration'), false);

  const stale = vtCase('https://l7q5ny.sbs/t5hfcgpk/cbNF2f/VdAcWI', 13, 1, '2026-02-03');
  assert.ok(stale.risk.score >= 75 && stale.risk.score <= 85, `score ${stale.risk.score}`);
  assert.equal(stale.sources[0].freshness, 'stale');
  assert.match(stale.risk.rationale.join(' '), /stale/i);
});

test('provider health distinguishes configuration, authentication, rate limit, timeout, and successful response', () => {
  const health = new ProviderHealth();
  delete process.env.VIRUSTOTAL_API_KEY;
  health.recordStart('virustotal_ip_lookup');
  assert.equal(health.getAll().find(item => item.provider === 'virustotal').lastStatus, 'not_configured');

  process.env.VIRUSTOTAL_API_KEY = 'test-only-placeholder';
  health.recordResult('virustotal_ip_lookup', 'unauthorized', 12, 'secret-safe');
  let row = health.getAll().find(item => item.provider === 'virustotal');
  assert.equal(row.configured, true);
  assert.equal(row.authenticationValid, false);
  assert.equal(row.reachable, true);
  assert.doesNotMatch(JSON.stringify(row), /test-only-placeholder|secret-safe/);

  health.recordResult('virustotal_ip_lookup', 'timeout', 20);
  row = health.getAll().find(item => item.provider === 'virustotal');
  assert.equal(row.lastStatus, 'timeout');
  assert.equal(row.reachable, false);

  health.recordResult('virustotal_ip_lookup', 'rate_limited', 8);
  row = health.getAll().find(item => item.provider === 'virustotal');
  assert.equal(row.lastStatus, 'rate_limited');
  assert.equal(row.authenticationValid, true);

  health.recordResult('virustotal_ip_lookup', 'success', 7);
  row = health.getAll().find(item => item.provider === 'virustotal');
  assert.equal(row.lastStatus, 'success');
  assert.equal(row.authenticationValid, true);
  assert.ok(row.lastSuccessAt);
  health.recordResult('virustotal_ip_lookup', 'no_match', 6);
  row = health.getAll().find(item => item.provider === 'virustotal');
  assert.equal(row.lastStatus, 'no_match');
  assert.equal(row.authenticationValid, true);
  assert.equal(row.reachable, true);
  delete process.env.VIRUSTOTAL_API_KEY;
});

test('current-status confidence falls with stale evidence while external evidence confidence remains separate', () => {
  const build = (daysAgo) => vtCase(
    '203.0.113.40',
    5,
    1,
    new Date(Date.now() - daysAgo * 86_400_000).toISOString(),
  );
  const recent = build(1);
  const stale = build(120);

  assert.ok(recent.confidence.currentStatusConfidenceScore > stale.confidence.currentStatusConfidenceScore);
  assert.ok(recent.confidence.evidenceConfidenceScore > 0);
  assert.equal(recent.confidence.currentStatusConfidenceScore <= 95, true);
  assert.equal(stale.sources[0].freshness, 'stale');
  assert.match(renderInvestigationReport(stale), /Current-status confidence: \d+%/);
});

test('explicit no_match is a successful lookup and cannot create threat evidence from contradictory fields', () => {
  const investigation = buildInvestigationFromEvidence({
    target: 'example.test',
    targetType: 'domain',
    expectedTools: ['phishing_database_lookup'],
    rawToolEvidence: [{
      ok: true,
      toolName: 'phishing_database_lookup',
      output: { status: 'no_match', findings: { match: true, category: 'phishing' } },
    }],
  });

  assert.equal(investigation.sources[0].status, 'no_match');
  assert.equal(investigation.sources[0].findingType, 'no_match');
  assert.equal(investigation.sources[0].quality.meaningful, false);
  assert.equal(investigation.coverage.successful, 1);
  assert.equal(investigation.coverage.noMatch, 1);
  assert.equal(investigation.coverage.failed, 0);
  assert.equal(investigation.risk.score, null);
  assert.equal(investigation.mitre.length, 0);
  assert.doesNotMatch(renderInvestigationReport(investigation), /returned a phishing-domain match/i);
});

test('shared HTTP status mapping keeps auth, not-found, timeout, rate-limit, and provider failures distinct', () => {
  assert.equal(statusForHttp(200), 'error');
  assert.equal(statusForHttp(401), 'unauthorized');
  assert.equal(statusForHttp(403), 'forbidden');
  assert.equal(statusForHttp(422), 'invalid_request');
  assert.equal(statusForHttp(404), 'not_found');
  assert.equal(statusForHttp(408), 'timeout');
  assert.equal(statusForHttp(429), 'rate_limited');
  assert.equal(statusForHttp(503), 'unavailable');
});
