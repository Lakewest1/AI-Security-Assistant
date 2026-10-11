const test = require('node:test');
const assert = require('node:assert/strict');
const { buildCurator } = require('../agent/InvestigationNarrative');
const { buildInvestigationFromEvidence } = require('../agent/Investigation');
const { renderInvestigationReport } = require('../agent/SecurityAssessment');
const { generateSecurityReport } = require('../reports/SecurityReportGenerator');
const { calculateRisk } = require('../agent/RiskScoring');

test('canonical investigation includes cautious narrative in the chat report output', () => {
  const investigation = buildInvestigationFromEvidence({
    target: 'example.test',
    targetType: 'domain',
    rawToolEvidence: [],
    expectedTools: [],
  });

  assert.match(investigation.curator.whatMatters, /insufficient to establish/i);
  assert.match(investigation.curator.whatWeDoNotKnow, /No internal telemetry/);
  assert.match(investigation.curator.recommendedNextStep, /Search DNS, proxy/);
  const output = renderInvestigationReport(investigation);
  assert.match(output, /What matters:/);
  assert.match(output, /What remains unknown:/);
  assert.match(output, /No internal telemetry/);
});

test('narrative separates aged threat evidence from current-status confidence', () => {
  const narrative = buildCurator({
    target: '203.0.113.5',
    targetType: 'ip',
    sources: [{
      provider: 'virustotal',
      status: 'success',
      findingType: 'reputation',
      findings: { malicious: 3, suspicious: 0 },
      quality: { meaningful: true, freshness: { status: 'stale' } },
      providerAnalysisAt: '2024-01-01T00:00:00.000Z',
    }],
    risk: { externalThreat: 'moderate', environmentalRisk: 'unknown', independentProviderCount: 1 },
    confidence: { evidenceConfidenceLevel: 'moderate', currentStatusConfidenceLevel: 'low', currentStatusConfidenceScore: 20 },
    coverage: { failed: 0 },
  });

  assert.match(narrative.whatMatters, /historical reputation evidence/i);
  assert.match(narrative.freshnessNote, /age reduces confidence/i);
  assert.equal(narrative.confidence.currentStatus, 'Low');
  assert.equal(narrative.confidence.currentStatusScore, 20);
});

test('tracking URL guidance does not claim an unobserved redirect destination', () => {
  const narrative = buildCurator({ target: 'https://example.test/redirect?url=https%3A%2F%2Fevil.test', targetType: 'url', sources: [], risk: {}, confidence: {} });

  assert.match(narrative.recommendedNextStep, /controlled, isolated investigation environment/);
  assert.match(narrative.recommendedNextStep, /No redirect or destination is verified/);
  assert.doesNotMatch(narrative.recommendedNextStep, /redirected to evil\.test/i);
});

test('IP narrative preserves reputation, identity, service, Tor, and unknown-impact distinctions', () => {
  const success = (toolName, findings) => ({ ok: true, toolName, output: { status: 'success', findings, collectedAt: '2026-10-07T00:00:00.000Z' } });
  const investigation = buildInvestigationFromEvidence({
    target: '185.220.101.34',
    targetType: 'ip',
    expectedTools: ['virustotal_ip_lookup', 'abuseipdb_ip_lookup', 'ipinfo_ip_lookup', 'shodan_ip_lookup', 'censys_ip_lookup'],
    rawToolEvidence: [
      success('virustotal_ip_lookup', { malicious: 16, suspicious: 3, lastAnalysisDate: '2026-10-06' }),
      success('abuseipdb_ip_lookup', { abuseConfidenceScore: 100, totalReports: 252, lastReportedAt: '2026-10-07' }),
      success('ipinfo_ip_lookup', { country: 'Germany', city: 'Berlin', hostname: 'tor-exit-34.example.test', organization: 'Example Network' }),
      success('shodan_ip_lookup', { organization: 'Example Network', hostnames: ['tor-exit-34.example.test'], ports: [80, 10134] }),
      { ok: true, toolName: 'censys_ip_lookup', output: { status: 'error', message: 'HTTP 422' } },
    ],
  });

  assert.match(investigation.curator.whatMatters, /VirusTotal returned 16 malicious and 3 suspicious/);
  assert.match(investigation.curator.whatMatters, /AbuseIPDB reported 100% abuse confidence across 252 reports/);
  assert.match(investigation.curator.importantContext, /Germany, Berlin/);
  assert.match(investigation.curator.importantContext, /ports 80, 10134/);
  assert.match(investigation.curator.importantContext, /Tor-exit/);
  assert.match(investigation.curator.whatWeDoNotKnow, /No internal telemetry/);
  assert.equal(investigation.risk.externalThreat, 'critical');
  assert.equal(investigation.risk.environmentalRisk, 'unknown');
  const output = renderInvestigationReport(investigation);
  assert.ok(output.includes(investigation.curator.whatMatters));
  assert.ok(output.includes(investigation.curator.importantContext));
  assert.match(output, /bounded heuristic.*not a probability/i);
});

test('URL engine detections from one provider are not described as independent corroboration', () => {
  const investigation = buildInvestigationFromEvidence({
    target: 'https://example.test/path',
    targetType: 'url',
    expectedTools: ['virustotal_url_lookup', 'google_web_risk_lookup', 'urlhaus_lookup'],
    rawToolEvidence: [
      { ok: true, toolName: 'virustotal_url_lookup', output: { status: 'success', findings: { malicious: 4, suspicious: 0 } } },
      { ok: true, toolName: 'google_web_risk_lookup', output: { status: 'forbidden', message: 'HTTP 403' } },
      { ok: true, toolName: 'urlhaus_lookup', output: { status: 'no_match', findings: { match: false } } },
    ],
  });

  assert.match(investigation.curator.whatMatters, /4 malicious and 0 suspicious/);
  assert.match(investigation.curator.whatMatters, /one provider and lack independent malicious-reputation corroboration/);
  assert.doesNotMatch(investigation.curator.whatMatters, /independent sources also contributed/);
  assert.equal(investigation.risk.independentProviderCount, 1);
  assert.equal(investigation.risk.environmentalRisk, 'unknown');
});

test('unknown threat freshness is stated as undated, not current', () => {
  const narrative = buildCurator({
    target: '198.51.100.8',
    targetType: 'ip',
    sources: [{ provider: 'virustotal', status: 'success', findingType: 'reputation', quality: { meaningful: true, freshness: { status: 'unknown' } }, findings: { malicious: 2, suspicious: 0 } }],
    risk: { externalThreat: 'elevated', independentProviderCount: 1, environmentalRisk: 'unknown' },
  });

  assert.match(narrative.freshnessNote, /Freshness could not be verified/);
  assert.match(narrative.freshnessNote, /not verified current activity/);
  for (const field of ['whatMatters', 'importantContext', 'whatWeDoNotKnow', 'recommendedNextStep']) {
    assert.ok(narrative[field].trim().length > 0, `${field} should not be empty`);
  }
});

test('unrelated successful infrastructure queries do not raise direct-reputation confidence', () => {
  const threat = {
    provider: 'virustotal', status: 'success', evidenceId: 'vt-evidence',
    findings: { malicious: 5, suspicious: 1 }, quality: { meaningful: true, freshness: { status: 'recent' } },
  };
  const investigation = { coverage: { planned: 1 }, sources: [threat], targetIdentity: { normalized: '198.51.100.8' }, conflicts: [] };
  const failedProvider = { provider: 'censys', status: 'invalid_request' };
  const baseline = calculateRisk({ investigation, successful: [threat], failed: [failedProvider] });
  const contextualSources = ['shodan', 'ipinfo', 'censys', 'urlscan'].map((provider) => ({
    provider, status: 'success', findings: { organization: 'Example Network' },
    quality: { meaningful: true, freshness: { status: 'unknown' }, directness: 'observational/contextual' },
  }));
  const withContext = calculateRisk({
    investigation: { ...investigation, coverage: { planned: 5 }, sources: [threat, ...contextualSources] },
    successful: [threat, ...contextualSources],
    failed: [failedProvider],
  });

  assert.equal(withContext.externalConfidenceScore, baseline.externalConfidenceScore);
  assert.equal(withContext.currentStatusConfidenceScore, baseline.currentStatusConfidenceScore);
  assert.equal(withContext.score, baseline.score);
  assert.equal(withContext.calibratedProbability, false);
});

test('PDF report generation accepts the canonical investigation narrative', async () => {
  const investigation = buildInvestigationFromEvidence({
    target: 'example.test',
    targetType: 'domain',
    rawToolEvidence: [],
    expectedTools: [],
  });
  const pdf = await generateSecurityReport({ investigation });

  assert.ok(Buffer.isBuffer(pdf));
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
});
