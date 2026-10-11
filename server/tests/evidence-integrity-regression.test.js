const test = require('node:test');
const assert = require('node:assert/strict');
const { buildInvestigationFromEvidence, normalizeSource } = require('../agent/Investigation');
const { deriveFinalInvestigationAssessment } = require('../agent/SecurityAssessment');
const { resolveRequiredTools } = require('../agent/RequiredToolResolver');

function success(toolName, findings) {
  return { ok: true, toolName, output: { status: 'success', findings, collectedAt: '2026-10-07T00:00:00.000Z' } };
}

test('empty ThreatFox, Phishing.Database false, and URLScan zero results are successful no-matches', () => {
  const cases = [
    success('threatfox_lookup', { matches: [] }),
    success('phishing_database_lookup', { match: false }),
    success('urlscan_lookup', { totalResults: 0, results: [] }),
    success('virustotal_url_lookup', { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 }),
  ];
  for (const evidence of cases) {
    const source = normalizeSource(evidence, { target: 'https://example.com/path_', targetType: 'url' });
    assert.equal(source.status, 'success');
    assert.equal(source.meaningful, false, evidence.toolName);
    assert.equal(source.findingType, 'no_match', evidence.toolName);
  }
});

test('URLScan observations are contextual meaningful evidence, not a threat match', () => {
  const source = normalizeSource(success('urlscan_lookup', { totalResults: 2, results: [{ page: { ip: '192.0.2.10' } }] }));
  assert.equal(source.meaningful, true);
  assert.equal(source.findingType, 'context_only');
});

test('bare domain paths preserve trailing underscores and adapt absolute provider URLs', () => {
  const target = 'webbdmail.s3.us-west-004.backblazeb2.com/ARIELAFDGEFGSKDHJEHT_';
  const plan = resolveRequiredTools([{ role: 'user', content: `Investigate ${target}` }]);
  assert.equal(plan.targets[0].type, 'url');
  assert.equal(plan.targets[0].value, target);
  assert.equal(plan.requiredToolArguments.virustotal_url_lookup.url, `https://${target}`);
  const inv = buildInvestigationFromEvidence({ target, targetType: 'url' });
  assert.equal(inv.targetIdentity.path, '/ARIELAFDGEFGSKDHJEHT_');
});

test('URL coverage separately counts meaningful, no-match, not-found, and failed providers', () => {
  const tools = [
    'virustotal_url_lookup', 'urlscan_lookup', 'urlhaus_lookup', 'threatfox_lookup',
    'phishing_database_lookup', 'google_web_risk_lookup', 'mozilla_observatory_scan',
  ];
  const evidence = [
    success('virustotal_url_lookup', { malicious: 4, suspicious: 0, harmless: 56, undetected: 32, lastAnalysisDate: '2026-08-02' }),
    success('urlscan_lookup', { totalResults: 2, results: [{ page: { ip: '192.0.2.1' } }] }),
    success('threatfox_lookup', { matches: [] }),
    success('phishing_database_lookup', { match: false }),
    { ok: true, toolName: 'urlhaus_lookup', output: { status: 'timeout' } },
    { ok: true, toolName: 'google_web_risk_lookup', output: { status: 'unauthorized' } },
    { ok: true, toolName: 'mozilla_observatory_scan', output: { status: 'timeout' } },
  ];
  const inv = buildInvestigationFromEvidence({
    target: 'https://example.com/', targetType: 'url', investigationId: 'regression-1',
    rawToolEvidence: evidence, expectedTools: tools,
  });
  assert.deepEqual(
    { consulted: inv.coverage.consulted, successful: inv.coverage.successful, meaningful: inv.coverage.meaningful, noMatch: inv.coverage.noMatch, failed: inv.coverage.failed },
    { consulted: 7, successful: 4, meaningful: 2, noMatch: 2, failed: 3 },
  );
  assert.equal(inv.target, 'https://example.com/');
  assert.equal(inv.risk.environmentalRisk, 'unknown');
  assert.equal(inv.risk.externalThreat, 'elevated');
  const reportAssessment = deriveFinalInvestigationAssessment(inv);
  assert.deepEqual(
    [reportAssessment.consultedSourceCount, reportAssessment.successfulProviderCount, reportAssessment.meaningfulProviderCount, reportAssessment.noMatchProviderCount, reportAssessment.failedProviderCount],
    [7, 4, 2, 2, 3],
  );
});

test('VirusTotal not-found is a successful lookup category but not a match or failure', () => {
  const inv = buildInvestigationFromEvidence({
    target: 'https://example.com/', targetType: 'url',
    rawToolEvidence: [{ ok: true, toolName: 'virustotal_url_lookup', output: { status: 'not_found', message: 'No existing analysis' } }],
    expectedTools: ['virustotal_url_lookup'],
  });
  assert.equal(inv.coverage.successful, 1);
  assert.equal(inv.coverage.notFound, 1);
  assert.equal(inv.coverage.noMatch, 0);
  assert.equal(inv.coverage.failed, 0);
  assert.equal(inv.sources[0].meaningful, false);
  assert.equal(inv.risk.externalThreat, 'unknown');
  assert.equal(inv.risk.score, null);
});

test('historical VirusTotal reputation keeps provider analysis date and reproducible factor evidence', () => {
  const inv = buildInvestigationFromEvidence({
    target: 'https://example.com/path_token_', targetType: 'url', investigationId: 'vt-history',
    rawToolEvidence: [success('virustotal_url_lookup', {
      evidenceId: 'vt-evidence-1', malicious: 13, suspicious: 1, harmless: 52, undetected: 28, lastAnalysisDate: '2026-02-03',
    })],
    expectedTools: ['virustotal_url_lookup'],
  });
  const source = inv.sources[0];
  assert.equal(inv.targetIdentity.path, '/path_token_');
  assert.equal(source.providerAnalysisAt, '2026-02-03T00:00:00.000Z');
  assert.equal(source.retrievedAt, '2026-10-07T00:00:00.000Z');
  assert.equal(source.freshness, 'stale');
  assert.equal(source.evidenceId, 'vt-evidence-1');
  assert.equal(source.findingType, 'reputation');
  assert.equal(inv.risk.factors.reduce((sum, factor) => sum + factor.contribution, 0), inv.risk.score);
  assert.ok(inv.risk.factors.every(factor => 'signal' in factor && 'evidenceSource' in factor && 'evidenceId' in factor));
  assert.notEqual(inv.risk.score, inv.confidence.score);
});

test('185.220.101.34 fixture remains a strong external warning with unknown environment impact', () => {
  const tools = ['virustotal_ip_lookup', 'abuseipdb_ip_lookup', 'ipinfo_ip_lookup', 'shodan_ip_lookup', 'censys_ip_lookup', 'viewdns_lookup'];
  const inv = buildInvestigationFromEvidence({
    target: '185.220.101.34', targetType: 'ip', expectedTools: tools,
    rawToolEvidence: [
      success('virustotal_ip_lookup', { malicious: 16, suspicious: 3, harmless: 44, undetected: 29, lastAnalysisDate: '2026-10-06' }),
      success('abuseipdb_ip_lookup', { abuseConfidenceScore: 100, totalReports: 252, lastReportedAt: '2026-10-07' }),
      success('ipinfo_ip_lookup', { country: 'Germany', city: 'Berlin', hostname: 'tor-exit-34.for-privacy.net', organization: 'AS60729 Stiftung Erneuerbare Freiheit' }),
      success('shodan_ip_lookup', { organization: 'ForPrivacyNET', asn: 'AS60729', hostnames: ['tor-exit-34.for-privacy.net'], ports: [80, 10134] }),
      { ok: true, toolName: 'censys_ip_lookup', output: { status: 'error' } },
      { ok: true, toolName: 'viewdns_lookup', output: { status: 'error' } },
    ],
  });
  assert.equal(inv.risk.externalThreat, 'critical');
  assert.ok(inv.risk.score >= 95 && inv.risk.score <= 100);
  assert.equal(inv.risk.environmentalRisk, 'unknown');
  assert.ok(inv.correlations.some(item => item.type === 'multi_engine_corroboration'));
  assert.ok(inv.correlations.some(item => item.type === 'reputation_corroboration'));
  assert.ok(inv.correlations.some(item => item.type === 'identity_corroboration'));
  assert.ok(inv.correlations.some(item => item.type === 'tor_infrastructure_context'));
  assert.ok(inv.risk.factors.reduce((sum, factor) => sum + factor.contribution, 0) === inv.risk.score);
});

test('94.240.240.229 fixture stays distinct from the strongly corroborated IP', () => {
  const inv = buildInvestigationFromEvidence({
    target: '94.240.240.229', targetType: 'ip',
    rawToolEvidence: [
      success('virustotal_ip_lookup', { malicious: 5, suspicious: 1, harmless: 40, undetected: 30, lastAnalysisDate: '2026-10-06' }),
      success('abuseipdb_ip_lookup', { abuseConfidenceScore: 0, totalReports: 0 }),
      success('ipinfo_ip_lookup', { country: 'Georgia', organization: 'Magticom' }),
    ],
  });
  assert.equal(inv.target, '94.240.240.229');
  assert.equal(inv.risk.environmentalRisk, 'unknown');
  assert.notEqual(inv.risk.externalThreat, 'critical');
  assert.equal(inv.correlations.some(item => item.type === 'reputation_corroboration'), false);
});

test('webbdmail path fixture preserves its underscore and remains unknown on no-match/unavailable evidence', () => {
  const target = 'webbdmail.s3.us-west-004.backblazeb2.com/ARIELAFDGEFGSKDHJEHT_';
  const tools = ['virustotal_url_lookup', 'urlscan_lookup', 'urlhaus_lookup', 'threatfox_lookup', 'phishing_database_lookup', 'google_web_risk_lookup', 'mozilla_observatory_scan'];
  const inv = buildInvestigationFromEvidence({
    target, targetType: 'url', expectedTools: tools,
    rawToolEvidence: [
      { ok: true, toolName: 'virustotal_url_lookup', output: { status: 'not_found', message: 'No existing analysis' } },
      success('urlscan_lookup', { totalResults: 0, observations: [] }),
      { ok: true, toolName: 'urlhaus_lookup', output: { status: 'timeout' } },
      success('threatfox_lookup', { matches: [] }),
      success('phishing_database_lookup', { match: false }),
      { ok: true, toolName: 'google_web_risk_lookup', output: { status: 'unauthorized' } },
      { ok: true, toolName: 'mozilla_observatory_scan', output: { status: 'timeout' } },
    ],
  });
  assert.equal(inv.target, target);
  assert.equal(inv.targetIdentity.path, '/ARIELAFDGEFGSKDHJEHT_');
  assert.equal(inv.risk.externalThreat, 'unknown');
  assert.equal(inv.risk.environmentalRisk, 'unknown');
  assert.equal(inv.coverage.noMatch, 3);
  assert.equal(inv.coverage.notFound, 1);
  assert.equal(inv.coverage.failed, 3);
});

test('drwglobal VT and phishing evidence remain separate, attributed, and cross-provider correlated', () => {
  const inv = buildInvestigationFromEvidence({
    target: 'drwglobal.com', targetType: 'domain',
    rawToolEvidence: [
      success('virustotal_domain_lookup', { malicious: 5, suspicious: 1, harmless: 56, undetected: 32, lastAnalysisDate: '2026-08-02' }),
      success('phishing_database_lookup', { domain: 'drwglobal.com', match: true, classification: 'phishing' }),
      success('urlscan_lookup', { totalResults: 0, observations: [] }),
      success('threatfox_lookup', { matches: [] }),
      { ok: true, toolName: 'urlhaus_lookup', output: { status: 'timeout' } },
    ],
  });
  assert.equal(inv.risk.environmentalRisk, 'unknown');
  assert.equal(inv.sources.find(source => source.provider === 'virustotal').findingType, 'reputation');
  assert.equal(inv.sources.find(source => source.provider === 'phishing_database').findingType, 'reputation');
  assert.ok(inv.correlations.some(item => item.type === 'multi_engine_corroboration'));
  assert.ok(inv.correlations.some(item => item.type === 'independent_provider_reputation_corroboration'));
});
