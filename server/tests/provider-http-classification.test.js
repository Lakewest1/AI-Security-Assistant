const test = require('node:test');
const assert = require('node:assert/strict');
const { createCensysTool } = require('../tools/external/censys');
const { createMozillaObservatoryTool } = require('../tools/external/mozilla-observatory');
const { createGoogleWebRiskTool } = require('../tools/external/google-web-risk');
const { buildInvestigationFromEvidence } = require('../agent/Investigation');
const { ProviderHealth } = require('../agent/ProviderHealth');

async function withMockedFetch(status, run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { status: 'INVALID_ARGUMENT', message: 'fixture response' } }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test('provider target metadata constrains Censys to IP and supports URL/domain checks where intended', () => {
  assert.deepEqual(createCensysTool({}).targetTypes, ['ip']);
  assert.deepEqual(createMozillaObservatoryTool().targetTypes, ['domain', 'url']);
  assert.deepEqual(createGoogleWebRiskTool().targetTypes, ['url', 'domain']);
});

test('Censys HTTP 422 is classified as an invalid request without leaking credentials', async () => {
  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    const result = await withMockedFetch(422, () => createCensysTool({ apiToken: 'offline-test-token', timeoutMs: 50 }).execute({ ip: '192.0.2.1' }));
    assert.equal(result.status, 'invalid_request');
    assert.doesNotMatch(JSON.stringify(result), /offline-test-token/);
  } finally {
    console.warn = originalWarn;
  }
});

test('Censys non-success results and logs exclude provider-controlled details and stay tightly bounded', async () => {
  const originalFetch = globalThis.fetch;
  const originalWarn = console.warn;
  const logs = [];
  const syntheticSecrets = [
    'fake-api-key-123',
    'Bearer fake-bearer-token',
    'synthetic.user@example.test',
    'x'.repeat(6000),
  ];
  globalThis.fetch = async () => new Response(JSON.stringify({
    error: { api_key: syntheticSecrets[0], nested: { authorization: syntheticSecrets[1] } },
    code: 'FAKE_PROVIDER_CODE',
    message: `failed for ${syntheticSecrets[2]} ${syntheticSecrets[3]}`,
    detail: { arbitrary: syntheticSecrets[0] },
    title: syntheticSecrets[1],
    type: 'synthetic-type',
  }), { status: 422, headers: { 'content-type': 'application/json' } });
  console.warn = (...args) => logs.push(args);
  try {
    const result = await createCensysTool({ apiToken: 'offline-test-token', timeoutMs: 50 })
      .execute({ ip: '192.0.2.1' });

    assert.equal(result.status, 'invalid_request');
    assert.equal(result.message, 'Censys request failed');
    assert.ok(result.message.length <= 500);
    assert.equal(logs.length, 1);
    assert.equal(logs[0][0], '[Censys] Provider request failed');
    assert.deepEqual(logs[0][1], { status: 422, category: 'invalid_request' });
    assert.ok(Buffer.byteLength(JSON.stringify(logs[0]), 'utf8') <= 256);

    const output = JSON.stringify({ result, logs });
    for (const secret of [...syntheticSecrets, 'FAKE_PROVIDER_CODE', 'synthetic-type', 'offline-test-token']) {
      assert.equal(output.includes(secret), false, `unexpected disclosure: ${secret.slice(0, 30)}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    console.warn = originalWarn;
  }
});

test('Mozilla Observatory HTTP 422 is classified as invalid request', async () => {
  const result = await withMockedFetch(422, () => createMozillaObservatoryTool({ timeoutMs: 50 }).execute({ url: 'https://example.test/path' }));
  assert.equal(result.status, 'invalid_request');
});

test('Google Web Risk HTTP 403 is permission-denied, not a clean no-match', async () => {
  const result = await withMockedFetch(403, () => createGoogleWebRiskTool({ apiKey: 'offline-test-key', timeoutMs: 50 }).execute({ url: 'https://example.test/path' }));
  assert.equal(result.status, 'forbidden');
  assert.doesNotMatch(JSON.stringify(result), /no match|clean/i);
});

test('forbidden and invalid-request provider responses remain failed evidence and do not change threat scoring', () => {
  const investigation = buildInvestigationFromEvidence({
    target: 'https://example.test/path',
    targetType: 'url',
    expectedTools: ['google_web_risk_lookup', 'mozilla_observatory_scan'],
    rawToolEvidence: [
      { ok: true, toolName: 'google_web_risk_lookup', output: { status: 'forbidden', message: 'HTTP 403' } },
      { ok: true, toolName: 'mozilla_observatory_scan', output: { status: 'invalid_request', message: 'HTTP 422' } },
    ],
  });

  assert.deepEqual(investigation.sources.map((source) => source.status), ['forbidden', 'invalid_request']);
  assert.equal(investigation.coverage.failed, 2);
  assert.equal(investigation.coverage.noMatch, 0);
  assert.equal(investigation.risk.score, null);
  assert.equal(investigation.risk.independentProviderCount, 0);
  assert.equal(investigation.risk.environmentalRisk, 'unknown');
});

test('provider health keeps HTTP 403 permission state distinct from authentication failure', () => {
  const health = new ProviderHealth();
  health.recordResult('mozilla_observatory_scan', 'forbidden', 12);
  const row = health.getAll().find((provider) => provider.provider === 'mozilla_observatory');
  assert.equal(row.lastStatus, 'forbidden');
  assert.equal(row.reachable, true);
  assert.equal(row.authenticationValid, null);
  assert.match(row.failureReason, /permission or access restrictions/i);
});
