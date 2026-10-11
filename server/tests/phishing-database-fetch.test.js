const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_FEED_URL,
  MAX_FEED_BYTES,
  createPhishingDatabaseTool,
  isApprovedFeedUrl,
} = require('../tools/external/phishing-database');

test('approved fixed HTTPS feed succeeds with a mocked response', async () => {
  let request;
  const tool = createPhishingDatabaseTool({
    fetchImpl: async (url, options) => {
      request = { url, options };
      return new Response('example.test\nphishing.test\n', { status: 200 });
    },
  });

  const result = await tool.execute({ domain: 'phishing.test' });

  assert.equal(request.url, DEFAULT_FEED_URL);
  assert.equal(request.options.method, 'GET');
  assert.equal(request.options.redirect, 'error');
  assert.equal(result.status, 'success');
  assert.equal(result.findings.match, true);
});

test('feed URL approval rejects invalid schemes and unapproved hosts', () => {
  assert.equal(isApprovedFeedUrl(DEFAULT_FEED_URL), true);
  assert.equal(isApprovedFeedUrl(DEFAULT_FEED_URL.replace('https:', 'http:')), false);
  assert.equal(isApprovedFeedUrl('https://localhost/feed.txt'), false);
  assert.equal(isApprovedFeedUrl('https://127.0.0.1/feed.txt'), false);
  assert.equal(isApprovedFeedUrl('https://example.test/feed.txt'), false);
  assert.equal(isApprovedFeedUrl('https://user:password@raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt'), false);
});

for (const destination of [
  'http://127.0.0.1/admin',
  'http://10.0.0.8/internal',
  'http://169.254.169.254/latest/meta-data/',
  'http://[::1]/internal',
  'http://[fe80::1]/internal',
]) {
  test(`feed fetch does not follow a redirect to ${new URL(destination).hostname}`, async () => {
    let calls = 0;
    let redirectMode;
    const tool = createPhishingDatabaseTool({
      fetchImpl: async (_url, options) => {
        calls += 1;
        redirectMode = options.redirect;
        return new Response(null, {
          status: 302,
          headers: { location: destination },
        });
      },
    });

    const result = await tool.execute({ domain: 'example.test' });

    assert.equal(redirectMode, 'error');
    assert.equal(calls, 1);
    assert.equal(result.status, 'unavailable');
    assert.equal(result.message, 'Feed unavailable: Feed returned HTTP 302');
  });
}

test('redirect chains cannot trigger a second request', async () => {
  let calls = 0;
  const tool = createPhishingDatabaseTool({
    fetchImpl: async (_url, options) => {
      calls += 1;
      assert.equal(options.redirect, 'error');
      return new Response(null, {
        status: 301,
        headers: { location: 'https://redirector.example.test/next' },
      });
    },
  });

  const result = await tool.execute({ domain: 'example.test' });

  assert.equal(calls, 1);
  assert.equal(result.status, 'unavailable');
});

test('oversized feed response is rejected before parsing and does not expose the URL', async () => {
  const tool = createPhishingDatabaseTool({
    fetchImpl: async () => new Response('x'.repeat(MAX_FEED_BYTES + 1), { status: 200 }),
  });

  const result = await tool.execute({ domain: 'example.test' });

  assert.equal(result.status, 'unavailable');
  assert.equal(result.message, 'Feed unavailable: Feed response exceeded the size limit');
  assert.equal(result.message.includes(DEFAULT_FEED_URL), false);
});

test('malformed feed content fails safely without replacing the cache', async () => {
  const tool = createPhishingDatabaseTool({
    fetchImpl: async () => new Response('<html><body>not a domain feed</body></html>', { status: 200 }),
  });

  const result = await tool.execute({ domain: 'example.test' });

  assert.equal(result.status, 'unavailable');
  assert.equal(result.message, 'Feed unavailable: Feed returned no usable domain entries');
});
