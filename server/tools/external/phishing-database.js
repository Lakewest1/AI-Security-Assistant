/**
 * Phishing.Database active-domain feed provider.
 *
 * Free/local-feed threat-intelligence source. The feed is cached in memory
 * and refreshed periodically; investigations never download the full feed
 * for each request.
 */

const DEFAULT_FEED_URL =
  'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt';
const MAX_FEED_BYTES = 5 * 1024 * 1024;

function isApprovedFeedUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' &&
      url.hostname === 'raw.githubusercontent.com' &&
      !url.username &&
      !url.password &&
      !url.port &&
      url.pathname === '/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt' &&
      !url.search &&
      !url.hash;
  } catch (_) {
    return false;
  }
}

async function readTextLimited(response, maxBytes) {
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new Error('Feed response body is unavailable');
  }

  const contentLength = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Error('Feed response exceeded the size limit');
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error('Feed response exceeded the size limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (_) {
    throw new Error('Feed response was not valid UTF-8 text');
  }
}

function normalizeDomain(input) {
  const raw = String(input?.domain || input?.url || input || '').trim();
  if (!raw) return null;

  try {
    const candidate = raw.includes('://') ? raw : `https://${raw}`;
    const parsed = new URL(candidate);
    let hostname = String(parsed.hostname || '').toLowerCase().trim();

    hostname = hostname.replace(/^\.+|\.+$/g, '');
    hostname = hostname.replace(/^www\./i, '');

    if (!hostname || hostname.length > 253) return null;
    if (hostname.includes('..')) return null;
    if (!hostname.includes('.')) return null;
    return hostname;
  } catch (_) {
    return null;
  }
}

function normalizeFeedEntry(line) {
  let value = String(line || '').trim();
  if (!value || value.startsWith('#') || value.startsWith('!')) return null;

  // The .txt feed is expected to contain domains, but tolerate accidental
  // surrounding whitespace/comments without accepting URLs as substrings.
  value = value.split(/\s+/)[0];
  return normalizeDomain(value);
}

function parseFeed(text) {
  const domains = new Set();
  for (const line of String(text || '').split(/\r?\n/)) {
    const domain = normalizeFeedEntry(line);
    if (domain) domains.add(domain);
  }
  return domains;
}

function createPhishingDatabaseTool({
  timeoutMs = 10000,
  refreshIntervalMs = 6 * 60 * 60 * 1000,
  fetchImpl = globalThis.fetch,
} = {}) {
  let cache = null;
  let cacheLoadedAt = 0;
  let refreshPromise = null;

  async function refreshFeed() {
    if (refreshPromise) return refreshPromise;

    refreshPromise = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        if (!isApprovedFeedUrl(DEFAULT_FEED_URL)) {
          throw new Error('Feed destination is not approved');
        }
        if (typeof fetchImpl !== 'function') {
          throw new Error('Feed fetch is unavailable');
        }

        const response = await fetchImpl(DEFAULT_FEED_URL, {
          method: 'GET',
          redirect: 'error',
          headers: {
            Accept: 'text/plain',
            'User-Agent': 'Lakewest-AI-Security-Assistant/1.0',
          },
          signal: controller.signal,
        });

        if (response.status !== 200) {
          throw new Error(`Feed returned HTTP ${response.status}`);
        }

        const body = await readTextLimited(response, MAX_FEED_BYTES);
        const domains = parseFeed(body);
        if (!domains.size) {
          throw new Error('Feed returned no usable domain entries');
        }

        cache = domains;
        cacheLoadedAt = Date.now();

        console.info(
          `[Phishing.Database] Active domain feed refreshed (${domains.size} normalized domains)`
        );

        return { domains, stale: false };
      } catch (error) {
        const message =
          error?.name === 'AbortError'
            ? `Feed download timed out after ${timeoutMs}ms`
            : error?.message === 'Feed response exceeded the size limit'
              ? error.message
              : error?.message === 'Feed response was not valid UTF-8 text'
                ? error.message
                : error?.message === 'Feed returned no usable domain entries'
                  ? error.message
                  : /^Feed returned HTTP \d{3}$/.test(error?.message || '')
                    ? error.message
                    : 'Feed download failed';

        if (cache && cache.size) {
          console.warn(
            `[Phishing.Database] Feed refresh failed; using cached feed: ${message}`
          );
          return { domains: cache, stale: true, refreshError: message };
        }

        throw new Error(`Feed unavailable: ${message}`);
      } finally {
        clearTimeout(timer);
        refreshPromise = null;
      }
    })();

    return refreshPromise;
  }

  async function getFeed() {
    const freshEnough =
      cache &&
      cache.size > 0 &&
      Date.now() - cacheLoadedAt < refreshIntervalMs;

    if (freshEnough) {
      return { domains: cache, stale: false };
    }

    return refreshFeed();
  }

  return {
    name: 'phishing_database',
    description:
      'Check a domain against the free Phishing.Database active phishing-domain feed',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', minLength: 1, maxLength: 253 },
        url: { type: 'string', minLength: 1, maxLength: 2048 },
      },
      additionalProperties: false,
    },
    category: 'threat-intelligence',
    targetTypes: ['domain', 'url'],
    readOnly: true,
    destructive: false,
    riskLevel: 'read',
    requiresApproval: false,

    async execute(input) {
      const domain = normalizeDomain(input);

      if (!domain) {
        return {
          ok: true,
          success: true,
          provider: 'phishing_database',
          status: 'error',
          collectedAt: new Date().toISOString(),
          message: 'Invalid domain or URL',
          findings: {},
          evidence: [],
        };
      }

      try {
        const { domains, stale, refreshError } = await getFeed();
        const match = domains.has(domain);

        return {
          ok: true,
          success: true,
          provider: 'phishing_database',
          status: stale ? 'partial' : 'success',
          collectedAt: new Date().toISOString(),
          message: match
            ? 'Exact normalized domain match found in the active Phishing.Database feed'
            : 'No exact normalized domain match found in the active Phishing.Database feed',
          findings: {
            domain,
            match,
            ...(match ? { classification: 'phishing' } : {}),
            feed: 'phishing-domains-ACTIVE.txt',
            cacheLoadedAt: cacheLoadedAt
              ? new Date(cacheLoadedAt).toISOString()
              : null,
            ...(stale ? { feedRefresh: 'stale', refreshError } : {}),
          },
          evidence: [
            {
              type: 'feed_match',
              source: 'Phishing.Database',
              domain,
              match,
              feed: 'phishing-domains-ACTIVE.txt',
            },
          ],
          limitations: [
            'A no-match result means the domain was not present in this feed at lookup time; it does not prove the domain is safe.',
            ...(stale
              ? ['The cached feed could not be refreshed during this lookup.']
              : []),
          ],
        };
      } catch (error) {
        return {
          ok: true,
          success: true,
          provider: 'phishing_database',
          status: 'unavailable',
          collectedAt: new Date().toISOString(),
          message: error?.message || 'Feed unavailable',
          findings: {
            domain,
          },
          evidence: [],
          limitations: [
            'The active Phishing.Database feed was unavailable; no clean or no-match conclusion was made.',
          ],
        };
      }
    },
  };
}

module.exports = {
  DEFAULT_FEED_URL,
  MAX_FEED_BYTES,
  isApprovedFeedUrl,
  normalizeDomain,
  parseFeed,
  createPhishingDatabaseTool,
};
