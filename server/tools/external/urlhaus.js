const {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  normalizeHttpUrl,
  normalizeDomain,
  compactObject,
} = require("./provider-utils");

const DEFAULT_TIMEOUT_MS = Number(process.env.URLHAUS_TIMEOUT_MS) || 8000;
const API_BASE = "https://urlhaus-api.abuse.ch";

function normalizeInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (input.url) {
    const url = normalizeHttpUrl(input.url);
    return url ? { type: "url", value: url } : null;
  }
  const domain = normalizeDomain(input.domain);
  return domain ? { type: "domain", value: domain } : null;
}

function evidenceFields(record) {
  if (!record || typeof record !== "object") return {};
  return compactObject({
    id: record.id,
    urlhausReference: record.urlhaus_reference,
    url: record.url,
    urlStatus: record.url_status,
    host: record.host,
    dateAdded: record.date_added,
    lastOnline: record.last_online,
    threat: record.threat,
    reporter: record.reporter,
    tags: record.tags,
    payloads: record.payloads,
  });
}

function noMatch(target) {
  return {
    ok: true,
    success: true,
    provider: "urlhaus",
    status: "success",
    collectedAt: new Date().toISOString(),
    message: "No URLhaus match was returned for the checked indicator.",
    findings: { target, indicatorChecked: target, match: false, matches: [] },
    evidence: [
      { field: "target", value: target, source: "urlhaus" },
      { field: "match", value: false, source: "urlhaus" },
    ],
  };
}

function createURLhausTool({ authKey, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return {
    name: "urlhaus_lookup",
    description: "Look up a submitted URL or domain in URLhaus malware URL intelligence.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", minLength: 4, maxLength: 2048 },
        domain: { type: "string", minLength: 3, maxLength: 253 },
      },
      additionalProperties: false,
      minProperties: 1,
    },
    category: "threat-intelligence",
    targetTypes: ["url", "domain"],
    readOnly: true,
    destructive: false,
    riskLevel: "read",
    requiresApproval: false,

    async execute(input) {
      const target = normalizeInput(input);
      if (!target) return publicResult("urlhaus", "error", "Invalid URL or domain target");
      if (!authKey) return publicResult("urlhaus", "not_configured", "URLhaus Auth-Key is not configured");

      const endpoint = target.type === "url" ? `${API_BASE}/v1/url/` : `${API_BASE}/v1/host/`;
      const form = new URLSearchParams(target.type === "url" ? { url: target.value } : { host: target.value });

      try {
        const { response, payload } = await fetchWithRetry(endpoint, {
          method: "POST",
          body: form.toString(),
          timeoutMs,
          headers: {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Auth-Key": authKey,
          },
          maxRetries: 1,
        });

        if (response.status !== 200) {
          return publicResult("urlhaus", statusForHttp(response.status), `URLhaus returned HTTP ${response.status}`);
        }
        if (!payload || typeof payload !== "object") return publicResult("urlhaus", "error", "URLhaus returned an unexpected response shape");
        if (payload.query_status === "no_results") return noMatch(target.value);
        if (payload.query_status !== "ok") return publicResult("urlhaus", "error", `URLhaus returned query status ${String(payload.query_status || "unknown")}`);

        if (target.type === "url") {
          const details = evidenceFields(payload);
          const findings = compactObject({
            target: target.value,
            indicatorChecked: target.value,
            match: true,
            matches: [details],
          });
          return {
            ok: true,
            success: true,
            provider: "urlhaus",
            status: "success",
            collectedAt: new Date().toISOString(),
            findings,
            evidence: Object.entries(findings).map(([field, value]) => ({ field, value, source: "urlhaus" })),
          };
        }

        const findings = compactObject({
          target: target.value,
          indicatorChecked: target.value,
          match: true,
          host: payload.host,
          firstSeen: payload.firstseen,
          urlCount: payload.url_count,
          blacklists: payload.blacklists,
          matches: Array.isArray(payload.urls) ? payload.urls.slice(0, 20).map(evidenceFields) : [],
          urlhausReference: payload.urlhaus_reference,
        });
        return {
          ok: true,
          success: true,
          provider: "urlhaus",
          status: "success",
          collectedAt: new Date().toISOString(),
          findings,
          evidence: Object.entries(findings).map(([field, value]) => ({ field, value, source: "urlhaus" })),
        };
      } catch (error) {
        return publicResult("urlhaus", error?.category === "tool_timeout" ? "timeout" : "unavailable", error?.message || "URLhaus request failed");
      }
    },
  };
}

module.exports = { createURLhausTool };
