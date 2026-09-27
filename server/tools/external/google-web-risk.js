const {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  normalizeHttpUrl,
  normalizeDomain,
} = require("./provider-utils");

const DEFAULT_TIMEOUT_MS = Number(process.env.GOOGLE_WEB_RISK_TIMEOUT_MS) || 8000;
const THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"];

function targetUrl(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (input.url) return normalizeHttpUrl(input.url);
  const domain = normalizeDomain(input.domain);
  return domain ? normalizeHttpUrl(`https://${domain}/`) : null;
}

function noMatch(provider, target) {
  return {
    ok: true,
    success: true,
    provider,
    status: "success",
    collectedAt: new Date().toISOString(),
    message: "No Google Web Risk match was returned for the checked URL and threat types.",
    findings: { target, indicatorChecked: target, matches: [] },
    evidence: [
      { field: "target", value: target, source: provider },
      { field: "matches", value: [], source: provider },
    ],
  };
}

function createGoogleWebRiskTool({ apiKey, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return {
    name: "google_web_risk_lookup",
    description: "Check a URL against Google Web Risk threat lists for malware, social engineering, and unwanted software.",
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
      const target = targetUrl(input);
      if (!target) return publicResult("google-web-risk", "error", "Invalid URL or domain target");
      if (!apiKey) return publicResult("google-web-risk", "not_configured", "Google Web Risk API key is not configured");

      const params = new URLSearchParams({ uri: target, key: apiKey });
      for (const threatType of THREAT_TYPES) params.append("threatTypes", threatType);
      const endpoint = `https://webrisk.googleapis.com/v1/uris:search?${params.toString()}`;

      try {
        const { response, payload } = await fetchWithRetry(endpoint, {
          timeoutMs,
          headers: { Accept: "application/json" },
          maxRetries: 1,
        });

        if (response.status !== 200) {
          return publicResult("google-web-risk", statusForHttp(response.status), `Google Web Risk returned HTTP ${response.status}`);
        }

        if (payload === null || typeof payload !== "object") {
          return publicResult("google-web-risk", "error", "Google Web Risk returned an unexpected response shape");
        }

        const matches = Array.isArray(payload?.threat?.threatTypes)
          ? payload.threat.threatTypes.filter((value) => THREAT_TYPES.includes(value))
          : [];

        if (!matches.length) return noMatch("google-web-risk", target);

        const findings = {
          target,
          indicatorChecked: target,
          matches,
          expireTime: payload?.threat?.expireTime,
        };
        const filtered = Object.fromEntries(Object.entries(findings).filter(([, value]) => value !== undefined && value !== null));
        return {
          ok: true,
          success: true,
          provider: "google-web-risk",
          status: "success",
          collectedAt: new Date().toISOString(),
          findings: filtered,
          evidence: Object.entries(filtered).map(([field, value]) => ({ field, value, source: "google-web-risk" })),
        };
      } catch (error) {
        return publicResult("google-web-risk", error?.category === "tool_timeout" ? "timeout" : "unavailable", error?.message || "Google Web Risk request failed");
      }
    },
  };
}

module.exports = { createGoogleWebRiskTool };
