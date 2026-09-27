const {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  normalizeHttpUrl,
  normalizeDomain,
  compactObject,
} = require("./provider-utils");

const DEFAULT_TIMEOUT_MS = Number(process.env.PHISHTANK_TIMEOUT_MS) || 8000;
const ENDPOINT = "https://checkurl.phishtank.com/checkurl/";

function targetUrl(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (input.url) return normalizeHttpUrl(input.url);
  const domain = normalizeDomain(input.domain);
  return domain ? normalizeHttpUrl(`https://${domain}/`) : null;
}

function normalizeMatch(result) {
  return compactObject({
    phishId: result?.phish_id,
    verified: result?.verified,
    online: result?.online,
    target: result?.target,
    submissionDate: result?.submission_time || result?.submitted_at,
    verificationDate: result?.verification_time || result?.verified_at,
    url: result?.url,
    detailUrl: result?.phish_detail_url || result?.phish_detail_page,
    valid: result?.valid,
  });
}

function createPhishTankTool({ appKey, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return {
    name: "phishtank_lookup",
    description: "Check a URL against PhishTank phishing intelligence.",
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
      if (!target) return publicResult("phishtank", "error", "Invalid URL or domain target");

      const form = new URLSearchParams({ url: target, format: "json" });
      if (appKey) form.set("app_key", appKey);

      try {
        const { response, payload } = await fetchWithRetry(ENDPOINT, {
          method: "POST",
          body: form.toString(),
          timeoutMs,
          headers: {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": process.env.PHISHTANK_USER_AGENT || "Lakewest-AI-Security-Assistant/1.0",
          },
          maxRetries: 1,
        });

        if (response.status === 509) return publicResult("phishtank", "rate_limited", "PhishTank rate limit reached");
        if (response.status !== 200) return publicResult("phishtank", statusForHttp(response.status), `PhishTank returned HTTP ${response.status}`);
        if (!payload || typeof payload !== "object") return publicResult("phishtank", "error", "PhishTank returned an unexpected response shape");

        const result = payload?.results && typeof payload.results === "object" ? payload.results : null;
        const inDatabase = result?.in_database === true || /^(?:y|yes|true|1)$/i.test(String(result?.in_database || ""));
        if (!inDatabase) {
          return {
            ok: true,
            success: true,
            provider: "phishtank",
            status: "success",
            collectedAt: new Date().toISOString(),
            message: "Not found in PhishTank.",
            findings: { target, indicatorChecked: target, match: false, matches: [] },
            evidence: [
              { field: "target", value: target, source: "phishtank" },
              { field: "match", value: false, source: "phishtank" },
            ],
          };
        }

        const match = normalizeMatch(result);
        const findings = compactObject({ target, indicatorChecked: target, match: true, matches: [match] });
        return {
          ok: true,
          success: true,
          provider: "phishtank",
          status: "success",
          collectedAt: new Date().toISOString(),
          findings,
          evidence: Object.entries(findings).map(([field, value]) => ({ field, value, source: "phishtank" })),
        };
      } catch (error) {
        return publicResult("phishtank", error?.category === "tool_timeout" ? "timeout" : "unavailable", error?.message || "PhishTank request failed");
      }
    },
  };
}

module.exports = { createPhishTankTool };
