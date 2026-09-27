const {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  normalizeHttpUrl,
  normalizeDomain,
  compactObject,
} = require("./provider-utils");

const DEFAULT_TIMEOUT_MS = Number(process.env.THREATFOX_TIMEOUT_MS) || 8000;
const ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/";

function normalizeInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (input.url) {
    const url = normalizeHttpUrl(input.url);
    return url ? { type: "url", value: url } : null;
  }
  const domain = normalizeDomain(input.domain);
  return domain ? { type: "domain", value: domain } : null;
}

function normalizeMatch(item) {
  return compactObject({
    id: item?.id,
    ioc: item?.ioc,
    iocType: item?.ioc_type,
    iocTypeDescription: item?.ioc_type_desc,
    threatType: item?.threat_type,
    threatTypeDescription: item?.threat_type_desc,
    malware: item?.malware,
    malwareFamily: item?.malware_printable || item?.malware,
    confidenceLevel: item?.confidence_level,
    firstSeen: item?.first_seen,
    lastSeen: item?.last_seen,
    tags: item?.tags,
    reporter: item?.reporter,
    reference: item?.reference,
  });
}

function exactMatch(item, target) {
  if (!item || typeof item !== "object") return false;
  const value = String(item.ioc || "");
  return String(item.ioc_type || "").toLowerCase() === target.type &&
    (target.type === "domain" ? value.toLowerCase() === target.value.toLowerCase() : value === target.value);
}

function createThreatFoxTool({ authKey, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return {
    name: "threatfox_lookup",
    description: "Look up an exact URL or domain IOC in ThreatFox threat intelligence.",
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
      if (!target) return publicResult("threatfox", "error", "Invalid URL or domain target");
      if (!authKey) return publicResult("threatfox", "not_configured", "ThreatFox Auth-Key is not configured");

      try {
        const { response, payload } = await fetchWithRetry(ENDPOINT, {
          method: "POST",
          body: JSON.stringify({ query: "search_ioc", search_term: target.value, exact_match: true }),
          timeoutMs,
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "Auth-Key": authKey,
          },
          maxRetries: 1,
        });

        if (response.status !== 200) return publicResult("threatfox", statusForHttp(response.status), `ThreatFox returned HTTP ${response.status}`);
        if (!payload || typeof payload !== "object") return publicResult("threatfox", "error", "ThreatFox returned an unexpected response shape");
        if (payload.query_status === "no_result" || payload.query_status === "no_results") {
          return {
            ok: true,
            success: true,
            provider: "threatfox",
            status: "success",
            collectedAt: new Date().toISOString(),
            message: "No ThreatFox match was returned for the checked indicator.",
            findings: { target: target.value, indicatorChecked: target.value, matches: [] },
            evidence: [
              { field: "target", value: target.value, source: "threatfox" },
              { field: "matches", value: [], source: "threatfox" },
            ],
          };
        }
        if (payload.query_status !== "ok") return publicResult("threatfox", "error", `ThreatFox returned query status ${String(payload.query_status || "unknown")}`);

        const raw = Array.isArray(payload.data) ? payload.data : [];
        const matches = raw.filter((item) => exactMatch(item, target)).map(normalizeMatch);
        const findings = { target: target.value, indicatorChecked: target.value, matches };
        return {
          ok: true,
          success: true,
          provider: "threatfox",
          status: "success",
          collectedAt: new Date().toISOString(),
          findings,
          evidence: Object.entries(findings).map(([field, value]) => ({ field, value, source: "threatfox" })),
        };
      } catch (error) {
        return publicResult("threatfox", error?.category === "tool_timeout" ? "timeout" : "unavailable", error?.message || "ThreatFox request failed");
      }
    },
  };
}

module.exports = { createThreatFoxTool };
