/**
 * AbuseIPDB read-only IP intelligence tool.
 *
 * API credentials are server-side only. Provider data is untrusted evidence.
 */
const net = require("net");

const DEFAULT_TIMEOUT_MS = Number(process.env.ABUSEIPDB_TIMEOUT_MS) || 8000;
const DEFAULT_MAX_AGE_DAYS = Number(process.env.ABUSEIPDB_MAX_AGE_DAYS) || 90;

function isValidIP(value) {
  if (typeof value !== "string") return false;
  const v = value.trim();
  return v.length > 0 && v.length <= 45 && net.isIP(v) !== 0;
}

function publicError(status, message) {
  return {
    ok: true,
    success: true,
    provider: "abuseipdb",
    status,
    message: String(message || "").slice(0, 500),
    findings: {},
    evidence: [],
  };
}

async function request(url, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Key: apiKey,
      },
      signal: controller.signal,
    });

    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { response, body };
  } catch (error) {
    if (error?.name === "AbortError") {
      const err = new Error(`AbuseIPDB request timed out after ${timeoutMs}ms`);
      err.category = "tool_timeout";
      throw err;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeData(data) {
  if (!data || typeof data !== "object") return null;
  const fields = [
    "ipAddress", "isPublic", "ipVersion", "isWhitelisted",
    "abuseConfidenceScore", "countryCode", "usageType", "isp",
    "domain", "hostnames", "totalReports", "numDistinctUsers",
    "lastReportedAt",
  ];
  const findings = {};
  for (const field of fields) {
    if (data[field] !== undefined && data[field] !== null) findings[field] = data[field];
  }
  return findings;
}

function createAbuseIPDBTool({ apiKey, timeoutMs = DEFAULT_TIMEOUT_MS, maxAgeInDays = DEFAULT_MAX_AGE_DAYS } = {}) {
  return {
    name: "abuseipdb_ip_lookup",
    description: "Look up an IPv4 or IPv6 address using AbuseIPDB threat intelligence",
    inputSchema: {
      type: "object",
      properties: {
        ip: { type: "string", minLength: 2, maxLength: 45 },
      },
      required: ["ip"],
      additionalProperties: false,
    },
    category: "threat-intelligence",
    targetTypes: ["ip"],
    readOnly: true,
    destructive: false,
    riskLevel: "read",
    requiresApproval: false,

    async execute(input) {
      if (!input || typeof input !== "object" || Array.isArray(input) || !isValidIP(input.ip)) {
        return {
          ok: true,
          success: true,
          provider: "abuseipdb",
          status: "error",
          message: "Invalid IP address",
          findings: {},
          evidence: [],
        };
      }

      if (!apiKey) {
        return publicError("unauthorized", "AbuseIPDB API key is not configured");
      }

      const params = new URLSearchParams({
        ipAddress: input.ip.trim(),
        maxAgeInDays: String(Math.min(Math.max(maxAgeInDays, 1), 365)),
      });
      const url = `https://api.abuseipdb.com/api/v2/check?${params.toString()}`;

      try {
        const { response, body } = await request(url, apiKey, timeoutMs);
        const statusCode = response.status;

        if (statusCode === 200) {
          const data = body?.data;
          const findings = normalizeData(data);
          if (!findings) return publicError("error", "AbuseIPDB returned an unexpected response shape");

          return {
            ok: true,
            success: true,
            provider: "abuseipdb",
            status: "success",
            collectedAt: new Date().toISOString(),
            findings,
            evidence: Object.keys(findings).map((field) => ({
              field,
              value: findings[field],
              source: "AbuseIPDB",
            })),
          };
        }

        if (statusCode === 401) return publicError("unauthorized", "AbuseIPDB rejected the API credentials");
        if (statusCode === 403) return publicError("forbidden", "AbuseIPDB denied access to the requested resource");
        if (statusCode === 429) return publicError("rate_limited", "AbuseIPDB rate limit reached");
        if ([500, 502, 503, 504].includes(statusCode)) return publicError("unavailable", `AbuseIPDB upstream service returned HTTP ${statusCode}`);
        if (statusCode === 404) return publicError("not_found", "AbuseIPDB did not return the requested indicator");

        return publicError("error", `AbuseIPDB returned HTTP ${statusCode}`);
      } catch (error) {
        if (error?.category === "tool_timeout") throw error;
        const wrapped = new Error("AbuseIPDB network request failed");
        wrapped.category = "network_error";
        throw wrapped;
      }
    },
  };
}

module.exports = {
  createAbuseIPDBTool,
  isValidIP,
};
