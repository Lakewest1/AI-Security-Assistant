/**
 * VirusTotal read-only IP intelligence tool.
 *
 * API credentials are server-side only. Provider data is untrusted evidence.
 * This adapter intentionally normalizes only documented VirusTotal IP fields.
 */
const net = require("net");

const DEFAULT_TIMEOUT_MS = Number(process.env.VIRUSTOTAL_TIMEOUT_MS) || 8000;

function isValidIP(value) {
  if (typeof value !== "string") return false;
  const v = value.trim();
  return v.length > 0 && v.length <= 45 && net.isIP(v) !== 0;
}

function publicError(status, message) {
  return {
    ok: true,
    success: true,
    provider: "virustotal",
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
        "x-apikey": apiKey,
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
      const err = new Error(`VirusTotal request timed out after ${timeoutMs}ms`);
      err.category = "tool_timeout";
      throw err;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeData(body, requestedIp) {
  const data = body?.data;
  const attributes = data?.attributes;
  if (!attributes || typeof attributes !== "object") return null;

  const stats = attributes.last_analysis_stats || {};
  const findings = {
    ip: data.id || requestedIp,
    country: attributes.country,
    asOwner: attributes.as_owner,
    asn: attributes.asn,
    network: attributes.network,
    reputation: attributes.reputation,
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    undetected: stats.undetected,
    timeout: stats.timeout,
    lastAnalysisDate: attributes.last_analysis_date,
  };

  return Object.fromEntries(
    Object.entries(findings).filter(([, value]) => value !== undefined && value !== null)
  );
}

function createVirusTotalTool({ apiKey, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return {
    name: "virustotal_ip_lookup",
    description: "Look up an IPv4 or IPv6 address using VirusTotal threat intelligence",
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
        return publicError("error", "Invalid IP address");
      }

      if (!apiKey) {
        return publicError("unauthorized", "VirusTotal API key is not configured");
      }

      const ip = input.ip.trim();
      const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`;

      try {
        const { response, body } = await request(url, apiKey, timeoutMs);
        const statusCode = response.status;

        if (statusCode === 200) {
          const findings = normalizeData(body, ip);
          if (!findings) return publicError("error", "VirusTotal returned an unexpected response shape");

          return {
            ok: true,
            success: true,
            provider: "virustotal",
            status: "success",
            collectedAt: new Date().toISOString(),
            findings,
            evidence: Object.keys(findings).map((field) => ({
              field,
              value: findings[field],
              source: "VirusTotal",
            })),
            // Preserve the compact fields expected by the existing Phase 1 logic.
            ...findings,
          };
        }

        if (statusCode === 401) return publicError("unauthorized", "VirusTotal rejected the API credentials");
        if (statusCode === 403) return publicError("forbidden", "VirusTotal denied access to the requested resource");
        if (statusCode === 429) return publicError("rate_limited", "VirusTotal rate limit reached");
        if ([500, 502, 503, 504].includes(statusCode)) return publicError("unavailable", `VirusTotal upstream service returned HTTP ${statusCode}`);
        if (statusCode === 404) return publicError("not_found", "VirusTotal did not return the requested indicator");

        return publicError("error", `VirusTotal returned HTTP ${statusCode}`);
      } catch (error) {
        if (error?.category === "tool_timeout") throw error;
        const wrapped = new Error("VirusTotal network request failed");
        wrapped.category = "network_error";
        throw wrapped;
      }
    },
  };
}

module.exports = {
  createVirusTotalTool,
  isValidIP,
};
