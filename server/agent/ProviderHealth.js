"use strict";

const PROVIDERS = Object.freeze({
  virustotal: { env: ["VIRUSTOTAL_API_KEY"], tools: ["virustotal_ip_lookup", "virustotal_domain_lookup", "virustotal_url_lookup"] },
  abuseipdb: { env: ["ABUSEIPDB_API_KEY"], tools: ["abuseipdb_ip_lookup"] },
  ipinfo: { env: ["IPINFO_TOKEN"], tools: ["ipinfo_ip_lookup"] },
  shodan: { env: ["SHODAN_API_KEY"], tools: ["shodan_ip_lookup"] },
  censys: { env: ["CENSYS_API_TOKEN"], optionalEnv: ["CENSYS_ORGANIZATION_ID"], tools: ["censys_ip_lookup"] },
  viewdns: { env: ["VIEWDNS_API_KEY"], tools: ["viewdns_lookup"] },
  urlscan: { env: ["URLSCAN_API_KEY"], tools: ["urlscan_lookup"] },
  urlhaus: { env: ["URLHAUS_AUTH_KEY"], tools: ["urlhaus_lookup"] },
  threatfox: { env: ["THREATFOX_AUTH_KEY"], tools: ["threatfox_lookup"] },
  phishing_database: { env: [], tools: ["phishing_database_lookup"], optional: true },
  google_web_risk: { env: ["GOOGLE_WEB_RISK_API_KEY"], tools: ["google_web_risk_lookup"] },
  mozilla_observatory: { env: [], tools: ["mozilla_observatory_scan"], optional: true },
  phishtank: { env: ["PHISHTANK_API_KEY"], tools: ["phishtank_lookup"] },
  securitytrails: { env: ["SECURITYTRAILS_API_KEY"], tools: ["securitytrails_lookup"] },
  hibp: { env: ["HIBP_API_KEY"], tools: ["hibp_lookup"] },
});

function cleanEnv(name) {
  const value = process.env[name];
  return typeof value === "string" && value.trim().replace(/^["']|["']$/g, "").trim().length > 0;
}
function statusReason(status) {
  if (status === "unauthorized") return "Authentication rejected by provider";
  if (status === "forbidden") return "Provider denied this request; permission or access restrictions may apply";
  if (status === "invalid_request") return "Provider rejected the request as invalid or unsupported";
  if (status === "not_configured") return "Required provider credentials are not configured";
  if (status === "timeout") return "Provider request timed out";
  if (status === "rate_limited") return "Provider rate limit reached";
  if (status === "unavailable") return "Provider or network is unavailable";
  if (status === "error") return "Provider returned an unexpected response";
  if (status === "not_found") return "Provider has no record for this target";
  return null;
}

class ProviderHealth {
  constructor() { this.state = new Map(); }
  _configuration(provider) {
    const definition = PROVIDERS[provider];
    if (!definition) return { definition: null, configured: false };
    return { definition, configured: definition.optional || definition.env.every(cleanEnv) };
  }
  recordStart(toolName) {
    for (const [provider, definition] of Object.entries(PROVIDERS)) {
      if (!definition.tools.includes(toolName)) continue;
      const { configured } = this._configuration(provider);
      const now = new Date().toISOString();
      const previous = this.state.get(provider) || {};
      this.state.set(provider, { ...previous, provider, configured, lastCheckedAt: now, lastStatus: configured ? "checking" : "not_configured", failureReason: configured ? null : "Required provider credentials are not configured", reachable: configured ? previous.reachable ?? null : null, authenticationValid: configured ? previous.authenticationValid ?? null : null });
      return provider;
    }
    return null;
  }
  recordResult(toolName, status, latencyMs, errorMessage) {
    const provider = Object.keys(PROVIDERS).find(key => PROVIDERS[key].tools.includes(toolName));
    if (!provider) return;
    const { configured } = this._configuration(provider);
    const now = new Date().toISOString();
    const previous = this.state.get(provider) || { provider, lastSuccessAt: null, lastFailureAt: null };
    const normalized = status === "success" || status === "partial" || status === "not_found" || status === "no_match" ? status : status === "empty" ? "success" : status || "error";
    const successfulResponse = ["success", "partial", "not_found", "no_match"].includes(normalized);
    const reachable = successfulResponse || ["unauthorized", "forbidden", "invalid_request", "rate_limited", "error"].includes(normalized);
      this.state.set(provider, {
      ...previous, provider, configured, lastCheckedAt: now, lastStatus: configured ? normalized : "not_configured",
      lastSuccessAt: successfulResponse ? now : previous.lastSuccessAt || null,
      lastFailureAt: successfulResponse ? previous.lastFailureAt || null : now,
      authenticationValid: configured ? normalized === "unauthorized" ? false : successfulResponse || normalized === "rate_limited" ? true : previous.authenticationValid ?? null : null,
      reachable: configured ? normalized === "timeout" || normalized === "unavailable" ? false : reachable : null,
      failureReason: configured ? statusReason(normalized) : "Required provider credentials are not configured",
      latencyMs: Number.isFinite(Number(latencyMs)) ? Math.max(0, Number(latencyMs)) : null,
    });
  }
  getAll() {
    return Object.entries(PROVIDERS).map(([provider, definition]) => {
      const { configured } = this._configuration(provider);
      const state = this.state.get(provider) || {};
      return { provider, configured, authenticationValid: configured ? state.authenticationValid ?? null : null, reachable: configured ? state.reachable ?? null : null, lastCheckedAt: state.lastCheckedAt || null, lastSuccessAt: state.lastSuccessAt || null, lastFailureAt: state.lastFailureAt || null, lastStatus: state.lastStatus || (configured ? "not_checked" : "not_configured"), failureReason: configured ? state.failureReason || null : "Required provider credentials are not configured", latencyMs: state.latencyMs ?? null, tools: definition.tools };
    });
  }
}

module.exports = { ProviderHealth, PROVIDERS };
