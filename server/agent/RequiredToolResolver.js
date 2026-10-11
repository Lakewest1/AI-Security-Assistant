/**
 * RequiredToolResolver
 *
 * Deterministically classifies investigation targets and returns the
 * controller execution plan. It never executes tools.
 */

const IPV4_CANDIDATE_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const URL_RE = /\bhttps?:\/\/[^\s<>"']+/i;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i;

const INVESTIGATION_INTENT_RE =
  /\b(?:investigate|investigation|check|lookup|look\s+up|analy[sz]e|analyse|reputation|malicious|threat|what\s+do\s+you\s+know|who\s+owns|is\s+this|scan|security\s+posture|breach)\b/i;

const { normalizeHttpUrl, normalizeDomain } = require("../tools/external/provider-utils");

const INVESTIGATION_PROFILES = Object.freeze({
  ip: [
    "virustotal_ip_lookup",
    "abuseipdb_ip_lookup",
    "ipinfo_ip_lookup",
    "shodan_ip_lookup",
    "censys_ip_lookup",
    "viewdns_lookup",
  ],
  domain: [
    "virustotal_domain_lookup",
    "urlscan_lookup",
    "urlhaus_lookup",
    "threatfox_lookup",
    "phishing_database_lookup",
    "google_web_risk_lookup",
    "mozilla_observatory_scan",
  ],
  url: [
    "virustotal_url_lookup",
    "urlscan_lookup",
    "urlhaus_lookup",
    "threatfox_lookup",
    "phishing_database_lookup",
    "google_web_risk_lookup",
    "mozilla_observatory_scan",
  ],
  email: [
    "hibp_lookup",
  ],
});

function isValidIPv4(value) {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  if (!normalized) return false;
  const parts = normalized.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function extractIPv4Candidates(text) { return typeof text === "string" ? text.match(IPV4_CANDIDATE_RE) || [] : []; }
function extractIPv4(text) { return extractIPv4Candidates(text).find(isValidIPv4) || null; }
function extractIPv4Candidate(text) { return extractIPv4Candidates(text)[0] || null; }

function normalizeUrlCandidate(value) {
  const candidate = String(value || "").trim();
  // Validate with the shared URL parser, but preserve the user's full URL
  // representation for target identity and provider-specific adapters.
  if (normalizeHttpUrl(candidate, { allowBareDomain: false })) return candidate;
  if (!candidate.includes("://") && normalizeHttpUrl(`https://${candidate}`, { allowBareDomain: false })) return candidate;
  return null;
}
function normalizeDomainCandidate(value) { return normalizeDomain(value); }
function extractEmail(text) { const match = String(text || "").match(EMAIL_RE); return match ? match[0] : null; }
function extractUrl(text) {
  const content=String(text||"");
  const match=content.match(URL_RE);
  if(match)return normalizeUrlCandidate(match[0]);
  // A domain followed by a path is a URL indicator even if the user omits
  // the scheme. Preserve every path character (including a trailing '_');
  // provider adapters add https:// where their API requires an absolute URL.
  const barePath=content.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s<>"']*)/i);
  return barePath?normalizeUrlCandidate(barePath[0]):null;
}
function extractDomain(text) {
  const match = String(text || "").match(DOMAIN_RE);
  return match ? normalizeDomainCandidate(match[0]) : null;
}
function getMessageText(messages) {
  if (!Array.isArray(messages)) return "";
  return messages.map((message) => {
    if (!message || message.role === "system") return "";
    if (typeof message.content === "string") return message.content;
    if (Array.isArray(message.content)) return message.content.filter((b) => b?.type === "text").map((b) => b.text || "").join("\n");
    return "";
  }).join("\n").trim();
}

function buildExecutionPlan(targetType, value) {
  const requiredTools = [...(INVESTIGATION_PROFILES[targetType] || [])];
  const requiredToolArguments = {};
  const providerUrl = targetType === "url" && !String(value).includes("://") ? `https://${value}` : value;
  for (const tool of requiredTools) {
    if (tool === "virustotal_ip_lookup" || tool === "abuseipdb_ip_lookup" || tool === "shodan_ip_lookup" || tool === "ipinfo_ip_lookup" || tool === "censys_ip_lookup") requiredToolArguments[tool] = { ip: value };
    else if (tool === "virustotal_domain_lookup") requiredToolArguments[tool] = { domain: value };
    else if (tool === "virustotal_url_lookup") requiredToolArguments[tool] = { url: providerUrl };
    else if (tool === "viewdns_lookup") requiredToolArguments[tool] = targetType === "ip" ? { ip: value } : { domain: value };
    else if (["google_web_risk_lookup", "phishing_database_lookup"].includes(tool)) requiredToolArguments[tool] = targetType === "url" ? { url: providerUrl } : { domain: value };
    else if (["urlhaus_lookup", "threatfox_lookup"].includes(tool)) requiredToolArguments[tool] = targetType === "url" ? { url: providerUrl } : { domain: value };
    else if (tool === "urlscan_lookup") requiredToolArguments[tool] = targetType === "url" ? { url: providerUrl } : { domain: value };
    else if (tool === "securitytrails_lookup") requiredToolArguments[tool] = { domain: value };
    else if (tool === "mozilla_observatory_scan") requiredToolArguments[tool] = targetType === "url" ? { url: providerUrl } : { domain: value };
    else if (tool === "hibp_lookup") requiredToolArguments[tool] = { email: value };
  }
  return {
    executionMode: "controller",
    concurrency: "parallel",
    failurePolicy: "all-settled",
    requiredTools,
    requiredToolArguments,
    executionGroups: [{ id: `${targetType}-security-intelligence`, mode: "parallel", failurePolicy: "all-settled", tools: requiredTools }],
  };
}
function emptyResolution() {
  return { requiredTools: [], requiredToolArguments: {}, targets: [], executionMode: "none", concurrency: null, failurePolicy: null, executionGroups: [] };
}
function resolveRequiredTools(messages) {
  const latestUserMessage = Array.isArray(messages)
    ? [...messages].reverse().find((message) => message?.role === "user")
    : null;
  const text = getMessageText(latestUserMessage ? [latestUserMessage] : []);
  if (!text) return emptyResolution();

  // A URL pasted by itself is already an unambiguous investigation target.
  // Only inspect the latest user message so prior targets cannot leak forward.
  const url = extractUrl(text);
  if (!INVESTIGATION_INTENT_RE.test(text) && !url) return emptyResolution();
  if (url) return { ...buildExecutionPlan("url", url), targets: [{ type: "url", value: url, valid: true }] };

  const ipCandidate = extractIPv4Candidate(text);
  if (ipCandidate) {
    if (!isValidIPv4(ipCandidate)) return {...emptyResolution(),executionMode:"validation",targets:[{type:"ipv4",value:ipCandidate,valid:false}]};
    return {...buildExecutionPlan("ip", ipCandidate),targets:[{type:"ipv4",value:ipCandidate,valid:true}]};
  }
  const email = extractEmail(text);
  if (email) return {...buildExecutionPlan("email",email),targets:[{type:"email",value:email,valid:true}]};
  const domain = extractDomain(text);
  if (domain) return {...buildExecutionPlan("domain",domain),targets:[{type:"domain",value:domain,valid:true}]};
  return emptyResolution();
}

module.exports = {
  INVESTIGATION_PROFILES,
  IPV4_REQUIRED_TOOLS: INVESTIGATION_PROFILES.ip,
  isValidIPv4,
  extractIPv4,
  extractIPv4Candidate,
  extractEmail,
  extractUrl,
  extractDomain,
  getMessageText,
  buildIPv4ExecutionPlan: (ip) => buildExecutionPlan("ip", ip),
  buildExecutionPlan,
  resolveRequiredTools,
};
