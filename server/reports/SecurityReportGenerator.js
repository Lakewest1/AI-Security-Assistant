"use strict";

const PDFDocument = require("pdfkit");
const crypto = require("crypto");
const { deriveFinalInvestigationAssessment } = require("../agent/SecurityAssessment");

const PAGE = {
  width: 595.28,
  height: 841.89,
  margin: 42,
  contentWidth: 511.28,
  contentBottom: 805,
  footerY: 808,
};

const COLORS = {
  navy: "#0F172A",
  slate: "#334155",
  muted: "#64748B",
  lightText: "#94A3B8",
  border: "#E2E8F0",
  borderStrong: "#CBD5E1",
  background: "#F8FAFC",
  white: "#FFFFFF",
  blue: "#2563EB",
  blueLight: "#EFF6FF",
  blueBorder: "#BFDBFE",
  green: "#16A34A",
  greenLight: "#F0FDF4",
  greenBorder: "#BBF7D0",
  amber: "#D97706",
  amberLight: "#FFFBEB",
  amberBorder: "#FDE68A",
  red: "#DC2626",
  redLight: "#FEF2F2",
  redBorder: "#FECACA",
};

const SPACING = {
  section: 9,
  cardGap: 8,
  cardPad: 10,
};

const PROVIDER_LABELS = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlscan: "URLScan",
  shodan: "Shodan",
  ipinfo: "IPinfo",
  censys: "Censys",
  securitytrails: "SecurityTrails",
  mozillasecurityobservatory: "Mozilla Observatory",
  mozillaobservatory: "Mozilla Observatory",
  viewdns: "ViewDNS",
  hibp: "Have I Been Pwned",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  phishingdatabase: "Phishing.Database",
  phishtank: "PhishTank",
  googlewebrisk: "Google Web Risk",
};

const TERMINAL_NON_EVIDENCE_STATUSES = new Set([
  "timeout",
  "unauthorized",
  "error",
  "failed",
  "unavailable",
  "not_configured",
  "not configured",
  "skipped",
  "not_required",
  "not required",
]);

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function safeString(value, fallback = "") {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "string") return value.replace(/—/g, "-").trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function truncate(value, maxLength = 100) {
  const text = safeString(value);
  if (!text) return "";
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 1))}…`;
}

function dedupe(items) {
  return [...new Set(items.filter(Boolean))];
}

function humanize(value) {
  return safeString(value)
    .replace(/[\s_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function normalizeProviderName(source) {
  const raw = safeString(source?.provider || source?.name || source?.source).toLowerCase();
  return raw.replace(/[\s_.-]+/g, "");
}

function providerLabel(source) {
  const normalized = normalizeProviderName(source);
  return PROVIDER_LABELS[normalized] || humanize(source?.provider || source?.name || source?.source || "Security Source");
}

function sourceStatus(source) {
  return safeString(source?.status, "unknown").toLowerCase();
}

function sourceIsAvailable(source) {
  return ["success", "partial"].includes(sourceStatus(source));
}

function sourceHasCanonicalMeaningful(source) {
  return source?.quality?.meaningful === true;
}

function sourceCanShowEvidence(source) {
  if (!sourceIsAvailable(source)) return false;
  const findings = getSourceFindings(source);
  return findings.some((finding) => finding && typeof finding === "object" && Object.keys(finding).length > 0);
}

function getSources(investigation) {
  return Array.isArray(investigation?.sources) ? investigation.sources : [];
}

function getFindings(investigation) {
  return Array.isArray(investigation?.findings) ? investigation.findings : [];
}

function getCorrelations(investigation) {
  return Array.isArray(investigation?.correlations) ? investigation.correlations : [];
}

function getConflicts(investigation) {
  return Array.isArray(investigation?.conflicts) ? investigation.conflicts : [];
}

function getSourceFindings(source) {
  if (Array.isArray(source?.findings)) return source.findings;
  if (source?.findings && typeof source.findings === "object") return [source.findings];
  if (source?.data && typeof source.data === "object") return [source.data];
  return [];
}

function firstFinding(source) {
  return getSourceFindings(source)[0] || {};
}

function findSource(investigation, provider) {
  const normalized = String(provider).toLowerCase().replace(/[\s_.-]+/g, "");
  return getSources(investigation).find((source) => normalizeProviderName(source) === normalized);
}

function resolveTargetValue(value) {
  if (typeof value === "string") return value.trim();
  if (value && typeof value === "object") return firstDefined(safeString(value.value), safeString(value.target), safeString(value.name));
  return undefined;
}

function getTarget({ investigation, metadata, target }) {
  return firstDefined(
    resolveTargetValue(target),
    resolveTargetValue(investigation?.target),
    resolveTargetValue(metadata?.target),
    "Unknown target"
  );
}

function detectTargetType({ investigation, metadata, target }) {
  const explicit = firstDefined(investigation?.targetType, metadata?.targetType, investigation?.target?.type);
  if (explicit) return safeString(explicit).toLowerCase();
  const value = resolveTargetValue(target || investigation?.target || metadata?.target);
  if (!value) return "indicator";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  if (value.includes("://") || /^www\./i.test(value)) return "url";
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) return "email";
  return "indicator";
}

function normalizeLevel(value) {
  const normalized = safeString(value).toLowerCase().replace(/[_-]+/g, " ");
  if (normalized === "critical") return "critical";
  if (normalized === "elevated") return "elevated";
  if (normalized === "high") return "high";
  if (normalized === "moderate" || normalized === "medium") return "moderate";
  if (normalized === "low") return "low";
  return "unknown";
}

function levelLabel(level) {
  switch (normalizeLevel(level)) {
    case "critical": return "Critical";
    case "elevated": return "Elevated";
    case "high": return "High";
    case "moderate": return "Moderate";
    case "low": return "Low";
    default: return "Unknown";
  }
}

function levelStyle(level) {
  switch (normalizeLevel(level)) {
    case "critical":
    case "elevated":
    case "high":
      return { color: COLORS.red, background: COLORS.redLight, border: COLORS.redBorder };
    case "moderate":
      return { color: COLORS.amber, background: COLORS.amberLight, border: COLORS.amberBorder };
    case "low":
      return { color: COLORS.green, background: COLORS.greenLight, border: COLORS.greenBorder };
    default:
      return { color: COLORS.slate, background: COLORS.background, border: COLORS.borderStrong };
  }
}

function normalizeTimestamp(value) {
  if (value === undefined || value === null || value === "") return null;
  let numeric = null;
  if (typeof value === "number" && Number.isFinite(value)) numeric = value;
  else if (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim())) numeric = Number(value.trim());

  if (numeric !== null) {
    const milliseconds = numeric < 1e12 ? numeric * 1000 : numeric;
    if (!Number.isFinite(milliseconds) || milliseconds <= 0) return null;
    const date = new Date(milliseconds);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDate(value) {
  const date = normalizeTimestamp(value);
  if (!date) return "";
  return date.toLocaleString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDateOnly(value) {
  const date = normalizeTimestamp(value);
  if (!date) return "";
  return date.toLocaleDateString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function mapCountry(country) {
  const countries = {
    DE: "Germany", US: "United States", GB: "United Kingdom", NG: "Nigeria",
    FR: "France", NL: "Netherlands", CA: "Canada", RU: "Russia", CN: "China",
  };
  return countries[safeString(country).toUpperCase()] || safeString(country);
}

function getCanonicalAssessment(investigation) {
  return deriveFinalInvestigationAssessment(investigation || {});
}

function deriveExternalThreat(investigation) {
  return normalizeLevel(getCanonicalAssessment(investigation).externalThreat);
}

function deriveEnvironmentalRisk(investigation) {
  return normalizeLevel(getCanonicalAssessment(investigation).environmentalRisk);
}

function deriveOverallConfidence(investigation) {
  return getCanonicalAssessment(investigation).overallConfidence || "unknown";
}

function deriveRiskScore(investigation) {
  return getCanonicalAssessment(investigation).riskScore;
}

function deriveConfidenceScore(investigation) {
  return getCanonicalAssessment(investigation).confidenceScore;
}

function deriveConfidenceLevel(investigation) {
  return getCanonicalAssessment(investigation).confidenceLevel || "unknown";
}

function deriveCoverage(investigation) {
  const assessment = getCanonicalAssessment(investigation);
  const [meaningful, total] = String(assessment.meaningfulCoverage || "0/0").split("/").map(Number);
  return {
    meaningful: Number.isFinite(meaningful) ? meaningful : 0,
    total: Number.isFinite(total) ? total : 0,
    consulted: assessment.consultedSourceCount || 0,
    label: assessment.evidenceCoverage || "none",
  };
}

function buildSourceSummary(investigation) {
  return getSources(investigation).map((source) => ({
    label: providerLabel(source),
    status: sourceStatus(source),
    meaningful: sourceHasCanonicalMeaningful(source),
  }));
}

function safeScalar(value, maxLength = 90) {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return truncate(value, maxLength);
  if (Array.isArray(value)) {
    if (!value.length) return "";
    const strings = value.filter((item) => typeof item === "string" || typeof item === "number" || typeof item === "boolean").map(String);
    return strings.length ? truncate(strings.slice(0, 4).join(", "), maxLength) : `${value.length} item${value.length === 1 ? "" : "s"}`;
  }
  return "";
}

function addRow(rows, label, value, suffix = "") {
  const rendered = safeScalar(value);
  if (!rendered) return;
  rows.push({ label, value: `${rendered}${suffix}` });
}

function getVirusTotalEvidence(source) {
  const finding = firstFinding(source);
  return {
    malicious: firstDefined(finding.malicious, finding.maliciousCount, finding.lastAnalysisStats?.malicious),
    suspicious: firstDefined(finding.suspicious, finding.suspiciousCount, finding.lastAnalysisStats?.suspicious),
    harmless: firstDefined(finding.harmless, finding.harmlessCount, finding.lastAnalysisStats?.harmless),
    undetected: firstDefined(finding.undetected, finding.undetectedCount, finding.lastAnalysisStats?.undetected),
    reputation: firstDefined(finding.reputation, finding.reputationScore),
    lastAnalysisDate: firstDefined(finding.lastAnalysisDate, finding.last_analysis_date, finding.lastAnalysis),
  };
}

function getAbuseIPDBEvidence(source) {
  const finding = firstFinding(source);
  return {
    abuseConfidenceScore: firstDefined(finding.abuseConfidenceScore, finding.abuse_confidence_score),
    totalReports: firstDefined(finding.totalReports, finding.total_reports),
    lastReportedAt: firstDefined(finding.lastReportedAt, finding.last_reported_at),
    countryCode: firstDefined(finding.countryCode, finding.country_code),
    isp: finding.isp,
  };
}

function getCensysEvidence(source) {
  const finding = firstFinding(source);
  const location = finding.location && typeof finding.location === "object" ? finding.location : {};
  const autonomousSystem = firstDefined(
    finding.autonomousSystem,
    finding.autonomous_system,
    finding.asn
  );
  return {
    country: firstDefined(location.country, finding.country),
    city: firstDefined(location.city, finding.city),
    autonomousSystem,
    services: Array.isArray(finding.services) ? finding.services : [],
  };
}

function getIPinfoEvidence(source) {
  const finding = firstFinding(source);
  return {
    country: finding.country,
    region: finding.region,
    city: finding.city,
    hostname: finding.hostname,
    organization: firstDefined(finding.organization, finding.org),
    asn: firstDefined(finding.asn, finding.autonomousSystemNumber),
  };
}

function humanizeCensysServices(services) {
  const rows = [];
  for (const service of Array.isArray(services) ? services : []) {
    if (!service || typeof service !== "object") continue;
    const port = firstDefined(service.port, service.portNumber);
    const transport = firstDefined(service.transportProtocol, service.transport);
    const software = service.software?.product || service.software?.name || service.product || service.name;
    const labels = Array.isArray(service.labels) ? service.labels : [];
    const proxyLike = labels.some((label) => /proxy_server/i.test(String(label))) || /tor/i.test(safeString(software));
    const pieces = [];
    if (port !== undefined) pieces.push(`Port ${port}`);
    if (transport) pieces.push(String(transport).toUpperCase());
    if (software) pieces.push(String(software));
    if (proxyLike) pieces.push("Tor/proxy indicator");
    if (pieces.length) rows.push(pieces.join(" · "));
  }
  return rows;
}

function formatVirusTotalLastAnalysis(value) {
  if (value === undefined || value === null || value === "") return "";
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "";
  const date = new Date(numeric * 1000);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleDateString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function getURLScanEvidence(source) {
  const finding = firstFinding(source);
  const observations = Array.isArray(finding.results)
    ? finding.results
    : Array.isArray(finding.observations)
      ? finding.observations
      : Array.isArray(finding.scans)
        ? finding.scans
        : [];
  const latest = observations.length ? observations[0] : null;
  const observedIp = firstDefined(
    finding.observedIp,
    finding.observedIP,
    finding.ip,
    latest?.page?.ip,
    latest?.lists?.ips?.[0],
    latest?.ip
  );
  const server = firstDefined(
    finding.server,
    latest?.page?.server,
    latest?.http?.server
  );
  const latestObservation = firstDefined(
    finding.latestObservation,
    finding.latestObservedAt,
    finding.lastScanDate,
    latest?.task?.time,
    latest?.page?.timestamp,
    latest?.timestamp
  );
  const totalResults = firstDefined(
    finding.totalResults,
    finding.total_results,
    observations.length || undefined
  );
  return { totalResults, observedIp, server, latestObservation };
}

const INTERNAL_EVIDENCE_KEYS = new Set([
  "meaningful",
  "evidenceQuality",
  "evidence_quality",
  "quality",
  "freshness",
  "isMeaningful",
  "sourceStatus",
  "providerStatus",
]);

function isInternalEvidenceKey(key) {
  return INTERNAL_EVIDENCE_KEYS.has(String(key)) || /^_(?:internal|control|scoring)/i.test(String(key));
}

function normalizeHostname(value) {
  let host = safeString(value).toLowerCase();
  if (!host) return "";
  try {
    if (host.includes("://")) host = new URL(host).hostname;
    else host = new URL(`https://${host}`).hostname;
  } catch {
    host = host.split("/")[0].split(":")[0];
  }
  return host.replace(/^www\./i, "").replace(/\.$/, "");
}

function getInvestigationHostname(investigation) {
  const target = resolveTargetValue(investigation?.target);
  return normalizeHostname(target);
}

function filterURLScanObservations(observations, investigation) {
  const rows = Array.isArray(observations) ? observations : [];
  const targetHost = getInvestigationHostname(investigation);
  if (!targetHost) return rows;

  const observationsWithDomain = rows.filter((observation) =>
    observation && typeof observation === "object" && safeString(observation.domain)
  );
  if (!observationsWithDomain.length) return rows;

  return rows.filter((observation) => {
    if (!observation || typeof observation !== "object") return false;
    const observedHost = normalizeHostname(observation.domain);
    if (!observedHost) return false;
    return observedHost === targetHost || observedHost.endsWith(`.${targetHost}`);
  });
}

function providerRows(source, investigation) {
  const label = providerLabel(source);
  const rows = [];
  if (label === "VirusTotal") {
    const e = getVirusTotalEvidence(source);
    addRow(rows, "Malicious detections", e.malicious);
    addRow(rows, "Suspicious detections", e.suspicious);
    addRow(rows, "Harmless detections", e.harmless);
    addRow(rows, "Undetected", e.undetected);
    const lastAnalysis = formatVirusTotalLastAnalysis(e.lastAnalysisDate);
    if (lastAnalysis) addRow(rows, "Last analysis", lastAnalysis);
    else addRow(rows, "Reputation score", e.reputation);
  } else if (label === "AbuseIPDB") {
    const e = getAbuseIPDBEvidence(source);
    addRow(rows, "Abuse confidence", e.abuseConfidenceScore, "%");
    addRow(rows, "Reported abuse cases", e.totalReports);
    if (e.lastReportedAt !== undefined && normalizeTimestamp(e.lastReportedAt)) addRow(rows, "Last reported", formatDateOnly(e.lastReportedAt));
    addRow(rows, "Country", e.countryCode ? mapCountry(e.countryCode) : "");
    addRow(rows, "ISP", e.isp);
  } else if (label === "Censys") {
    const e = getCensysEvidence(source);
    addRow(rows, "Country", e.country ? mapCountry(e.country) : "");
    addRow(rows, "City", e.city);
    if (e.autonomousSystem && typeof e.autonomousSystem === "object") {
      const asnNumber = firstDefined(e.autonomousSystem.asn, e.autonomousSystem.number);
      const asnName = firstDefined(e.autonomousSystem.description, e.autonomousSystem.name);
      const asnValue = asnNumber !== undefined && asnName
        ? `AS${asnNumber} - ${asnName}`
        : firstDefined(asnName, asnNumber !== undefined ? `AS${asnNumber}` : "");
      addRow(rows, "Autonomous system", asnValue);
    } else {
      addRow(rows, "Autonomous system", e.autonomousSystem);
    }
    const services = humanizeCensysServices(e.services);
    if (services.length) addRow(rows, "Services", services.join("; "));
  } else if (label === "IPinfo") {
    const e = getIPinfoEvidence(source);
    addRow(rows, "Country", e.country ? mapCountry(e.country) : "");
    addRow(rows, "Region", e.region);
    addRow(rows, "City", e.city);
    addRow(rows, "Hostname", e.hostname);
    addRow(rows, "Organization", e.organization);
    addRow(rows, "ASN", e.asn);
  } else if (label === "URLScan") {
    const finding = firstFinding(source);
    const rawObservations = Array.isArray(finding.results)
      ? finding.results
      : Array.isArray(finding.observations)
        ? finding.observations
        : Array.isArray(finding.scans)
          ? finding.scans
          : [];
    const filteredObservations = filterURLScanObservations(rawObservations, investigation);
    const e = getURLScanEvidence({
      ...source,
      findings: [{
        ...finding,
        results: filteredObservations,
        observations: filteredObservations,
        scans: filteredObservations,
        totalResults: rawObservations.length && filteredObservations.length !== rawObservations.length
          ? filteredObservations.length
          : finding.totalResults,
      }],
    });
    addRow(rows, "Results", e.totalResults);
    addRow(rows, "Observed IP", e.observedIp);
    addRow(rows, "Server", e.server);
    if (e.latestObservation !== undefined && normalizeTimestamp(e.latestObservation)) {
      addRow(rows, "Latest observation", formatDateOnly(e.latestObservation));
    }
  }

  if (!rows.length) {
    for (const finding of getSourceFindings(source)) {
      if (!finding || typeof finding !== "object") continue;
      for (const [key, value] of Object.entries(finding)) {
        if (rows.length >= 5) break;
        if (isInternalEvidenceKey(key)) continue;
        if (value === undefined || value === null || value === "") continue;
        const rendered = safeScalar(value);
        if (!rendered) continue;
        rows.push({ label: humanize(key), value: rendered });
      }
      if (rows.length >= 5) break;
    }
  }
  return rows.slice(0, 6);
}

function buildEvidenceGroups(investigation) {
  const groups = [];
  for (const source of getSources(investigation)) {
    if (!sourceCanShowEvidence(source)) continue;
    const rows = providerRows(source, investigation);
    if (!rows.length) continue;
    groups.push({ title: providerLabel(source), status: sourceStatus(source), rows });
  }
  return groups
    .sort((a, b) => {
      const aMeaningful = sourceHasCanonicalMeaningful(findSource(investigation, a.title)) ? 0 : 1;
      const bMeaningful = sourceHasCanonicalMeaningful(findSource(investigation, b.title)) ? 0 : 1;
      return aMeaningful - bMeaningful;
    })
    .slice(0, 6);
}

function buildWhyThisMatters(investigation) {
  const reasons = [];
  const vt = findSource(investigation, "virustotal");
  if (vt && sourceCanShowEvidence(vt)) {
    const e = getVirusTotalEvidence(vt);
    if (e.malicious !== undefined) reasons.push(`VirusTotal reported ${e.malicious} malicious detection${Number(e.malicious) === 1 ? "" : "s"}.`);
    if (e.suspicious !== undefined && Number(e.suspicious) > 0) reasons.push(`VirusTotal also reported ${e.suspicious} suspicious detection${Number(e.suspicious) === 1 ? "" : "s"}.`);
  }
  const abuse = findSource(investigation, "abuseipdb");
  if (abuse && sourceCanShowEvidence(abuse)) {
    const e = getAbuseIPDBEvidence(abuse);
    if (e.abuseConfidenceScore !== undefined) reasons.push(`AbuseIPDB reported an abuse confidence score of ${e.abuseConfidenceScore}%.`);
    if (e.totalReports !== undefined) reasons.push(`AbuseIPDB recorded ${e.totalReports} reported abuse case${Number(e.totalReports) === 1 ? "" : "s"}.`);
  }
  const censys = findSource(investigation, "censys");
  if (censys && sourceCanShowEvidence(censys)) {
    const e = getCensysEvidence(censys);
    const tor = e.isTor === true || e.isTor === "true";
    const proxy = e.isProxy === true || e.isProxy === "true";
    if (tor || proxy) reasons.push(`Censys identified ${tor ? "Tor" : "proxy"}-related infrastructure.`);
  }
  const urlscan = findSource(investigation, "urlscan");
  const vtEvidence = vt && sourceCanShowEvidence(vt) ? getVirusTotalEvidence(vt) : {};
  const phishing = findSource(investigation, "phishing_database");
  const urlhaus = findSource(investigation, "urlhaus");
  const threatfox = findSource(investigation, "threatfox");
  const noStrongReputation =
    (vtEvidence.malicious === undefined || Number(vtEvidence.malicious) === 0) &&
    (vtEvidence.suspicious === undefined || Number(vtEvidence.suspicious) === 0) &&
    (!phishing || !sourceCanShowEvidence(phishing) || firstFinding(phishing).match !== true) &&
    (!urlhaus || !sourceCanShowEvidence(urlhaus) || firstFinding(urlhaus).match !== true) &&
    (!threatfox || !sourceCanShowEvidence(threatfox) || !Array.isArray(firstFinding(threatfox).matches) || firstFinding(threatfox).matches.length === 0);
  if (noStrongReputation && urlscan && sourceCanShowEvidence(urlscan)) {
    const e = getURLScanEvidence(urlscan);
    if (e.totalResults !== undefined) reasons.push(`Available external intelligence did not identify a confirmed phishing or malware match. URLScan returned ${e.totalResults} result${Number(e.totalResults) === 1 ? "" : "s"}.`);
  } else {
    reasons.push("These are external intelligence signals and do not by themselves prove compromise, successful exploitation, or impact inside the environment.");
  }
  return dedupe(reasons).slice(0, 4);
}

function buildAssessmentSentence({ externalThreat, environmentalRisk }) {
  if (["elevated", "high", "critical"].includes(externalThreat)) {
    if (environmentalRisk === "unknown") return "Strong external warning signs were found, but the available evidence does not confirm impact inside your environment.";
    return "Strong external warning signs were found. Environmental findings are based only on the internal evidence provided.";
  }
  if (externalThreat === "moderate") {
    if (environmentalRisk === "unknown") return "Some external warning signs were found. Internal impact cannot be confirmed because internal telemetry was not provided.";
    return "Some external warning signs were found. The available evidence does not establish that an attack occurred.";
  }
  if (externalThreat === "low") return "Limited external warning signs were found. This does not prove the indicator is safe.";
  return "Available external information was not sufficient to determine the external threat level with confidence.";
}

function buildRecommendations({ externalThreat, environmentalRisk }) {
  const recommendations = [
    "Search firewall, EDR, SIEM, DNS and proxy logs for the investigated target.",
    "Identify any affected host, account, application or process associated with the activity.",
    "Review activity immediately before and after the observed connection or event.",
    "Confirm whether the activity was expected and authorized.",
  ];
  if (["elevated", "high", "critical"].includes(externalThreat)) {
    recommendations.push("If the activity was unauthorized, investigate it as a potential incident and consider containment according to the organization's incident-response process; do not rely on reputation alone.");
  } else {
    recommendations.push("Do not block or contain solely because of an external reputation signal; validate the activity against internal telemetry and business context.");
  }
  if (environmentalRisk === "unknown") {
    recommendations.push("Review EDR, SIEM, firewall, DNS, proxy, identity and network-flow telemetry because environmental impact has not been established.");
  }
  recommendations.push("Continue monitoring for related activity and correlate any new internal evidence with the existing investigation.");
  return dedupe(recommendations).slice(0, 6);
}

function limitationText(item) {
  if (item && typeof item === "object") return firstDefined(safeString(item.statement), safeString(item.description), safeString(item.message));
  return safeString(item);
}

function buildKeyLimitations({ investigation, environmentalRisk }) {
  const limitations = [];
  if (environmentalRisk === "unknown") limitations.push("The investigation could not establish environmental impact without supporting internal telemetry.");
  const failedSources = getSources(investigation)
    .filter((source) => TERMINAL_NON_EVIDENCE_STATUSES.has(sourceStatus(source)))
    .map(providerLabel);
  if (failedSources.length) limitations.push(`Unavailable or failed sources reduced coverage: ${dedupe(failedSources).join(", ")}.`);
  const partialSources = getSources(investigation).filter((source) => sourceStatus(source) === "partial").map(providerLabel);
  if (partialSources.length) limitations.push(`Partial results were returned by: ${dedupe(partialSources).join(", ")}.`);
  for (const limitation of Array.isArray(investigation?.limitations) ? investigation.limitations : []) {
    const text = limitationText(limitation);
    if (text) limitations.push(text);
  }
  return dedupe(limitations).slice(0, 4);
}

function crossSourceText(item, type) {
  if (item === undefined || item === null) return "";
  if (typeof item === "string") return item.trim();
  if (typeof item !== "object") return safeString(item);
  if (type === "correlation") {
    const description = firstDefined(item.description, item.statement, item.message);
    const evidenceType = firstDefined(item.evidenceType, item.type);
    const strength = firstDefined(item.strength, item.confidence);
    const prefix = [safeString(evidenceType), safeString(strength)].filter(Boolean).join("; ");
    if (prefix && description) return `[${prefix}] ${description}`;
    if (description) return safeString(description);
    return safeString(JSON.stringify(item));
  }
  const description = firstDefined(item.description, item.statement, item.message);
  const resolution = firstDefined(item.resolution, item.status);
  if (resolution && description) return `${description} Resolution: ${resolution}.`;
  if (description) return safeString(description);
  return safeString(JSON.stringify(item));
}

function drawCrossSourceAnalysis(doc, investigation) {
  const correlations = getCorrelations(investigation);
  const conflicts = getConflicts(investigation);
  if (!correlations.length && !conflicts.length) return;

  const y = 575;
  const height = 154;
  drawCard(doc, { x: PAGE.margin, y, width: PAGE.contentWidth, height, background: COLORS.white, border: COLORS.border });
  drawSectionTitle(doc, "Cross-Source Analysis", PAGE.margin + 10, y + 9, PAGE.contentWidth - 20);

  const columns = [
    { title: "Correlations", items: correlations.map((item) => crossSourceText(item, "correlation")) },
    { title: "Conflicts", items: conflicts.map((item) => crossSourceText(item, "conflict")) },
  ].filter((column) => column.items.length);
  const gap = 10;
  const width = columns.length === 2 ? (PAGE.contentWidth - 20 - gap) / 2 : PAGE.contentWidth - 20;
  let x = PAGE.margin + 10;

  for (const column of columns) {
    drawText(doc, column.title, x, y + 27, width, { font: "Helvetica-Bold", size: 6.7, color: COLORS.muted });
    let currentY = y + 40;
    for (const item of column.items) {
      if (!item) continue;
      doc.circle(x + 2.5, currentY + 3.5, 1.4).fill(COLORS.blue);
      const itemHeight = doc.font("Helvetica").fontSize(6.15).heightOfString(item, { width: width - 11, lineGap: 0.5 });
      drawText(doc, item, x + 9, currentY, width - 9, { size: 6.15, color: COLORS.slate, lineGap: 0.5 });
      currentY += Math.max(12, itemHeight + 3);
    }
    x += width + gap;
  }
}

function drawText(doc, text, x, y, width, options = {}) {
  const { font = "Helvetica", size = 9, color = COLORS.slate, align = "left", lineGap = 1 } = options;
  doc.font(font).fontSize(size).fillColor(color).text(safeString(text), x, y, { width, align, lineGap });
  return doc.y;
}

function drawCard(doc, { x, y, width, height, background = COLORS.white, border = COLORS.border, radius = 8 }) {
  doc.roundedRect(x, y, width, height, radius).fillAndStroke(background, border);
}

function drawStatusPill(doc, text, x, y, style, maxWidth = 105) {
  const label = truncate(text, 18) || "Unknown";
  doc.font("Helvetica-Bold").fontSize(6.7);
  const width = Math.min(maxWidth, Math.max(42, doc.widthOfString(label) + 14));
  doc.roundedRect(x, y, width, 15, 7.5).fill(style.background);
  doc.fillColor(style.color).text(label, x + 7, y + 4, { width: width - 14, lineBreak: false });
  return width;
}

function drawSectionTitle(doc, title, x = PAGE.margin, y, width = PAGE.contentWidth) {
  doc.font("Helvetica-Bold").fontSize(9.5).fillColor(COLORS.navy).text(title, x, y, { width, lineBreak: false });
}

function drawHeader(doc, { target, targetType, reportId, generatedAt }) {
  doc.rect(0, 0, PAGE.width, 6).fill(COLORS.blue);
  drawText(doc, "LAKEWEST AI SECURITY ASSISTANT", PAGE.margin, 27, 250, { font: "Helvetica-Bold", size: 9, color: COLORS.blue });
  drawText(doc, "AI SECURITY ASSISTANT", PAGE.margin, 40, 250, { size: 7, color: COLORS.muted });
  drawText(doc, "SECURITY INVESTIGATION BRIEF", PAGE.margin, 63, 330, { font: "Helvetica-Bold", size: 17, color: COLORS.navy });
  drawText(doc, "Evidence-led investigation summary", PAGE.margin, 85, 330, { size: 7.5, color: COLORS.muted });

  const metaX = 382;
  drawText(doc, "REPORT ID", metaX, 27, 170, { font: "Helvetica-Bold", size: 6.5, color: COLORS.lightText });
  drawText(doc, truncate(reportId, 28), metaX, 39, 170, { size: 7, color: COLORS.slate });
  drawText(doc, "GENERATED", metaX, 55, 170, { font: "Helvetica-Bold", size: 6.5, color: COLORS.lightText });
  drawText(doc, formatDate(generatedAt), metaX, 67, 170, { size: 7, color: COLORS.slate });

  const targetY = 111;
  drawCard(doc, { x: PAGE.margin, y: targetY, width: PAGE.contentWidth, height: 52, background: COLORS.background, border: COLORS.border });
  drawText(doc, "INVESTIGATION TARGET", PAGE.margin + 12, targetY + 9, 250, { font: "Helvetica-Bold", size: 6.5, color: COLORS.lightText });
  drawText(doc, truncate(target, 72), PAGE.margin + 12, targetY + 21, 360, { font: "Helvetica-Bold", size: 11, color: COLORS.navy });

}

function drawAssessmentCards(doc, externalThreat, environmentalRisk) {
  const gap = SPACING.cardGap;
  const width = (PAGE.contentWidth - gap) / 2;
  const y = 175;
  const height = 65;
  const externalStyle = levelStyle(externalThreat);
  drawCard(doc, { x: PAGE.margin, y, width, height, background: externalStyle.background, border: externalStyle.border });
  drawText(doc, "EXTERNAL THREAT", PAGE.margin + 11, y + 9, width - 22, { font: "Helvetica-Bold", size: 6.8, color: externalStyle.color });
  drawText(doc, levelLabel(externalThreat), PAGE.margin + 11, y + 23, width - 22, { font: "Helvetica-Bold", size: 16, color: externalStyle.color });
  drawText(doc, "Assessment based on the available external intelligence.", PAGE.margin + 11, y + 45, width - 22, { size: 6.8, color: COLORS.muted });

  const envX = PAGE.margin + width + gap;
  const envStyle = levelStyle(environmentalRisk);
  drawCard(doc, { x: envX, y, width, height, background: envStyle.background, border: envStyle.border });
  drawText(doc, "ENVIRONMENTAL RISK", envX + 11, y + 9, width - 22, { font: "Helvetica-Bold", size: 6.8, color: envStyle.color });
  drawText(doc, levelLabel(environmentalRisk), envX + 11, y + 23, width - 22, { font: "Helvetica-Bold", size: 16, color: envStyle.color });
  drawText(doc, environmentalRisk === "unknown" ? "The investigation could not establish environmental impact." : "Based only on the supplied internal evidence.", envX + 11, y + 45, width - 22, { size: 6.8, color: COLORS.muted });
}

function drawMetricRow(doc, riskScore, confidenceScore, confidenceLevel, coverage) {
  const y = 249;
  const gap = SPACING.cardGap;
  const width = (PAGE.contentWidth - gap * 2) / 3;
  const height = 51;

  drawCard(doc, { x: PAGE.margin, y, width, height });
  drawText(doc, "RISK SCORE", PAGE.margin + 11, y + 8, width - 22, { font: "Helvetica-Bold", size: 6.6, color: COLORS.muted });
  drawText(doc, riskScore === null ? "Unknown" : `${riskScore}/100`, PAGE.margin + 11, y + 21, width - 22, { font: "Helvetica-Bold", size: 12, color: COLORS.slate });
  drawText(doc, "Risk score from the investigation.", PAGE.margin + 11, y + 38, width - 22, { size: 6.4, color: COLORS.muted });

  const confidenceX = PAGE.margin + width + gap;
  drawCard(doc, { x: confidenceX, y, width, height });
  drawText(doc, "CONFIDENCE", confidenceX + 11, y + 8, width - 22, { font: "Helvetica-Bold", size: 6.6, color: COLORS.muted });
  const confidenceText = confidenceScore === null ? "Unknown" : `${confidenceScore}% - ${humanize(confidenceLevel)}`;
  drawText(doc, confidenceText, confidenceX + 11, y + 21, width - 22, { font: "Helvetica-Bold", size: 10.5, color: COLORS.slate });
  drawText(doc, "Confidence based on the available evidence.", confidenceX + 11, y + 38, width - 22, { size: 6.4, color: COLORS.muted });

  const coverageX = confidenceX + width + gap;
  drawCard(doc, { x: coverageX, y, width, height });
  drawText(doc, "MEANINGFUL COVERAGE", coverageX + 11, y + 8, width - 22, { font: "Helvetica-Bold", size: 6.6, color: COLORS.muted });
  drawText(doc, `${coverage.meaningful}/${coverage.total}`, coverageX + 11, y + 20, width - 22, { font: "Helvetica-Bold", size: 12, color: COLORS.blue });
  drawText(doc, `${coverage.consulted} consulted`, coverageX + 11, y + 37, width - 22, { size: 6.4, color: COLORS.muted });
}

function drawWrappedBulletList(doc, items, x, y, width, fontSize = 7.3, maxItems = items.length) {
  let currentY = y;
  for (const item of items.slice(0, maxItems)) {
    const text = safeString(item);
    if (!text) continue;
    doc.circle(x + 3, currentY + 4, 1.8).fill(COLORS.blue);
    const h = doc.font("Helvetica").fontSize(fontSize).heightOfString(text, { width: width - 13, lineGap: 1 });
    doc.fillColor(COLORS.slate).text(text, x + 12, currentY, { width: width - 12, lineGap: 1 });
    currentY += Math.max(13, h + 3);
  }
  return currentY;
}

function drawActionPanel(doc, recommendations) {
  const y = 346;
  const height = 110;
  drawCard(doc, { x: PAGE.margin, y, width: PAGE.contentWidth, height, background: COLORS.blueLight, border: COLORS.blueBorder });
  drawText(doc, "WHAT TO DO NOW", PAGE.margin + 10, y + 9, PAGE.contentWidth - 20, { font: "Helvetica-Bold", size: 8.5, color: COLORS.navy });
  drawWrappedBulletList(doc, recommendations, PAGE.margin + 11, y + 27, PAGE.contentWidth - 22, 7.05, 6);
}

function drawWhyThisMatters(doc, reasons) {
  const y = 466;
  drawSectionTitle(doc, "Why This Matters", PAGE.margin, y);
  drawWrappedBulletList(doc, reasons, PAGE.margin, y + 18, PAGE.contentWidth, 7.1, 3);
}

function evidenceCardHeight(group, width) {
  const rows = group.rows || [];
  let height = 29;
  for (const row of rows.slice(0, 5)) {
    const valueHeight = Math.max(12, measureTextHeight(row.value, width * 0.52 - 8, 6.5));
    height += Math.max(15, valueHeight + 2);
  }
  return Math.min(94, height + 7);
}

function measureTextHeight(text, width, size) {
  const doc = measureTextHeight.doc;
  doc.font("Helvetica").fontSize(size);
  return doc.heightOfString(safeString(text), { width, lineGap: 1 });
}

function drawEvidenceGroups(doc, groups) {
  const y = 510;
  drawSectionTitle(doc, "Key Evidence", PAGE.margin, y);
  drawText(doc, "Selected evidence from provider results with usable returned data.", PAGE.margin, y + 13, PAGE.contentWidth, { size: 6.5, color: COLORS.muted });

  const gap = 7;
  const columns = 2;
  const width = (PAGE.contentWidth - gap) / columns;
  let currentY = y + 28;
  let rowMaxHeight = 0;
  const visible = groups.slice(0, 4);

  for (let index = 0; index < visible.length; index += 1) {
    const group = visible[index];
    const column = index % columns;
    if (column === 0) rowMaxHeight = 0;
    const height = evidenceCardHeight(group, width);
    rowMaxHeight = Math.max(rowMaxHeight, height);
    const x = PAGE.margin + column * (width + gap);
    drawCard(doc, { x, y: currentY, width, height, background: COLORS.white, border: COLORS.border });
    drawText(doc, group.title, x + 9, currentY + 8, width - 75, { font: "Helvetica-Bold", size: 7.5, color: COLORS.navy });
    const statusStyle = group.status === "partial"
      ? { color: COLORS.amber, background: COLORS.amberLight }
      : { color: COLORS.green, background: COLORS.greenLight };
    const pillW = group.status === "partial" ? 43 : 45;
    drawStatusPill(doc, humanize(group.status), x + width - pillW - 9, currentY + 7, statusStyle, pillW);
    let rowY = currentY + 24;
    for (const row of group.rows.slice(0, 5)) {
      drawText(doc, row.label, x + 9, rowY, width * 0.43, { size: 6.2, color: COLORS.muted });
      const valueH = measureTextHeight(row.value, width * 0.52 - 8, 6.4);
      drawText(doc, truncate(row.value, 82), x + width * 0.43, rowY, width * 0.52 - 8, { font: "Helvetica-Bold", size: 6.4, color: COLORS.slate, align: "right", lineGap: 1 });
      rowY += Math.max(14, valueH + 1);
    }
    if (column === 1 || index === visible.length - 1) currentY += rowMaxHeight + gap;
  }
}

function drawEnvironmentCheck(doc, environmentalRisk) {
  const y = 45;
  drawSectionTitle(doc, "Environment Check", PAGE.margin, y);
  const cardY = y + 16;
  const height = 67;
  const unknown = environmentalRisk === "unknown";
  drawCard(doc, { x: PAGE.margin, y: cardY, width: PAGE.contentWidth, height, background: unknown ? COLORS.background : COLORS.greenLight, border: unknown ? COLORS.border : COLORS.greenBorder });
  drawText(doc, unknown ? "Environmental telemetry not established" : "Environmental evidence supplied", PAGE.margin + 11, cardY + 10, PAGE.contentWidth - 22, { font: "Helvetica-Bold", size: 8, color: unknown ? COLORS.slate : COLORS.green });
  drawText(doc, unknown
    ? "The investigation could not establish environmental impact. External intelligence cannot establish whether the target affected the environment without supporting internal telemetry."
    : "The investigation includes environmental evidence. Interpret the environmental risk only within the scope of the supplied internal evidence.",
  PAGE.margin + 11, cardY + 27, PAGE.contentWidth - 22, { size: 7.1, color: COLORS.slate, lineGap: 1 });
}

function drawConfidenceCoveragePage2(doc, confidence, confidenceScore, confidenceLevel, coverage) {
  const y = 136;
  drawSectionTitle(doc, "Confidence & Coverage", PAGE.margin, y);
  const gap = 7;
  const width = (PAGE.contentWidth - gap) / 2;
  const height = 56;
  drawCard(doc, { x: PAGE.margin, y: y + 16, width, height });
  drawText(doc, "OVERALL CONFIDENCE", PAGE.margin + 11, y + 25, width - 22, { font: "Helvetica-Bold", size: 6.5, color: COLORS.muted });
  drawText(doc, confidenceScore === null ? humanize(confidence) : `${confidenceScore}% - ${humanize(confidenceLevel)}`, PAGE.margin + 11, y + 38, width - 22, { font: "Helvetica-Bold", size: 10.5, color: COLORS.slate });

  const x = PAGE.margin + width + gap;
  drawCard(doc, { x, y: y + 16, width, height });
  drawText(doc, "MEANINGFUL COVERAGE", x + 11, y + 25, width - 22, { font: "Helvetica-Bold", size: 6.5, color: COLORS.muted });
  drawText(doc, `${coverage.meaningful}/${coverage.total}`, x + 11, y + 38, width - 22, { font: "Helvetica-Bold", size: 12, color: COLORS.blue });
  drawText(doc, `${coverage.consulted} consulted`, x + 88, y + 40, width - 100, { size: 6.5, color: COLORS.muted, align: "right" });
}

function statusStyle(status) {
  if (status === "success") return { color: COLORS.green, background: COLORS.greenLight };
  if (status === "partial") return { color: COLORS.amber, background: COLORS.amberLight };
  if (["timeout", "error", "failed", "unauthorized"].includes(status)) return { color: COLORS.red, background: COLORS.redLight };
  return { color: COLORS.muted, background: COLORS.background };
}

function drawSourceTable(doc, sourceSummary) {
  const y = 221;
  drawSectionTitle(doc, "Security Sources", PAGE.margin, y);
  const rows = sourceSummary.filter((source) => !["skipped", "not_required", "not required"].includes(source.status)).slice(0, 10);
  const rowHeight = 18;
  const headerHeight = 20;
  const tableY = y + 16;
  const height = headerHeight + rows.length * rowHeight;
  drawCard(doc, { x: PAGE.margin, y: tableY, width: PAGE.contentWidth, height: height + 1, background: COLORS.white, border: COLORS.border });
  doc.rect(PAGE.margin, tableY, PAGE.contentWidth, headerHeight).fill(COLORS.background);
  const sourceX = PAGE.margin + 9;
  const statusX = PAGE.margin + 255;
  const meaningfulX = PAGE.margin + 390;
  drawText(doc, "SOURCE", sourceX, tableY + 7, 235, { font: "Helvetica-Bold", size: 6.2, color: COLORS.muted });
  drawText(doc, "STATUS", statusX, tableY + 7, 110, { font: "Helvetica-Bold", size: 6.2, color: COLORS.muted });
  drawText(doc, "MEANINGFUL", meaningfulX, tableY + 7, 95, { font: "Helvetica-Bold", size: 6.2, color: COLORS.muted });
  rows.forEach((source, index) => {
    const rowY = tableY + headerHeight + index * rowHeight;
    if (index % 2 === 1) doc.rect(PAGE.margin, rowY, PAGE.contentWidth, rowHeight).fill("#FCFDFE");
    drawText(doc, source.label, sourceX, rowY + 5, 235, { size: 6.8, color: COLORS.slate });
    drawStatusPill(doc, humanize(source.status), statusX, rowY + 1.5, statusStyle(source.status), 96);
    drawText(doc, source.meaningful ? "Yes" : "No", meaningfulX, rowY + 5, 95, { font: "Helvetica-Bold", size: 6.8, color: source.meaningful ? COLORS.green : COLORS.muted });
  });
}

function drawLimitations(doc, limitations) {
  const y = 448;
  drawSectionTitle(doc, "Important Limitations", PAGE.margin, y);
  const cardY = y + 16;
  const height = 25 + limitations.slice(0, 4).length * 20;
  drawCard(doc, { x: PAGE.margin, y: cardY, width: PAGE.contentWidth, height, background: COLORS.amberLight, border: COLORS.amberBorder });
  let currentY = cardY + 10;
  for (const limitation of limitations.slice(0, 4)) {
    doc.circle(PAGE.margin + 13, currentY + 4, 1.8).fill(COLORS.amber);
    const h = doc.font("Helvetica").fontSize(6.8).heightOfString(limitation, { width: PAGE.contentWidth - 34, lineGap: 1 });
    drawText(doc, limitation, PAGE.margin + 23, currentY, PAGE.contentWidth - 34, { size: 6.8, color: COLORS.slate, lineGap: 1 });
    currentY += Math.max(17, h + 2);
  }
}

function drawPage2Bottom(doc) {
  const y = 752;
  drawText(doc, "This brief presents the available investigation evidence. External intelligence is not proof of compromise, successful exploitation, or internal impact without corroborating environmental telemetry.", PAGE.margin, y, PAGE.contentWidth, { size: 6.2, color: COLORS.lightText, lineGap: 1 });
}

function drawFooter(doc) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i += 1) {
    doc.switchToPage(i);
    const y = PAGE.footerY;
    doc.moveTo(PAGE.margin, y - 5).lineTo(PAGE.width - PAGE.margin, y - 5).strokeColor(COLORS.border).lineWidth(0.5).stroke();
    drawText(doc, "Lakewest AI Security Assistant", PAGE.margin, y, 250, { size: 6.5, color: COLORS.lightText });
    drawText(doc, `Page ${i - range.start + 1} of ${range.count}`, PAGE.width - PAGE.margin - 100, y, 100, { size: 6.5, color: COLORS.lightText, align: "right" });
  }
}

function createPdfBuffer(build) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margin: PAGE.margin,
      info: {
        Title: "Lakewest AI Security Assistant - Security Investigation Brief",
        Author: "Lakewest AI Security Assistant",
        Subject: "Security Investigation Brief",
        Creator: "Lakewest AI Security Assistant",
      },
      bufferPages: true,
      autoFirstPage: true,
    });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    try {
      build(doc);
      drawFooter(doc);
      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}

async function generateSecurityReport({ investigation, metadata = {}, target, requestId } = {}) {
  if (!investigation || typeof investigation !== "object") throw new Error("A canonical investigation object is required.");

  const resolvedTarget = getTarget({ investigation, metadata, target });
  const targetType = detectTargetType({ investigation, metadata, target: resolvedTarget });
  const externalThreat = deriveExternalThreat(investigation);
  const environmentalRisk = deriveEnvironmentalRisk(investigation);
  const confidence = deriveOverallConfidence(investigation);
  const confidenceScore = deriveConfidenceScore(investigation);
  const confidenceLevel = deriveConfidenceLevel(investigation);
  const riskScore = deriveRiskScore(investigation);
  const coverage = deriveCoverage(investigation);
  const sourceSummary = buildSourceSummary(investigation);
  const whyThisMatters = buildWhyThisMatters(investigation);
  const evidenceGroups = buildEvidenceGroups(investigation);
  const recommendations = buildRecommendations({ externalThreat, environmentalRisk });
  const limitations = buildKeyLimitations({ investigation, environmentalRisk });
  const assessment = buildAssessmentSentence({ externalThreat, environmentalRisk });
  const reportId = requestId || metadata.requestId || crypto.randomUUID();
  const generatedAt = new Date();

  return createPdfBuffer((doc) => {
    drawHeader(doc, { target: resolvedTarget, targetType, reportId, generatedAt });
    drawAssessmentCards(doc, externalThreat, environmentalRisk);
    drawMetricRow(doc, riskScore, confidenceScore, confidenceLevel, coverage);
    drawText(doc, "ASSESSMENT", PAGE.margin, 310, PAGE.contentWidth, { font: "Helvetica-Bold", size: 8.5, color: COLORS.navy });
    drawText(doc, assessment, PAGE.margin, 322, PAGE.contentWidth, { size: 7.4, color: COLORS.slate, lineGap: 1 });
    drawActionPanel(doc, recommendations);
    drawWhyThisMatters(doc, whyThisMatters);
    drawEvidenceGroups(doc, evidenceGroups);

    doc.addPage();
    drawEnvironmentCheck(doc, environmentalRisk);
    drawConfidenceCoveragePage2(doc, confidence, confidenceScore, confidenceLevel, coverage);
    drawSourceTable(doc, sourceSummary);
    drawLimitations(doc, limitations);
    drawCrossSourceAnalysis(doc, investigation);
    drawPage2Bottom(doc);
  });
}

class SecurityReportGenerator {
  async generateSecurityReport(options = {}) {
    return generateSecurityReport(options);
  }
}

module.exports = SecurityReportGenerator;
module.exports.SecurityReportGenerator = SecurityReportGenerator;
module.exports.generateSecurityReport = generateSecurityReport;

// A tiny PDFKit measurement document is reused only for height calculations.
// It is never emitted as a report page.
measureTextHeight.doc = new PDFDocument({ size: "A4", margin: 0, autoFirstPage: false });
