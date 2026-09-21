const PDFDocument = require("pdfkit");
const crypto = require("crypto");

/**
 * Lakewest AI Security Assistant
 * Concise SOC Security Investigation Brief
 *
 * PRESENTATION LAYER ONLY.
 *
 * SecurityAssessment.js / Investigation.js remain the authoritative
 * source of security conclusions.
 *
 * Design principles (UNCHANGED):
 *   - External reputation != confirmed compromise
 *   - External intelligence != internal telemetry
 *   - Never infer internal telemetry from external provider fields
 *   - Keep technical evidence readable for non-experts
 *
 * UX principles (NEW):
 *   - 1–2 pages normally
 *   - Target, threat, risk, actions visible immediately
 *   - No repeated conclusions
 *   - Compact cards, subtle severity accents
 *   - Humanized provider evidence, never raw JSON
 */

// ============================================================================
// DESIGN SYSTEM
// ============================================================================

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

  purple: "#7C3AED",
  purpleLight: "#F5F3FF",

  cyan: "#0891B2",
  cyanLight: "#ECFEFF",
};

const PAGE = {
  width: 595.28,
  height: 841.89,
  margin: 42,
};

const CONTENT = {
  width: PAGE.width - PAGE.margin * 2,
  bottom: PAGE.height - 42,
  footerY: PAGE.height - 30,
};

// Compact spacing tokens
const SPACE = {
  section: 13,
  cardGap: 9,
  cardPad: 11,
  rowGap: 5,
  paraGap: 4,
};

// ============================================================================
// GENERAL HELPERS (UNCHANGED)
// ============================================================================

function normalizeLevel(value) {
  const v = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\_-]+/g, " ");

  if (!v) return "unknown";

  if (v === "critical" || v.includes("critical")) {
    return "critical";
  }

  if (
    v === "high" ||
    v === "elevated" ||
    v.includes("high") ||
    v.includes("elevated")
  ) {
    return "high";
  }

  if (
    v === "moderate" ||
    v === "medium" ||
    v.includes("moderate") ||
    v.includes("medium")
  ) {
    return "moderate";
  }

  if (v === "low" || v.includes("low")) {
    return "low";
  }

  return "unknown";
}

function displayLevel(value) {
  const normalized = normalizeLevel(value);

  switch (normalized) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "moderate":
      return "MODERATE";
    case "low":
      return "LOW";
    default:
      return "UNKNOWN";
  }
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return undefined;
}

function formatDate(value) {
  const date = value ? new Date(value) : new Date();

  if (Number.isNaN(date.getTime())) {
    return new Date().toLocaleString();
  }

  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatDateShort(value) {
  const date = value ? new Date(value) : new Date();

  if (Number.isNaN(date.getTime())) {
    return new Date().toLocaleDateString();
  }

  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return String(value ?? "Unknown");
  }

  return number.toLocaleString("en-US");
}

function safeString(value, fallback = "") {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  if (typeof value === "string") {
    return value;
  }

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function capitalize(value) {
  const text = safeString(value, "");

  if (!text) return "";

  return text.charAt(0).toUpperCase() + text.slice(1);
}

function generateReportId() {
  return crypto.randomUUID();
}

function truncate(text, maxLength = 250) {
  const value = String(text ?? "");

  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength - 3)}...`;
}

function humanizeField(value) {
  return String(value ?? "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

// ============================================================================
// INVESTIGATION EXTRACTION (UNCHANGED)
// ============================================================================

function extractInvestigation({ investigation, metadata }) {
  if (investigation && typeof investigation === "object") {
    return investigation;
  }

  if (metadata?.investigation && typeof metadata.investigation === "object") {
    return metadata.investigation;
  }

  return null;
}

function getSources(investigation) {
  return Array.isArray(investigation?.sources) ? investigation.sources : [];
}

function getFindings(investigation) {
  return Array.isArray(investigation?.findings) ? investigation.findings : [];
}

function getLimitations(investigation) {
  return Array.isArray(investigation?.limitations) ? investigation.limitations : [];
}

function getTarget({ investigation, metadata, target }) {
  return firstDefined(
    target,
    investigation?.target,
    metadata?.target,
    "Unknown target"
  );
}

function detectTargetType({ investigation, metadata, target }) {
  return firstDefined(
    investigation?.targetType,
    metadata?.targetType,
    detectTargetTypeFromValue(target),
    "indicator"
  );
}

function detectTargetTypeFromValue(value) {
  const text = String(value || "").trim();

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) {
    return "ip";
  }

  if (text.includes("://") || /^www\./i.test(text)) {
    return "url";
  }

  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(text)) {
    return "email";
  }

  return "indicator";
}

// ============================================================================
// PROVIDER HELPERS (UNCHANGED)
// ============================================================================

function normalizeProviderName(source) {
  return String(
    firstDefined(source?.provider, source?.providerName, source?.name, "")
  )
    .trim()
    .toLowerCase()
    .replace(/[\s\_-]+/g, "");
}

function providerLabel(source) {
  const provider = normalizeProviderName(source);

  const labels = {
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
  };

  return (
    labels[provider] ||
    capitalize(
      firstDefined(
        source?.provider,
        source?.providerName,
        source?.name,
        "Unknown source"
      )
    )
  );
}

function getSourceFindings(source) {
  if (source?.findings && typeof source.findings === "object") {
    return source.findings;
  }
  return {};
}

function sourceIsAvailable(source) {
  return (
    source &&
    ["success", "partial"].includes(String(source.status || "").toLowerCase())
  );
}

function sourceIsMeaningful(source) {
  if (!sourceIsAvailable(source)) {
    return false;
  }

  if (source?.quality && typeof source.quality.meaningful === "boolean") {
    return source.quality.meaningful;
  }

  const findings = getSourceFindings(source);

  return Object.keys(findings).some((key) => {
    const value = findings[key];

    if (value === undefined || value === null || value === "") {
      return false;
    }

    if (Array.isArray(value)) {
      return value.length > 0;
    }

    if (typeof value === "object") {
      return Object.keys(value).length > 0;
    }

    return true;
  });
}

function meaningfulSources(investigation) {
  return getSources(investigation).filter(sourceIsMeaningful);
}

// ============================================================================
// SECURITY ASSESSMENT (UNCHANGED)
// ============================================================================

function deriveExternalThreat(investigation) {
  const explicit = firstDefined(
    investigation?.risk?.externalThreat,
    investigation?.risk?.external_threat
  );
  return normalizeLevel(explicit);
}

function deriveEnvironmentalRisk(investigation) {
  const explicit = firstDefined(
    investigation?.risk?.environmentalRisk,
    investigation?.risk?.environmental_risk
  );
  return normalizeLevel(explicit);
}

function deriveCoverage(investigation) {
  const explicit = firstDefined(
    investigation?.risk?.evidenceCoverage,
    investigation?.risk?.evidence_coverage
  );

  if (explicit) {
    return String(explicit).toLowerCase();
  }

  const meaningful = meaningfulSources(investigation).length;

  if (meaningful === 0) return "none";
  if (meaningful <= 2) return "limited";
  return "broad";
}

function deriveExternalConfidence(investigation) {
  return normalizeLevel(
    firstDefined(
      investigation?.confidence?.externalIntelligence,
      investigation?.confidence?.external_intelligence
    )
  );
}

function deriveEnvironmentalConfidence(investigation) {
  return normalizeLevel(
    firstDefined(
      investigation?.confidence?.environmentalAssessment,
      investigation?.confidence?.environmental_assessment
    )
  );
}

function deriveOverallConfidence(investigation) {
  return normalizeLevel(investigation?.confidence?.level);
}

// ============================================================================
// INTERNAL TELEMETRY (UNCHANGED)
// ============================================================================

function hasExplicitInternalTelemetry(investigation) {
  const explicitValues = [
    investigation?.internalTelemetry,
    investigation?.hasInternalTelemetry,
    investigation?.environmentalTelemetry,
    investigation?.telemetryProvided,
    investigation?.assessment?.internalTelemetry,
    investigation?.assessment?.hasInternalTelemetry,
  ];

  for (const value of explicitValues) {
    if (typeof value === "boolean") {
      return value;
    }

    if (
      typeof value === "string" &&
      /^(true|yes|available|provided)$/i.test(value.trim())
    ) {
      return true;
    }
  }

  return false;
}

function detectInternalTelemetry(investigation) {
  if (hasExplicitInternalTelemetry(investigation)) {
    return true;
  }

  const environmentalEvidence = getFindings(investigation).filter((finding) => {
    const type = String(finding?.type || "").toLowerCase();

    return (
      type.includes("environment") ||
      type.includes("endpoint") ||
      type.includes("authentication") ||
      type.includes("firewall") ||
      type.includes("network_flow") ||
      type.includes("networkflow") ||
      type.includes("packet") ||
      type.includes("internal_telemetry")
    );
  });

  return environmentalEvidence.length > 0;
}

// ============================================================================
// PROVIDER EVIDENCE (UNCHANGED)
// ============================================================================

function findSource(investigation, providerName) {
  const wanted = String(providerName)
    .toLowerCase()
    .replace(/[\s\_-]+/g, "");

  return getSources(investigation).find(
    (source) => normalizeProviderName(source) === wanted
  );
}

function getVirusTotalEvidence(investigation) {
  const source = findSource(investigation, "virustotal");
  if (!source) return null;

  const findings = getSourceFindings(source);

  return {
    source,
    malicious: findings.malicious,
    suspicious: findings.suspicious,
    harmless: findings.harmless,
    undetected: findings.undetected,
    reputation: findings.reputation,
    lastAnalysisDate: findings.lastAnalysisDate,
  };
}

function getAbuseIPDBEvidence(investigation) {
  const source = findSource(investigation, "abuseipdb");
  if (!source) return null;

  const findings = getSourceFindings(source);

  return {
    source,
    abuseConfidenceScore: findings.abuseConfidenceScore,
    totalReports: findings.totalReports,
    lastReportedAt: findings.lastReportedAt,
    countryCode: findings.countryCode,
    isp: findings.isp,
  };
}

function getCensysEvidence(investigation) {
  const source = findSource(investigation, "censys");
  if (!source) return null;

  const findings = getSourceFindings(source);

  return {
    source,
    isTor: findings.isTor ?? findings.tor ?? findings.isTorExit,
    isProxy: findings.isProxy ?? findings.proxy,
    services: findings.services,
    autonomousSystem: findings.autonomousSystem,
    location: findings.location,
    lastUpdated: findings.lastUpdated,
  };
}

function getIPinfoEvidence(investigation) {
  const source = findSource(investigation, "ipinfo");
  if (!source) return null;

  const findings = getSourceFindings(source);

  return {
    source,
    country: findings.country,
    region: findings.region,
    city: findings.city,
    hostname: findings.hostname,
    org: findings.org,
    loc: findings.loc,
    timezone: findings.timezone,
  };
}

// ============================================================================
// HUMAN-READABLE TECHNICAL FORMATTING
// ============================================================================

function formatCensysServices(services) {
  if (!Array.isArray(services)) return [];

  const results = [];

  for (const service of services) {
    const port = service?.port;

    const software = Array.isArray(service?.software) ? service.software : [];

    const labels = Array.isArray(service?.labels)
      ? service.labels.map((item) => String(item?.value || "").toUpperCase())
      : [];

    const softwareText = software
      .map((item) => {
        const vendor = item?.vendor || "";
        const product = item?.product || "";
        return `${vendor} ${product}`.trim();
      })
      .filter(Boolean)
      .join(", ");

    const isTor =
      labels.includes("PROXY_SERVER") || /tor/i.test(softwareText);

    if (isTor && port) {
      results.push({
        port,
        label: `Port ${port} — Tor/proxy service observed`,
        tor: true,
      });
      continue;
    }

    if (port) {
      const transport = service?.transportProtocol
        ? `/${String(service.transportProtocol).toUpperCase()}`
        : "";

      if (softwareText) {
        results.push({
          port,
          label: `Port ${port}${transport} — ${softwareText}`,
          tor: false,
        });
      } else {
        results.push({
          port,
          label: `Port ${port}${transport} — Service observed`,
          tor: false,
        });
      }
    }
  }

  return results;
}

function formatCensysPortList(services) {
  if (!Array.isArray(services)) return "";
  const ports = services
    .map((s) => s?.port)
    .filter((p) => p !== undefined && p !== null);
  return ports.join(", ");
}

// ============================================================================
// EVIDENCE COLLECTION (COMPACT, PRIORITIZED)
// ============================================================================

/**
 * Build compact evidence rows grouped by provider.
 * Never returns raw JSON.
 */
function collectEvidenceRows(investigation) {
  const groups = [];

  // VirusTotal
  const vt = getVirusTotalEvidence(investigation);
  if (vt && sourceIsMeaningful(vt.source)) {
    const rows = [];
    if (vt.malicious !== undefined && vt.malicious !== null) {
      rows.push({
        label: "Malicious detections",
        value: formatNumber(vt.malicious),
        highlight: Number(vt.malicious) > 0,
      });
    }
    if (vt.suspicious !== undefined && vt.suspicious !== null) {
      rows.push({
        label: "Suspicious detections",
        value: formatNumber(vt.suspicious),
        highlight: Number(vt.suspicious) > 0,
      });
    }
    if (vt.reputation !== undefined && vt.reputation !== null) {
      rows.push({
        label: "Reputation score",
        value: safeString(vt.reputation),
        highlight: Number(vt.reputation) < 0,
      });
    }
    if (vt.lastAnalysisDate) {
      rows.push({
        label: "Last analysis",
        value: formatDateShort(vt.lastAnalysisDate),
      });
    }
    if (rows.length) {
      groups.push({ provider: "VirusTotal", rows });
    }
  }

  // AbuseIPDB
  const abuse = getAbuseIPDBEvidence(investigation);
  if (abuse && sourceIsMeaningful(abuse.source)) {
    const rows = [];
    if (
      abuse.abuseConfidenceScore !== undefined &&
      abuse.abuseConfidenceScore !== null
    ) {
      rows.push({
        label: "Abuse confidence",
        value: `${formatNumber(abuse.abuseConfidenceScore)}%`,
        highlight: Number(abuse.abuseConfidenceScore) > 0,
      });
    }
    if (abuse.totalReports !== undefined && abuse.totalReports !== null) {
      rows.push({
        label: "Reported abuse cases",
        value: formatNumber(abuse.totalReports),
        highlight: Number(abuse.totalReports) > 0,
      });
    }
    if (abuse.lastReportedAt) {
      rows.push({
        label: "Last reported",
        value: formatDateShort(abuse.lastReportedAt),
      });
    }
    if (rows.length) {
      groups.push({ provider: "AbuseIPDB", rows });
    }
  }

  // Censys — humanized
  const censys = getCensysEvidence(investigation);
  if (censys && sourceIsMeaningful(censys.source)) {
    const rows = [];

    const torDetected =
      censys.isTor === true || String(censys.isTor).toLowerCase() === "true";
    const proxyDetected =
      censys.isProxy === true ||
      String(censys.isProxy).toLowerCase() === "true";

    if (torDetected) {
      rows.push({
        label: "Tor/proxy infrastructure",
        value: "Detected",
        highlight: true,
      });
    } else if (proxyDetected) {
      rows.push({
        label: "Proxy infrastructure",
        value: "Detected",
        highlight: true,
      });
    }

    const portList = formatCensysPortList(censys.services);
    if (portList) {
      rows.push({
        label: "Observed ports",
        value: portList,
      });
    }

    const formattedServices = formatCensysServices(censys.services);
    for (const svc of formattedServices.slice(0, 4)) {
      if (!svc.tor && svc.label) {
        rows.push({
          label: `Port ${svc.port}`,
          value:
            svc.label.replace(/^Port \d+\S*\s—\s/, "") || "Service observed",
        });
      }
    }

    if (
      censys.autonomousSystem &&
      typeof censys.autonomousSystem === "object"
    ) {
      const asn = firstDefined(
        censys.autonomousSystem.asn,
        censys.autonomousSystem.number
      );
      const name = firstDefined(
        censys.autonomousSystem.name,
        censys.autonomousSystem.organization,
        censys.autonomousSystem.org
      );
      if (asn || name) {
        rows.push({
          label: "Autonomous system",
          value: [asn && `AS${asn}`, name].filter(Boolean).join(" — "),
        });
      }
    }

    if (rows.length) {
      groups.push({ provider: "Censys", rows });
    }
  }

  // IPinfo — humanized
  const ipinfo = getIPinfoEvidence(investigation);
  if (ipinfo && sourceIsMeaningful(ipinfo.source)) {
    const rows = [];

    const countryMap = {
      DE: "Germany",
      US: "United States",
      GB: "United Kingdom",
      NG: "Nigeria",
      FR: "France",
      NL: "Netherlands",
      CA: "Canada",
      RU: "Russia",
      CN: "China",
    };

    if (ipinfo.country) {
      rows.push({
        label: "Country",
        value:
          countryMap[String(ipinfo.country).toUpperCase()] ||
          String(ipinfo.country),
      });
    }
    if (ipinfo.region) {
      rows.push({ label: "Region", value: String(ipinfo.region) });
    }
    if (ipinfo.city) {
      rows.push({ label: "City", value: String(ipinfo.city) });
    }
    if (ipinfo.hostname) {
      rows.push({
        label: "Hostname",
        value: truncate(String(ipinfo.hostname), 60),
        highlight: /tor|proxy|vpn/i.test(String(ipinfo.hostname)),
      });
    }
    if (ipinfo.org) {
      rows.push({
        label: "Organization",
        value: truncate(String(ipinfo.org), 60),
      });
    }

    if (rows.length) {
      groups.push({ provider: "IPinfo", rows });
    }
  }

  // Other providers — compact, non-duplicated
  const knownProviders = ["VirusTotal", "AbuseIPDB", "Censys", "IPinfo"];

  for (const source of meaningfulSources(investigation)) {
    const label = providerLabel(source);
    if (knownProviders.includes(label)) continue;

    const findings = getSourceFindings(source);
    const rows = [];

    for (const [field, value] of Object.entries(findings).slice(0, 5)) {
      if (value === undefined || value === null || value === "") continue;

      let printable;
      if (Array.isArray(value)) {
        printable = value
          .slice(0, 4)
          .map((v) =>
            typeof v === "object" ? truncate(JSON.stringify(v), 60) : String(v)
          )
          .join(", ");
      } else if (typeof value === "object") {
        printable = truncate(JSON.stringify(value), 120);
      } else {
        printable = truncate(String(value), 120);
      }

      if (!printable) continue;

      rows.push({
        label: humanizeField(field),
        value: printable,
      });
    }

    if (rows.length) {
      groups.push({ provider: label, rows });
    }
  }

  return groups;
}

// ============================================================================
// PLAIN-ENGLISH REPORT CONTENT (DEDUPLICATED)
// ============================================================================

function buildAssessmentSentence({ externalThreat, environmentalRisk }) {
  const strong = externalThreat === "high" || externalThreat === "critical";

  if (strong && environmentalRisk === "unknown") {
    return "Strong external warning signs were found, but the available evidence does not confirm impact inside your environment.";
  }

  if (strong && environmentalRisk !== "unknown") {
    return "Strong external warning signs were found. Environmental findings are based only on the internal evidence provided.";
  }

  if (externalThreat === "moderate" && environmentalRisk === "unknown") {
    return "Some external warning signs were found. Internal impact cannot be confirmed because internal telemetry was not provided.";
  }

  if (externalThreat === "moderate") {
    return "Some external warning signs were found. The available evidence does not establish that an attack occurred.";
  }

  if (externalThreat === "low") {
    return "Limited external warning signs were found. This does not prove the indicator is safe.";
  }

  return "Available external information was not sufficient to determine the external threat level with confidence.";
}

function buildWhyThisMatters({ investigation, externalThreat }) {
  const vt = getVirusTotalEvidence(investigation);
  const abuse = getAbuseIPDBEvidence(investigation);
  const censys = getCensysEvidence(investigation);

  const parts = [];

  if (vt && Number(vt.malicious) > 0) {
    parts.push(
      `VirusTotal recorded ${formatNumber(vt.malicious)} malicious detections`
    );
  } else if (vt && Number(vt.suspicious) > 0) {
    parts.push(
      `VirusTotal recorded ${formatNumber(vt.suspicious)} suspicious detections`
    );
  }

  if (abuse && Number(abuse.abuseConfidenceScore) > 0) {
    parts.push(
      `AbuseIPDB reported an abuse confidence of ${formatNumber(
        abuse.abuseConfidenceScore
      )}%`
    );
  }

  const torDetected =
    censys &&
    (censys.isTor === true || String(censys.isTor).toLowerCase() === "true");

  if (torDetected) {
    parts.push("Censys observed Tor/proxy infrastructure");
  }

  const strong = externalThreat === "high" || externalThreat === "critical";

  let opening = strong
    ? "External security sources show strong warning signs for this indicator."
    : externalThreat === "moderate"
    ? "External security sources show some warning signs for this indicator."
    : "External security sources show limited warning signs for this indicator.";

  let detail = "";
  if (parts.length) {
    detail = " " + capitalize(parts.join("; ")) + ".";
  }

  return (
    opening +
    detail +
    " External reputation increases concern, but it does not by itself prove that your environment was compromised."
  );
}

function buildEnvironmentCheck({ investigation, environmentalRisk }) {
  const internalTelemetry = detectInternalTelemetry(investigation);

  if (internalTelemetry) {
    return {
      telemetryLabel: "Available",
      message:
        "Environmental evidence was included in this investigation. External reputation should still be interpreted separately from proof of compromise.",
    };
  }

  if (environmentalRisk === "unknown") {
    return {
      telemetryLabel: "Not provided",
      message:
        "Because internal firewall, EDR, SIEM, DNS, proxy, identity, or network telemetry was not supplied, the investigation cannot determine whether the indicator affected your environment.",
    };
  }

  return {
    telemetryLabel: "Not provided",
    message:
      "Internal environmental evidence was not sufficient to determine whether this indicator affected your environment.",
  };
}

function buildRecommendations({ target, externalThreat, environmentalRisk }) {
  const strong = externalThreat === "high" || externalThreat === "critical";

  const steps = [
    `Search firewall, EDR, SIEM, DNS and proxy logs for ${truncate(
      String(target),
      40
    )}.`,
    "Identify the affected host, account, application or process that communicated with the indicator.",
    "Review activity immediately before and after the connection.",
    "Confirm whether the connection was expected or authorized.",
  ];

  if (strong) {
    steps.push(
      "If unauthorized, investigate as a security incident and consider containment according to your security process."
    );
  } else {
    steps.push(
      "Do not make a blocking decision from reputation alone — confirm activity and business context first."
    );
  }

  if (environmentalRisk === "unknown") {
    steps.push(
      "Review EDR, SIEM, firewall, DNS, proxy, identity, or network-flow logs for the same time period if available."
    );
  }

  steps.push("Continue monitoring for this and related indicators.");

  return steps.slice(0, 6);
}

function buildKeyLimitations({ investigation, environmentalRisk }) {
  const internalTelemetry = detectInternalTelemetry(investigation);
  const unique = new Set();

  const candidates = [];

  if (environmentalRisk === "unknown" && !internalTelemetry) {
    candidates.push(
      "No internal telemetry was provided, so environmental impact cannot be confirmed."
    );
  }

  // Surface unauthorized / failed providers (deduped)
  const sources = getSources(investigation);
  const failed = sources.filter((s) => {
    const status = String(s.status || "").toLowerCase();
    return (
      status === "unauthorized" || status === "error" || status === "failed"
    );
  });

  if (failed.length) {
    const labels = failed.map(providerLabel).join(", ");
    candidates.push(
      `Some sources were unavailable (${truncate(
        labels,
        80
      )}), which reduces coverage.`
    );
  }

  const partial = sources.filter(
    (s) => String(s.status || "").toLowerCase() === "partial"
  );

  if (partial.length) {
    const labels = partial.map(providerLabel).join(", ");
    candidates.push(
      `Partial results returned by ${truncate(
        labels,
        80
      )} limit confidence in those findings.`
    );
  }

  candidates.push(
    "External reputation alone does not confirm compromise or successful attack."
  );

  // Add investigation limitations, deduped
  for (const lim of getLimitations(investigation)) {
    const text = String(lim).trim();
    if (text) candidates.push(text);
  }

  const result = [];
  for (const c of candidates) {
    const key = c.toLowerCase();
    if (unique.has(key)) continue;
    unique.add(key);
    result.push(c);
    if (result.length >= 4) break;
  }

  return result;
}

// ============================================================================
// SOURCE SUMMARY
// ============================================================================

function buildSourceSummary(investigation) {
  return getSources(investigation).map((source) => ({
    label: providerLabel(source),

    status: String(source?.status || "unknown").toUpperCase(),

    meaningful: sourceIsMeaningful(source),
  }));
}

// ============================================================================
// PDF DESIGN PRIMITIVES
// ============================================================================

function ensureSpace(doc, requiredHeight = 60) {
  if (doc.y + requiredHeight > CONTENT.bottom) {
    doc.addPage();
    doc.y = PAGE.margin;
  }
}

function getLevelStyle(level) {
  const normalized = normalizeLevel(level);

  switch (normalized) {
    case "critical":
    case "high":
      return {
        color: COLORS.red,
        background: COLORS.redLight,
        border: COLORS.redBorder,
      };
    case "moderate":
      return {
        color: COLORS.amber,
        background: COLORS.amberLight,
        border: COLORS.amberBorder,
      };
    case "low":
      return {
        color: COLORS.green,
        background: COLORS.greenLight,
        border: COLORS.greenBorder,
      };
    default:
      return {
        color: COLORS.slate,
        background: COLORS.background,
        border: COLORS.border,
      };
  }
}

// ============================================================================
// PAGE FRAME
// ============================================================================

function drawHeader(doc, { target, targetType, reportId, generatedAt }) {
  // Top accent bar
  doc.rect(0, 0, PAGE.width, 5).fill(COLORS.blue);

  // Brand block
  doc
    .font("Helvetica-Bold")
    .fontSize(15)
    .fillColor(COLORS.navy)
    .text("LAKEWEST", PAGE.margin, 20);

  doc
    .font("Helvetica")
    .fontSize(7.5)
    .fillColor(COLORS.muted)
    .text("AI SECURITY ASSISTANT", PAGE.margin, 38);

  // Report type (right aligned)
  doc
    .font("Helvetica-Bold")
    .fontSize(8)
    .fillColor(COLORS.slate)
    .text("SECURITY INVESTIGATION BRIEF", PAGE.width - 240, 22, {
      width: 198,
      align: "right",
    });

  doc
    .font("Helvetica")
    .fontSize(7)
    .fillColor(COLORS.lightText)
    .text(`Report ID: ${truncate(reportId, 26)}`, PAGE.width - 240, 36, {
      width: 198,
      align: "right",
    });

  // Divider
  doc
    .moveTo(PAGE.margin, 54)
    .lineTo(PAGE.width - PAGE.margin, 54)
    .strokeColor(COLORS.border)
    .lineWidth(0.6)
    .stroke();

  // Target block (compact, prominent)
  const blockY = 62;
  const blockHeight = 48;

  doc
    .roundedRect(PAGE.margin, blockY, CONTENT.width, blockHeight, 7)
    .fillAndStroke(COLORS.background, COLORS.border);

  // Left accent
  doc.rect(PAGE.margin, blockY, 4, blockHeight).fill(COLORS.blue);

  doc
    .font("Helvetica")
    .fontSize(7)
    .fillColor(COLORS.muted)
    .text("TARGET", PAGE.margin + 14, blockY + 9);

  doc
    .font("Helvetica-Bold")
    .fontSize(13)
    .fillColor(COLORS.navy)
    .text(truncate(String(target), 70), PAGE.margin + 14, blockY + 21, {
      width: CONTENT.width - 220,
    });

  // Right side: type + generated
  doc
    .font("Helvetica-Bold")
    .fontSize(7.5)
    .fillColor(COLORS.blue)
    .text(
      String(targetType).toUpperCase(),
      PAGE.width - PAGE.margin - 200,
      blockY + 9,
      {
        width: 186,
        align: "right",
      }
    );

  doc
    .font("Helvetica")
    .fontSize(7.5)
    .fillColor(COLORS.muted)
    .text(
      `Generated ${formatDate(generatedAt)}`,
      PAGE.width - PAGE.margin - 240,
      blockY + 24,
      {
        width: 226,
        align: "right",
      }
    );

  doc.y = blockY + blockHeight + 12;
}

function drawFooter(doc) {
  const range = doc.bufferedPageRange();
  const total = range.count;

  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);

    doc
      .save()
      .strokeColor(COLORS.border)
      .lineWidth(0.5)
      .moveTo(PAGE.margin, CONTENT.footerY - 6)
      .lineTo(PAGE.width - PAGE.margin, CONTENT.footerY - 6)
      .stroke();

    doc
      .font("Helvetica")
      .fontSize(7)
      .fillColor(COLORS.lightText)
      .text("Lakewest AI Security Assistant", PAGE.margin, CONTENT.footerY, {
        width: 250,
      });

    doc
      .font("Helvetica")
      .fontSize(7)
      .fillColor(COLORS.lightText)
      .text(
        `Page ${i + 1} of ${total}`,
        PAGE.width - PAGE.margin - 120,
        CONTENT.footerY,
        {
          width: 120,
          align: "right",
        }
      );

    doc.restore();
  }
}

// ============================================================================
// SECTION HEADERS
// ============================================================================

function drawSectionHeader(doc, title, subtitle) {
  ensureSpace(doc, 36);

  const y = doc.y;

  // Small blue bar
  doc.rect(PAGE.margin, y + 1, 3, 13).fill(COLORS.blue);

  doc
    .font("Helvetica-Bold")
    .fontSize(10.5)
    .fillColor(COLORS.navy)
    .text(title, PAGE.margin + 11, y);

  if (subtitle) {
    doc
      .font("Helvetica")
      .fontSize(7.5)
      .fillColor(COLORS.muted)
      .text(subtitle, PAGE.margin + 11, y + 14, {
        width: CONTENT.width - 11,
      });
    doc.y = y + 30;
  } else {
    doc.y = y + 19;
  }

  doc.y += SPACE.section - 8;
}

// ============================================================================
// ASSESSMENT CARDS
// ============================================================================

function drawAssessmentCards(doc, externalThreat, environmentalRisk) {
  ensureSpace(doc, 92);

  const gap = 10;
  const cardWidth = (CONTENT.width - gap) / 2;
  const cardHeight = 74;
  const y = doc.y;

  const cards = [
    {
      x: PAGE.margin,
      title: "EXTERNAL THREAT",
      level: externalThreat,
      caption: "Reputation & external intelligence",
    },
    {
      x: PAGE.margin + cardWidth + gap,
      title: "ENVIRONMENTAL RISK",
      level: environmentalRisk,
      caption: "Evidence of impact in your environment",
    },
  ];

  for (const card of cards) {
    const style = getLevelStyle(card.level);

    doc
      .roundedRect(card.x, y, cardWidth, cardHeight, 8)
      .fillAndStroke(style.background, style.border);

    // Left severity accent
    doc.roundedRect(card.x, y, 4, cardHeight, 2).fill(style.color);

    doc
      .font("Helvetica-Bold")
      .fontSize(7.5)
      .fillColor(COLORS.muted)
      .text(card.title, card.x + 14, y + 11);

    // Level badge
    const badgeText = displayLevel(card.level);
    doc.font("Helvetica-Bold").fontSize(10);
    const badgeTextWidth = doc.widthOfString(badgeText);
    const badgeWidth = Math.max(70, badgeTextWidth + 26);
    const badgeHeight = 22;

    doc
      .roundedRect(card.x + 14, y + 25, badgeWidth, badgeHeight, 5)
      .fill(style.color);

    doc
      .font("Helvetica-Bold")
      .fontSize(10)
      .fillColor(COLORS.white)
      .text(badgeText, card.x + 14, y + 31, {
        width: badgeWidth,
        align: "center",
      });

    doc
      .font("Helvetica")
      .fontSize(7)
      .fillColor(COLORS.muted)
      .text(card.caption, card.x + 14, y + 55, {
        width: cardWidth - 28,
      });
  }

  doc.y = y + cardHeight + 10;
}

function drawAssessmentSentence(doc, sentence) {
  ensureSpace(doc, 44);

  const y = doc.y;

  doc.font("Helvetica").fontSize(9).fillColor(COLORS.slate);

  const textHeight = doc.heightOfString(sentence, {
    width: CONTENT.width - 26,
    lineGap: 2,
  });

  const boxHeight = textHeight + 20;

  doc
    .roundedRect(PAGE.margin, y, CONTENT.width, boxHeight, 6)
    .fillAndStroke(COLORS.blueLight, COLORS.blueBorder);

  doc.rect(PAGE.margin, y, 3, boxHeight).fill(COLORS.blue);

  doc
    .font("Helvetica")
    .fontSize(9)
    .fillColor(COLORS.slate)
    .text(sentence, PAGE.margin + 14, y + 10, {
      width: CONTENT.width - 26,
      lineGap: 2,
    });

  doc.y = y + boxHeight + 12;
}

// ============================================================================
// ACTION PANEL
// ============================================================================

function drawActionPanel(doc, steps) {
  ensureSpace(doc, 100);

  const startY = doc.y;

  doc
    .roundedRect(PAGE.margin, startY, CONTENT.width, 4, 2)
    .fill(COLORS.navy);

  const panelY = startY + 4;
  const paddingX = 14;
  const paddingTop = 11;

  let contentHeight = 0;

  contentHeight += 14;
  contentHeight += 8;

  const fontSize = 8.5;
  const stepHeight = 15;

  doc.font("Helvetica").fontSize(fontSize);

  for (const step of steps) {
    const h = doc.heightOfString(step, {
      width: CONTENT.width - paddingX * 2 - 18,
      lineGap: 1.5,
    });
    contentHeight += Math.max(stepHeight, h + 4);
  }

  const totalHeight = paddingTop + contentHeight + 12;

  doc
    .roundedRect(PAGE.margin, panelY, CONTENT.width, totalHeight, 7)
    .fillAndStroke(COLORS.white, COLORS.borderStrong);

  doc.roundedRect(PAGE.margin, panelY, 4, totalHeight, 2).fill(COLORS.red);

  doc
    .font("Helvetica-Bold")
    .fontSize(10)
    .fillColor(COLORS.navy)
    .text("WHAT TO DO NOW", PAGE.margin + paddingX, panelY + paddingTop);

  let cy = panelY + paddingTop + 20;

  steps.forEach((step, i) => {
    const numberText = `${i + 1}.`;
    const textX = PAGE.margin + paddingX + 16;

    doc
      .font("Helvetica-Bold")
      .fontSize(fontSize)
      .fillColor(COLORS.blue)
      .text(numberText, PAGE.margin + paddingX, cy + 1);

    doc
      .font("Helvetica")
      .fontSize(fontSize)
      .fillColor(COLORS.slate)
      .text(step, textX, cy, {
        width: CONTENT.width - paddingX * 2 - 18,
        lineGap: 1.5,
      });

    const h = doc.heightOfString(step, {
      width: CONTENT.width - paddingX * 2 - 18,
      lineGap: 1.5,
    });

    cy += Math.max(stepHeight, h + 4);
  });

  doc.y = panelY + totalHeight + 12;
}

// ============================================================================
// EVIDENCE ROWS (GROUPED, COMPACT)
// ============================================================================

function drawEvidenceGroups(doc, groups) {
  if (!groups.length) {
    ensureSpace(doc, 40);
    doc
      .font("Helvetica")
      .fontSize(8.5)
      .fillColor(COLORS.muted)
      .text(
        "No structured provider evidence was available.",
        PAGE.margin,
        doc.y,
        {
          width: CONTENT.width,
        }
      );
    doc.y += 16;
    return;
  }

  const labelWidth = 165;

  for (const group of groups) {
    const rowHeight = 16;
    const headerHeight = 16;
    const groupPad = 8;
    const groupHeight =
      headerHeight + group.rows.length * rowHeight + groupPad * 2;

    ensureSpace(doc, groupHeight + 8);

    const y = doc.y;

    doc
      .roundedRect(PAGE.margin, y, CONTENT.width, groupHeight, 6)
      .fillAndStroke(COLORS.white, COLORS.border);

    doc
      .roundedRect(PAGE.margin, y, CONTENT.width, headerHeight + 2, 6)
      .fill(COLORS.background);

    doc
      .font("Helvetica-Bold")
      .fontSize(8.5)
      .fillColor(COLORS.navy)
      .text(group.provider, PAGE.margin + 11, y + 4);

    let cy = y + headerHeight + 2;

    for (const row of group.rows) {
      doc
        .moveTo(PAGE.margin + 11, cy)
        .lineTo(PAGE.width - PAGE.margin - 11, cy)
        .strokeColor(COLORS.border)
        .lineWidth(0.4)
        .stroke();

      doc
        .font("Helvetica")
        .fontSize(8)
        .fillColor(COLORS.muted)
        .text(row.label, PAGE.margin + 11, cy + 4, {
          width: labelWidth,
        });

      doc
        .font(row.highlight ? "Helvetica-Bold" : "Helvetica")
        .fontSize(8)
        .fillColor(row.highlight ? COLORS.red : COLORS.navy)
        .text(String(row.value), PAGE.margin + 11 + labelWidth, cy + 4, {
          width: CONTENT.width - labelWidth - 22,
          align: "right",
        });

      cy += rowHeight;
    }

    doc.y = y + groupHeight + SPACE.rowGap + 2;
  }
}

// ============================================================================
// ENVIRONMENT CHECK
// ============================================================================

function drawEnvironmentCheck(doc, { telemetryLabel, message }) {
  ensureSpace(doc, 62);

  const y = doc.y;
  const paddingX = 12;
  const paddingY = 10;

  doc.font("Helvetica").fontSize(8.5);
  const textHeight = doc.heightOfString(message, {
    width: CONTENT.width - paddingX * 2,
    lineGap: 2,
  });

  const boxHeight = textHeight + paddingY * 2 + 18;

  const isUnknown = telemetryLabel === "Not provided";
  const bg = isUnknown ? COLORS.amberLight : COLORS.greenLight;
  const accent = isUnknown ? COLORS.amber : COLORS.green;
  const border = isUnknown ? COLORS.amberBorder : COLORS.greenBorder;

  doc
    .roundedRect(PAGE.margin, y, CONTENT.width, boxHeight, 6)
    .fillAndStroke(bg, border);

  doc.rect(PAGE.margin, y, 3, boxHeight).fill(accent);

  doc
    .font("Helvetica")
    .fontSize(7.5)
    .fillColor(COLORS.muted)
    .text("INTERNAL TELEMETRY", PAGE.margin + paddingX, y + paddingY);

  doc
    .font("Helvetica-Bold")
    .fontSize(10)
    .fillColor(accent)
    .text(
      telemetryLabel.toUpperCase(),
      PAGE.margin + paddingX,
      y + paddingY + 12
    );

  doc
    .font("Helvetica")
    .fontSize(8.5)
    .fillColor(COLORS.slate)
    .text(message, PAGE.margin + paddingX, y + paddingY + 30, {
      width: CONTENT.width - paddingX * 2,
      lineGap: 2,
    });

  doc.y = y + boxHeight + 12;
}

// ============================================================================
// COMPACT METRIC GRID (CONFIDENCE + COVERAGE)
// ============================================================================

function drawCompactMetricGrid(doc, metrics) {
  const columns = metrics.length <= 4 ? metrics.length : 4;
  const gap = 7;

  const cellWidth = (CONTENT.width - gap * (columns - 1)) / columns;
  const cellHeight = 46;

  const rows = Math.ceil(metrics.length / columns);
  const totalHeight = rows * cellHeight + (rows - 1) * gap;

  ensureSpace(doc, totalHeight + 8);

  const startY = doc.y;

  metrics.forEach((metric, i) => {
    const row = Math.floor(i / columns);
    const col = i % columns;

    const x = PAGE.margin + col * (cellWidth + gap);
    const y = startY + row * (cellHeight + gap);

    const style = metric.level
      ? getLevelStyle(metric.level)
      : {
          color: COLORS.blue,
          background: COLORS.blueLight,
          border: COLORS.blueBorder,
        };

    doc
      .roundedRect(x, y, cellWidth, cellHeight, 6)
      .fillAndStroke(COLORS.white, COLORS.border);

    doc.roundedRect(x, y, cellWidth, 3, 1.5).fill(style.color);

    doc
      .font("Helvetica")
      .fontSize(6.5)
      .fillColor(COLORS.muted)
      .text(metric.label.toUpperCase(), x + 9, y + 9, {
        width: cellWidth - 18,
      });

    doc
      .font("Helvetica-Bold")
      .fontSize(10)
      .fillColor(metric.level ? style.color : COLORS.navy)
      .text(String(metric.value), x + 9, y + 22, {
        width: cellWidth - 18,
      });
  });

  doc.y = startY + totalHeight + 12;
}

// ============================================================================
// SOURCE TABLE
// ============================================================================

function drawSourceTable(doc, sources) {
  if (!sources.length) {
    doc
      .font("Helvetica")
      .fontSize(8.5)
      .fillColor(COLORS.muted)
      .text("No security sources were recorded.", PAGE.margin, doc.y, {
        width: CONTENT.width,
      });
    doc.y += 16;
    return;
  }

  const rowHeight = 17;
  const headerHeight = 16;
  const statusColWidth = 90;

  const totalHeight = headerHeight + sources.length * rowHeight + 8;

  ensureSpace(doc, totalHeight + 8);

  const y = doc.y;

  doc
    .roundedRect(PAGE.margin, y, CONTENT.width, totalHeight, 6)
    .fillAndStroke(COLORS.white, COLORS.border);

  doc
    .roundedRect(PAGE.margin, y, CONTENT.width, headerHeight, 6)
    .fill(COLORS.background);

  doc
    .font("Helvetica-Bold")
    .fontSize(7)
    .fillColor(COLORS.muted)
    .text("SOURCE", PAGE.margin + 11, y + 5);

  doc
    .font("Helvetica-Bold")
    .fontSize(7)
    .fillColor(COLORS.muted)
    .text("STATUS", PAGE.width - PAGE.margin - statusColWidth - 11, y + 5, {
      width: statusColWidth,
      align: "right",
    });

  let cy = y + headerHeight;

  for (const source of sources) {
    doc
      .moveTo(PAGE.margin + 11, cy)
      .lineTo(PAGE.width - PAGE.margin - 11, cy)
      .strokeColor(COLORS.border)
      .lineWidth(0.4)
      .stroke();

    doc
      .font("Helvetica")
      .fontSize(8)
      .fillColor(COLORS.navy)
      .text(source.label, PAGE.margin + 11, cy + 4, {
        width: CONTENT.width - statusColWidth - 30,
      });

    const status = String(source.status || "unknown").toUpperCase();
    let badgeColor = COLORS.slate;
    let badgeBg = COLORS.background;
    let badgeBorder = COLORS.border;

    const lower = status.toLowerCase();
    if (lower === "success") {
      badgeColor = COLORS.green;
      badgeBg = COLORS.greenLight;
      badgeBorder = COLORS.greenBorder;
    } else if (lower === "partial") {
      badgeColor = COLORS.amber;
      badgeBg = COLORS.amberLight;
      badgeBorder = COLORS.amberBorder;
    } else if (
      lower === "unauthorized" ||
      lower === "error" ||
      lower === "failed"
    ) {
      badgeColor = COLORS.red;
      badgeBg = COLORS.redLight;
      badgeBorder = COLORS.redBorder;
    }

    doc.font("Helvetica-Bold").fontSize(6.5);
    const badgeW = Math.max(58, doc.widthOfString(status) + 16);
    const badgeX = PAGE.width - PAGE.margin - 11 - badgeW;
    const badgeH = 13;

    doc
      .roundedRect(badgeX, cy + 2, badgeW, badgeH, 3)
      .fillAndStroke(badgeBg, badgeBorder);

    doc
      .font("Helvetica-Bold")
      .fontSize(6.5)
      .fillColor(badgeColor)
      .text(status, badgeX, cy + 5, {
        width: badgeW,
        align: "center",
      });

    cy += rowHeight;
  }

  doc.y = y + totalHeight + 12;
}

// ============================================================================
// LIMITATIONS
// ============================================================================

function drawLimitations(doc, limitations) {
  if (!limitations.length) return;

  const bulletHeight = 14;
  ensureSpace(doc, limitations.length * bulletHeight + 10);

  let cy = doc.y;

  for (const lim of limitations) {
    doc.circle(PAGE.margin + 3, cy + 5, 1.8).fill(COLORS.amber);

    doc
      .font("Helvetica")
      .fontSize(8)
      .fillColor(COLORS.slate)
      .text(lim, PAGE.margin + 12, cy, {
        width: CONTENT.width - 12,
        lineGap: 1.5,
      });

    const h = doc.heightOfString(lim, {
      width: CONTENT.width - 12,
      lineGap: 1.5,
    });

    cy += Math.max(bulletHeight, h + 4);
  }

  doc.y = cy + 8;
}

// ============================================================================
// PDF BUFFER
// ============================================================================

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

// ============================================================================
// MAIN REPORT GENERATOR
// ============================================================================

async function generateSecurityReport({
  investigation,
  metadata,
  target,
  requestId,
} = {}) {
  const inv = extractInvestigation({ investigation, metadata });

  if (!inv) {
    throw new Error("No security investigation was provided.");
  }

  const resolvedTarget = getTarget({
    investigation: inv,
    metadata,
    target,
  });

  const targetType = detectTargetType({
    investigation: inv,
    metadata,
    target: resolvedTarget,
  });

  // --------------------------------------------------------------------------
  // AUTHORITATIVE SECURITY ASSESSMENT (UNCHANGED)
  // --------------------------------------------------------------------------

  const externalThreat = deriveExternalThreat(inv);
  const environmentalRisk = deriveEnvironmentalRisk(inv);
  const externalConfidence = deriveExternalConfidence(inv);
  const environmentalConfidence = deriveEnvironmentalConfidence(inv);
  const overallConfidence = deriveOverallConfidence(inv);
  const coverage = deriveCoverage(inv);
  const internalTelemetry = detectInternalTelemetry(inv);
  const meaningfulCount = meaningfulSources(inv).length;
  const consultedCount = getSources(inv).length;

  const reportId = requestId || generateReportId();
  const generatedAt = new Date();

  // --------------------------------------------------------------------------
  // DERIVED PRESENTATION CONTENT
  // --------------------------------------------------------------------------

  const assessmentSentence = buildAssessmentSentence({
    externalThreat,
    environmentalRisk,
  });

  const whyThisMatters = buildWhyThisMatters({
    investigation: inv,
    externalThreat,
  });

  const environmentCheck = buildEnvironmentCheck({
    investigation: inv,
    environmentalRisk,
  });

  const recommendations = buildRecommendations({
    target: resolvedTarget,
    externalThreat,
    environmentalRisk,
  });

  const evidenceGroups = collectEvidenceRows(inv);

  const keyLimitations = buildKeyLimitations({
    investigation: inv,
    environmentalRisk,
  });

  const sources = buildSourceSummary(inv);

  // --------------------------------------------------------------------------
  // BUILD PDF
  // --------------------------------------------------------------------------

  return createPdfBuffer((doc) => {
    // ----------------------------------------------------------------------
    // HEADER + ASSESSMENT
    // ----------------------------------------------------------------------

    drawHeader(doc, {
      target: resolvedTarget,
      targetType,
      reportId,
      generatedAt,
    });

    drawAssessmentCards(doc, externalThreat, environmentalRisk);

    drawAssessmentSentence(doc, assessmentSentence);

    // ----------------------------------------------------------------------
    // ACTION REQUIRED
    // ----------------------------------------------------------------------

    drawSectionHeader(
      doc,
      "What To Do Now",
      "Immediate next steps for the analyst"
    );

    drawActionPanel(doc, recommendations);

    // ----------------------------------------------------------------------
    // WHY THIS MATTERS
    // ----------------------------------------------------------------------

    drawSectionHeader(
      doc,
      "Why This Matters",
      "External signal vs. environmental impact"
    );

    ensureSpace(doc, 50);

    {
      const y = doc.y;
      doc.font("Helvetica").fontSize(8.5);
      const textHeight = doc.heightOfString(whyThisMatters, {
        width: CONTENT.width - 24,
        lineGap: 2,
      });
      const boxHeight = textHeight + 18;

      doc
        .roundedRect(PAGE.margin, y, CONTENT.width, boxHeight, 6)
        .fillAndStroke(COLORS.background, COLORS.border);

      doc.rect(PAGE.margin, y, 3, boxHeight).fill(COLORS.blue);

      doc
        .font("Helvetica")
        .fontSize(8.5)
        .fillColor(COLORS.slate)
        .text(whyThisMatters, PAGE.margin + 13, y + 9, {
          width: CONTENT.width - 24,
          lineGap: 2,
        });

      doc.y = y + boxHeight + 12;
    }

    // ----------------------------------------------------------------------
    // KEY EVIDENCE
    // ----------------------------------------------------------------------

    drawSectionHeader(
      doc,
      "Key Evidence",
      "Most relevant provider findings (humanized)"
    );

    drawEvidenceGroups(doc, evidenceGroups);

    // ----------------------------------------------------------------------
    // ENVIRONMENT CHECK
    // ----------------------------------------------------------------------

    drawSectionHeader(
      doc,
      "Environment Check",
      "Whether internal telemetry was available"
    );

    drawEnvironmentCheck(doc, environmentCheck);

    // ----------------------------------------------------------------------
    // CONFIDENCE + COVERAGE
    // ----------------------------------------------------------------------

    drawSectionHeader(
      doc,
      "Confidence & Coverage",
      "Strength and breadth of available evidence"
    );

    drawCompactMetricGrid(doc, [
      {
        label: "External confidence",
        value: displayLevel(externalConfidence),
        level: externalConfidence,
      },
      {
        label: "Environmental confidence",
        value: displayLevel(environmentalConfidence),
        level: environmentalConfidence,
      },
      {
        label: "Overall confidence",
        value: displayLevel(overallConfidence),
        level: overallConfidence,
      },
      {
        label: "Coverage",
        value: String(coverage).toUpperCase(),
      },
    ]);

    // Sources line
    ensureSpace(doc, 24);
    doc
      .font("Helvetica")
      .fontSize(8)
      .fillColor(COLORS.muted)
      .text(
        `Sources: ${meaningfulCount} meaningful / ${consultedCount} consulted`,
        PAGE.margin,
        doc.y,
        { width: CONTENT.width }
      );
    doc.y += 16;

    // ----------------------------------------------------------------------
    // SECURITY SOURCES TABLE
    // ----------------------------------------------------------------------

    drawSectionHeader(
      doc,
      "Security Sources",
      "Provider availability and status"
    );

    drawSourceTable(doc, sources);

    // ----------------------------------------------------------------------
    // IMPORTANT LIMITATIONS
    // ----------------------------------------------------------------------

    if (keyLimitations.length) {
      drawSectionHeader(
        doc,
        "Important Limitations",
        "Context to consider before taking action"
      );

      drawLimitations(doc, keyLimitations);
    }

    // ----------------------------------------------------------------------
    // FINAL DISCLAIMER (compact)
    // ----------------------------------------------------------------------

    ensureSpace(doc, 44);

    {
      const y = doc.y;
      const disclaimer =
        "External reputation does not confirm compromise. Internal security logs may be required to determine whether your environment was affected.";

      doc.font("Helvetica").fontSize(7.5);
      const h = doc.heightOfString(disclaimer, {
        width: CONTENT.width - 20,
        lineGap: 1.5,
      });
      const boxHeight = h + 18;

      doc
        .roundedRect(PAGE.margin, y, CONTENT.width, boxHeight, 6)
        .fillAndStroke(COLORS.navy, COLORS.navy);

      doc
        .font("Helvetica")
        .fontSize(7.5)
        .fillColor("#CBD5E1")
        .text(disclaimer, PAGE.margin + 10, y + 9, {
          width: CONTENT.width - 20,
          lineGap: 1.5,
        });

      doc.y = y + boxHeight + 6;
    }
  });
}

// ============================================================================
// EXPORT
// ============================================================================

module.exports = {
  generateSecurityReport,
};