"use strict";

const LABELS = Object.freeze({
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  ipinfo: "IPinfo",
  censys: "Censys",
  shodan: "Shodan",
  urlscan: "URLScan",
  securitytrails: "SecurityTrails",
  mozilla_observatory: "Mozilla Observatory",
  google_web_risk: "Google Web Risk",
  "google-web-risk": "Google Web Risk",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  phishtank: "PhishTank",
  phishing_database: "Phishing.Database",
  viewdns: "ViewDNS",
  hibp: "Have I Been Pwned",
});

const THREAT_PROVIDERS = new Set([
  "virustotal", "abuseipdb", "google_web_risk", "google-web-risk",
  "urlhaus", "threatfox", "phishtank", "phishing_database",
]);
const POSTURE_PROVIDERS = new Set(["mozilla_observatory"]);
const CONTEXT_PROVIDERS = new Set([
  "ipinfo", "censys", "shodan", "urlscan", "securitytrails", "viewdns",
]);
const FAILED_STATUSES = new Set([
  "error", "failed", "timeout", "unauthorized", "not_configured",
  "rate_limited", "unavailable", "skipped",
]);

function sourcesOf(investigation) {
  return Array.isArray(investigation?.sources) ? investigation.sources : [];
}

function findingsOf(source) {
  if (source?.findings && typeof source.findings === "object" && !Array.isArray(source.findings)) return source.findings;
  if (Array.isArray(source?.findings)) return source.findings.find((item) => item && typeof item === "object") || {};
  return {};
}

function providerName(provider) {
  return LABELS[String(provider || "").toLowerCase()] || String(provider || "Security provider");
}

function numberFrom(...values) {
  for (const value of values) {
    if (value === null || value === undefined || value === "") continue;
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function freshnessOf(source) {
  return String(source?.quality?.freshness?.status || source?.freshness || "unknown").toLowerCase();
}

function dateOf(source, findings = findingsOf(source)) {
  return source?.providerAnalysisAt || source?.providerObservedAt || findings.lastAnalysisDate || findings.last_analysis_date || findings.lastReportedAt || findings.last_reported_at || findings.lastUpdated || null;
}

function formatDate(value) {
  if (!value) return "";
  const numeric = Number(value);
  const date = Number.isFinite(numeric) && numeric > 0
    ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
    : new Date(value);
  if (!Number.isFinite(date.getTime())) return "";
  return new Intl.DateTimeFormat("en-US", { timeZone: "UTC", year: "numeric", month: "short", day: "2-digit" }).format(date);
}

function sourceFreshnessPhrase(source) {
  const findings = findingsOf(source);
  const freshness = freshnessOf(source);
  const date = formatDate(dateOf(source, findings));
  return `Freshness: ${freshness}${date ? `; last analysis/report: ${date}` : ""}.`;
}

function sourceIsUsable(source) {
  return ["success", "partial", "empty"].includes(String(source?.status || "").toLowerCase());
}

function sourceHasPositiveEvidence(source) {
  return ["success", "partial"].includes(String(source?.status || "").toLowerCase()) &&
    source?.quality?.meaningful === true && !["no_match", "not_found"].includes(String(source?.findingType || "").toLowerCase());
}

function isThreatMatch(source) {
  if (!sourceHasPositiveEvidence(source)) return false;
  const provider = String(source?.provider || "").toLowerCase();
  const f = findingsOf(source);
  if (provider === "virustotal") return numberFrom(f.malicious, f.maliciousCount, f.lastAnalysisStats?.malicious) > 0 || numberFrom(f.suspicious, f.suspiciousCount, f.lastAnalysisStats?.suspicious) > 0;
  if (provider === "abuseipdb") return numberFrom(f.abuseConfidenceScore, f.abuse_confidence_score) > 0 || numberFrom(f.totalReports, f.total_reports) > 0;
  if (provider === "google_web_risk" || provider === "google-web-risk") return Array.isArray(f.matches) && f.matches.length > 0;
  if (provider === "urlhaus" || provider === "phishing_database") return f.match === true;
  if (provider === "threatfox") return Array.isArray(f.matches) && f.matches.length > 0;
  if (provider === "phishtank") return f.match === true && Array.isArray(f.matches) && f.matches.some((match) => match?.verified === true || /^(?:true|yes|1)$/i.test(String(match?.verified || "")));
  return THREAT_PROVIDERS.has(provider) && source?.quality?.directness === "reputation" && source?.quality?.meaningful === true;
}

function threatIntelligenceSummaries(investigation) {
  const summaries = [];
  for (const source of sourcesOf(investigation)) {
    const provider = String(source?.provider || "").toLowerCase();
    if (!THREAT_PROVIDERS.has(provider) || !sourceIsUsable(source) || !isThreatMatch(source)) continue;
    const findings = findingsOf(source);
    const freshness = sourceFreshnessPhrase(source);
    if (provider === "virustotal") {
      const malicious = numberFrom(findings.malicious, findings.maliciousCount, findings.lastAnalysisStats?.malicious);
      const suspicious = numberFrom(findings.suspicious, findings.suspiciousCount, findings.lastAnalysisStats?.suspicious);
      const harmless = numberFrom(findings.harmless, findings.harmlessCount, findings.lastAnalysisStats?.harmless);
      const undetected = numberFrom(findings.undetected, findings.undetectedCount, findings.lastAnalysisStats?.undetected);
      const counts = [];
      if (malicious !== null) counts.push(`${malicious} malicious`);
      if (suspicious !== null) counts.push(`${suspicious} suspicious`);
      if (harmless !== null) counts.push(`${harmless} harmless`);
      if (undetected !== null) counts.push(`${undetected} undetected`);
      summaries.push({ provider: "VirusTotal", text: `VirusTotal reported ${counts.join(", ")} detections. ${freshness}`, source });
    } else if (provider === "abuseipdb") {
      const confidence = numberFrom(findings.abuseConfidenceScore, findings.abuse_confidence_score);
      const reports = numberFrom(findings.totalReports, findings.total_reports);
      const details = [];
      if (confidence !== null) details.push(`${confidence}% abuse confidence`);
      if (reports !== null) details.push(`${reports} reported abuse cases`);
      summaries.push({ provider: "AbuseIPDB", text: `AbuseIPDB reported ${details.join(" with ")}. ${freshness}`, source });
    } else {
      summaries.push({ provider: providerName(provider), text: `${providerName(provider)} returned a matching threat-intelligence record. ${freshness}`, source });
    }
  }
  return summaries;
}

function postureSummaries(investigation) {
  return sourcesOf(investigation).filter((source) => POSTURE_PROVIDERS.has(String(source?.provider || "").toLowerCase()) && sourceHasPositiveEvidence(source)).map((source) => {
    const f = findingsOf(source);
    const grade = f.grade || f.letterGrade || f.securityGrade || null;
    const score = numberFrom(f.score, f.observatoryScore, f.gradeScore);
    const testsFailed = numberFrom(f.testsFailed, f.failedTests, f.failed, f.tests?.failed);
    const testsPassed = numberFrom(f.testsPassed, f.passedTests, f.passed, f.tests?.passed);
    const results = [];
    if (grade !== null && grade !== undefined && grade !== "") results.push(`Grade ${String(grade)}`);
    if (score !== null) results.push(`Score ${score}`);
    if (testsFailed !== null || testsPassed !== null) results.push(`${testsFailed ?? "?"} tests failed / ${testsPassed ?? "?"} passed`);
    return { provider: providerName(source.provider), text: `${providerName(source.provider)} reported ${results.length ? results.join("; ") : "a security-posture result"}. Security posture finding; it is not evidence of malicious activity by itself. ${sourceFreshnessPhrase(source)}`, source, grade, score, testsFailed, testsPassed };
  });
}

function contextualSummaries(investigation) {
  const summaries = [];
  for (const source of sourcesOf(investigation)) {
    const provider = String(source?.provider || "").toLowerCase();
    if (!CONTEXT_PROVIDERS.has(provider) || !sourceIsUsable(source) || source?.quality?.meaningful !== true) continue;
    const findings = findingsOf(source);
    if (provider === "ipinfo") {
      const details = [findings.country, findings.region, findings.city, findings.organization || findings.org, findings.hostname].filter((value) => typeof value === "string" && value.trim()).slice(0, 4);
      const torContext = details.some((value) => /tor[- ]?exit/i.test(value)) ? " This includes a Tor-exit hostname indicator." : "";
      summaries.push(details.length ? `IPinfo returned network identity and location context: ${details.join(", ")}.${torContext} This context does not establish malicious activity or communication from inside the environment.` : "IPinfo returned contextual network observations; these do not establish malicious activity or communication from inside the environment.");
    } else if (provider === "shodan") {
      const ports = Array.isArray(findings.ports) ? findings.ports.filter((port) => port !== null && port !== undefined).slice(0, 5) : [];
      const details = [];
      if (ports.length) details.push(`externally observed port${ports.length === 1 ? "" : "s"} ${ports.join(", ")}`);
      const organization = findings.organization || findings.org;
      if (typeof organization === "string" && organization.trim()) details.push(`organization ${organization.trim()}`);
      const hostname = (Array.isArray(findings.hostnames) ? findings.hostnames : [findings.hostname]).find((value) => typeof value === "string" && value.trim());
      if (hostname) details.push(`hostname ${hostname.trim()}`);
      const torContext = details.some((value) => /tor[- ]?exit/i.test(value)) || /tor[- ]?exit/i.test(JSON.stringify(findings)) ? " This includes a Tor-exit infrastructure indicator." : "";
      summaries.push(`Shodan ${details.length ? `listed ${details.join("; ")}` : "returned infrastructure observations"}.${torContext} These external service observations do not establish malicious activity or show that an internal host communicated with the target.`);
    } else if (provider === "urlscan") {
      const count = numberFrom(findings.totalResults, findings.total_results);
      summaries.push(`URLScan returned ${count === null ? "observational" : `${count} scan`} result${count === 1 ? "" : "s"}. URLScan observations are context, not automatic malicious confirmation.`);
    } else {
      const serialized = JSON.stringify(findings);
      const torContext = /\btor[- ]?exit\b/i.test(serialized) ? " The observations include a Tor-exit infrastructure indicator." : "";
      summaries.push(`${providerName(provider)} returned contextual infrastructure observations.${torContext} These do not by themselves establish malicious activity or environmental impact.`);
    }
  }
  return summaries.slice(0, 3);
}

function confidenceLabel(value) {
  const label = String(value || "unknown").replace(/[_-]+/g, " ").trim();
  return label ? label.charAt(0).toUpperCase() + label.slice(1) : "Unknown";
}

function buildCurator(investigation) {
  const threatEvidence = threatIntelligenceSummaries(investigation);
  const context = contextualSummaries(investigation);
  const posture = postureSummaries(investigation);
  const risk = investigation?.risk || {};
  const confidence = investigation?.confidence || {};
  const targetType = String(investigation?.targetType || "").toLowerCase();
  const isIp = /^(?:ip|ipv4|ipv6)$/.test(targetType);
  const vt = threatEvidence.find((item) => item.provider === "VirusTotal");
  const abuseSource = sourcesOf(investigation).find((source) => String(source?.provider || "").toLowerCase() === "abuseipdb");
  const abuseFindings = abuseSource ? findingsOf(abuseSource) : {};
  const abuseCanBeCited = abuseSource && ["success", "partial"].includes(String(abuseSource.status || "").toLowerCase());
  const abuseConfidence = abuseCanBeCited ? numberFrom(abuseFindings.abuseConfidenceScore, abuseFindings.abuse_confidence_score) : null;
  const abuseReports = abuseCanBeCited ? numberFrom(abuseFindings.totalReports, abuseFindings.total_reports) : null;
  const vtFindings = vt ? findingsOf(vt.source) : {};
  const vtMalicious = numberFrom(vtFindings.malicious, vtFindings.maliciousCount, vtFindings.lastAnalysisStats?.malicious);
  const vtSuspicious = numberFrom(vtFindings.suspicious, vtFindings.suspiciousCount, vtFindings.lastAnalysisStats?.suspicious);
  const abuseHasZero = abuseConfidence === 0 && abuseReports === 0;
  const historicalThreatLevel = String(risk.externalThreat || risk.level || "unknown").toLowerCase();
  const independentThreatProviders = numberFrom(risk.independentProviderCount) ?? new Set(threatEvidence.map((item) => item.provider)).size;
  let whatMatters;
  if (vt && abuseConfidence > 0 && abuseReports > 0) {
    const strong = ["high", "critical"].includes(historicalThreatLevel);
    whatMatters = `VirusTotal returned ${vtMalicious ?? 0} malicious and ${vtSuspicious ?? 0} suspicious detections, while AbuseIPDB reported ${abuseConfidence}% abuse confidence across ${abuseReports} reports. ${strong ? "The canonical assessment treats these as strong corroborating external reputation signals" : "These are corroborating external reputation signals"}; they do not confirm current activity or establish impact inside the environment.`;
  } else if (vt && abuseHasZero) {
    const detections = (vtMalicious || 0) + (vtSuspicious || 0);
    const limited = detections <= 4 && !["high", "critical"].includes(historicalThreatLevel);
    const historical = ["stale", "aging"].includes(freshnessOf(vt.source)) ? "historical " : "";
    whatMatters = `VirusTotal returned ${vtMalicious ?? 0} malicious and ${vtSuspicious ?? 0} suspicious detections. These are ${limited ? "limited " : ""}${historical}threat signals${independentThreatProviders < 2 ? " without independent threat-provider corroboration" : ""}; AbuseIPDB returned 0% abuse confidence and no reports. The providers use different datasets, so this is a signal difference, not proof of current activity or environmental impact.`;
  } else if (vt) {
    const latest = formatDate(dateOf(vt.source, vtFindings));
    const isOld = ["stale", "aging"].includes(freshnessOf(vt.source));
    const singleProvider = independentThreatProviders < 2;
    whatMatters = `VirusTotal returned ${vtMalicious ?? 0} malicious and ${vtSuspicious ?? 0} suspicious detections${latest ? `; its latest available analysis is from ${latest}` : ""}. ${singleProvider ? "These engine detections come from one provider and lack independent malicious-reputation corroboration. " : "Independent threat-reputation sources also contributed evidence. "}${isOld ? "This is historical reputation evidence, not confirmation of current activity." : "This is an external reputation signal and does not establish activity inside the environment."}`;
  } else if (threatEvidence.length) {
    whatMatters = `Meaningful threat-intelligence evidence was returned by ${threatEvidence.slice(0, 2).map((item) => item.provider).join(" and ")}. The external evidence does not establish activity inside the environment.`;
  } else if (context.length || posture.length) {
    const availableContext = [...context, ...posture.map((item) => item.text)].slice(0, 1).join(" ");
    whatMatters = `No direct malicious or phishing reputation match was established. ${availableContext} These contextual observations do not establish malicious activity; no-match, unavailable, and unknown results do not establish that the target is safe.`;
  } else {
    whatMatters = "Available evidence is insufficient to establish a direct malicious or phishing match. No-match, unavailable, and unknown results do not establish that the target is safe.";
  }
  const contextItems = [...context, ...posture.map((item) => item.text)];
  const staleSources = sourcesOf(investigation).filter((source) => ["stale", "aging"].includes(freshnessOf(source)) && isThreatMatch(source));
  if (staleSources.length) contextItems.unshift(`The latest available ${staleSources.map((source) => providerName(source.provider)).join(" and ")} evidence is aging or stale; it remains historical evidence but does not establish current activity.`);
  if (abuseHasZero && vt) contextItems.unshift("AbuseIPDB and VirusTotal returned different reputation signals; their datasets and methods differ, so this is a signal difference rather than proof either provider is wrong.");
  const coverage = investigation?.coverage || {};
  if (Number(coverage.failed || 0) > 0 || Number(coverage.unavailable || 0) > 0) contextItems.push("Provider coverage was partial because one or more consulted sources were unavailable or failed.");
  const importantContext = contextItems.length
    ? contextItems.slice(0, 2).join(" ")
    : "No additional contextual infrastructure or security-posture observations were established by the available successful sources.";
  const environmentalRisk = String(risk.environmentalRisk || "unknown").toLowerCase();
  const target = String(investigation?.target || "this target");
  const whatWeDoNotKnow = environmentalRisk === "unknown"
    ? `No internal telemetry was provided, so it is unknown whether ${target} communicated with, was accessed by, or affected the environment.`
    : "Environmental conclusions are limited to the internal telemetry included in this investigation; activity outside that evidence window remains unknown.";
  const recommendedNextStep = isIp
    ? `Search historical firewall, proxy, DNS, EDR, SIEM and network-flow telemetry for ${target}; determine inbound/outbound direction, affected hosts, identities and authorization.`
    : `Search DNS, proxy, web-gateway, email-security, browser and EDR telemetry for ${target}; identify users or hosts, downloads, credential submission and redirects where available.`;
  const isTrackingUrl = targetType === "url" && (/(?:^|\/)(?:click|redirect|track|tracking|out|link)(?:\/|[?#]|$)/i.test(target) || /[?&](?:url|u|redirect|redirect_url|target|destination)=/i.test(target));
  const trackingUrlGuidance = isTrackingUrl
    ? ` For the supplied URL ${target}, inspect the redirect chain and final destination in a controlled, isolated investigation environment. No redirect or destination is verified unless an observation below explicitly establishes it; do not open the URL on an analyst's normal workstation.`
    : "";
  const unknownFreshnessSources = threatEvidence.map((item) => item.source).filter((source) => freshnessOf(source) === "unknown");
  const freshnessParts = [];
  if (staleSources.length) freshnessParts.push(`Historical threat evidence from ${staleSources.map((source) => providerName(source.provider)).join(" and ")} remains evidence, but its age reduces confidence that the same threat condition is active now.`);
  if (unknownFreshnessSources.length) freshnessParts.push(`Freshness could not be verified for threat evidence from ${[...new Set(unknownFreshnessSources.map((source) => providerName(source.provider)))].join(" and ")}; treat it as undated evidence, not verified current activity.`);
  const freshnessNote = freshnessParts.join(" ");
  return {
    whatMatters,
    importantContext,
    whatWeDoNotKnow,
    recommendedNextStep: `${recommendedNextStep}${trackingUrlGuidance}`,
    freshnessNote,
    confidence: {
      evidence: confidenceLabel(confidence.evidenceConfidenceLevel || confidence.externalIntelligence || confidence.externalConfidence),
      evidenceScore: numberFrom(confidence.evidenceConfidenceScore, confidence.externalIntelligenceScore),
      currentStatus: confidenceLabel(confidence.currentStatusConfidenceLevel),
      currentStatusScore: numberFrom(confidence.currentStatusConfidenceScore, risk.externalThreatAssessment?.currentStatusConfidence),
      environmentalImpact: environmentalRisk === "unknown" ? "Unknown — no internal telemetry was provided" : confidenceLabel(environmentalRisk),
      overall: confidenceLabel(confidence.level),
      overallScore: numberFrom(confidence.score, confidence.overallConfidenceScore),
    },
    threatEvidence,
    posture,
    context,
  };
}

function buildWhyThisMatters(investigation) {
  const summaries = threatIntelligenceSummaries(investigation);
  if (!summaries.length) return [];
  const reasons = summaries.slice(0, 3).map((item) => item.text);
  reasons.push("These are external intelligence signals and do not by themselves prove compromise, successful exploitation, or impact inside the environment.");
  return reasons;
}

module.exports = {
  sourcesOf,
  findingsOf,
  providerName,
  freshnessOf,
  formatDate,
  sourceFreshnessPhrase,
  threatIntelligenceSummaries,
  postureSummaries,
  contextualSummaries,
  buildCurator,
  buildWhyThisMatters,
};
