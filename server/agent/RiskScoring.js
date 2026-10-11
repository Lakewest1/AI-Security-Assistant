"use strict";

// All external-threat score weights live here. VirusTotal engine counts are
// bounded as one provider signal; independent corroboration is counted once
// per provider, never once per engine.
const RISK_WEIGHTS = Object.freeze({
  virusTotalBase: 53,
  virusTotalMaliciousPerEngine: 3,
  virusTotalMaliciousCap: 35,
  virusTotalSuspiciousPerEngine: 1.5,
  virusTotalSuspiciousCap: 6,
  abuseOnlyBase: 42,
  abuseConfidenceMultiplier: 0.25,
  abuseWithOtherSignalMultiplier: 0.2,
  abuseConfidenceCap: 25,
  abuseWithOtherSignalCap: 20,
  reportVolumePerFifty: 1,
  reportVolumeCap: 4,
  confirmedUrlMatch: 17,
  independentProviderCorroboration: 8,
  independentProviderCap: 16,
  recentEvidence: 3,
  agingEvidence: 0,
  staleEvidence: -14,
  unknownFreshness: -4,
  conflict: -6,
  conflictCap: 18,
  infrastructureContext: 2,
});

function n(value) { const result = Number(value); return Number.isFinite(result) ? result : null; }
function freshnessContribution(source) {
  const status = source?.quality?.freshness?.status || source?.freshness || "unknown";
  if (status === "recent" || status === "fresh") return RISK_WEIGHTS.recentEvidence;
  if (status === "aging") return RISK_WEIGHTS.agingEvidence;
  if (status === "stale") return RISK_WEIGHTS.staleEvidence;
  return RISK_WEIGHTS.unknownFreshness;
}
function factor(name, signal, contribution, evidenceSource = null, evidenceId = null) {
  return { name, signal, contribution, evidenceSource, evidenceId };
}
function riskBand(score, independentProviders) {
  if (score === null) return "unknown";
  if (score >= 95 && independentProviders >= 2) return "critical";
  if (score >= 70) return "high";
  if (score >= 55) return "elevated";
  if (score >= 35) return "moderate";
  return "low";
}
function confidenceBand(score) {
  if (score >= 80) return "high";
  if (score >= 60) return "moderate";
  return "low";
}

function currentStatusConfidence(threatSources, failed) {
  if (!threatSources.length) return null;
  const weights = { recent: 100, fresh: 100, aging: 70, stale: 30, unknown: 50 };
  const averageFreshness = threatSources.reduce((total, source) => {
    const status = source?.quality?.freshness?.status || source?.freshness || "unknown";
    return total + (weights[status] ?? weights.unknown);
  }, 0) / threatSources.length;
  const corroboration = Math.min(1, new Set(threatSources.map(source => source.provider)).size / 2);
  const corroborationFactor = 0.75 + 0.25 * corroboration;
  const failurePenalty = Math.min(18, failed.length * 3);
  // Current status confidence is capped: fresh external feeds still do not
  // establish that a threat is active in the user's environment.
  return Math.max(0, Math.min(95, Math.round(averageFreshness * corroborationFactor - failurePenalty)));
}

function calculateRisk({ investigation, successful = [], failed = [], environmentalRefs = [], urlReputation = {} } = {}) {
  const sources = successful.filter(source => source?.quality?.meaningful === true);
  const byProvider = new Map(sources.map(source => [source.provider, source]));
  const vt = byProvider.get("virustotal");
  const abuse = byProvider.get("abuseipdb");
  const factors = [];
  const threatProviders = new Set();
  let directSignalCount = 0;

  if (vt) {
    const malicious = Math.max(0, n(vt.findings?.malicious) || 0);
    const suspicious = Math.max(0, n(vt.findings?.suspicious) || 0);
    if (malicious > 0 || suspicious > 0) {
      factors.push(factor("direct_reputation_base", "VirusTotal supplied malicious or suspicious detections", RISK_WEIGHTS.virusTotalBase, "virustotal", vt.evidenceId));
      if (malicious > 0) factors.push(factor("virustotal_malicious_detections", `${malicious} malicious engines (bounded as one provider signal)`, Math.min(RISK_WEIGHTS.virusTotalMaliciousCap, malicious * RISK_WEIGHTS.virusTotalMaliciousPerEngine), "virustotal", vt.evidenceId));
      if (suspicious > 0) factors.push(factor("virustotal_suspicious_detections", `${suspicious} suspicious engines`, Math.min(RISK_WEIGHTS.virusTotalSuspiciousCap, suspicious * RISK_WEIGHTS.virusTotalSuspiciousPerEngine), "virustotal", vt.evidenceId));
      threatProviders.add("virustotal");
      directSignalCount += 1;
    }
  }

  if (abuse) {
    const confidence = Math.max(0, n(abuse.findings?.abuseConfidenceScore) || 0);
    const reports = Math.max(0, n(abuse.findings?.totalReports) || 0);
    if (confidence > 0 || reports > 0) {
      if (!directSignalCount) factors.push(factor("direct_reputation_base", "AbuseIPDB supplied abuse reputation evidence", RISK_WEIGHTS.abuseOnlyBase, "abuseipdb", abuse.evidenceId));
      const multiplier = directSignalCount ? RISK_WEIGHTS.abuseWithOtherSignalMultiplier : RISK_WEIGHTS.abuseConfidenceMultiplier;
      const cap = directSignalCount ? RISK_WEIGHTS.abuseWithOtherSignalCap : RISK_WEIGHTS.abuseConfidenceCap;
      if (confidence > 0) factors.push(factor("abuse_reputation", `${confidence}% AbuseIPDB confidence`, Math.min(cap, Math.round(confidence * multiplier)), "abuseipdb", abuse.evidenceId));
      if (reports > 0) factors.push(factor("abuse_report_volume", `${reports} AbuseIPDB reports`, Math.min(RISK_WEIGHTS.reportVolumeCap, Math.floor(reports / 50) * RISK_WEIGHTS.reportVolumePerFifty), "abuseipdb", abuse.evidenceId));
      threatProviders.add("abuseipdb");
      directSignalCount += 1;
    }
  }

  for (const provider of urlReputation.strongProviders || []) {
    const source = byProvider.get(provider);
    if (!source) continue;
    if (!directSignalCount) factors.push(factor("direct_reputation_base", "A provider returned a direct URL reputation match", RISK_WEIGHTS.virusTotalBase, provider, source.evidenceId));
    factors.push(factor("confirmed_url_reputation", `${provider} returned a direct URL threat match`, RISK_WEIGHTS.confirmedUrlMatch, provider, source.evidenceId));
    threatProviders.add(provider);
    directSignalCount += 1;
  }

  const independentProviderCount = threatProviders.size;
  if (independentProviderCount > 1) {
    factors.push(factor("independent_provider_corroboration", `${independentProviderCount} independent provider sources returned compatible threat evidence`, Math.min(RISK_WEIGHTS.independentProviderCap, (independentProviderCount - 1) * RISK_WEIGHTS.independentProviderCorroboration), [...threatProviders].join(", "), null));
  }

  const threatSources = [...threatProviders].map(provider => byProvider.get(provider)).filter(Boolean);
  for (const source of threatSources) {
    const contribution = freshnessContribution(source);
    factors.push(factor("evidence_freshness", `${source.provider} evidence freshness: ${source.quality?.freshness?.status || source.freshness || "unknown"}`, contribution, source.provider, source.evidenceId));
  }

  const conflictCount = Math.min(RISK_WEIGHTS.conflictCap / Math.abs(RISK_WEIGHTS.conflict), investigation?.conflicts?.length || 0);
  if (conflictCount) factors.push(factor("provider_signal_conflict", `${conflictCount} unresolved provider signal conflict(s)`, -conflictCount * Math.abs(RISK_WEIGHTS.conflict), "investigation", investigation?.investigationId || null));

  const hasThreatEvidence = directSignalCount > 0;
  const hasTorContext = investigation?.correlations?.some(item => item.type === "tor_infrastructure_context") === true;
  if (hasThreatEvidence && hasTorContext) factors.push(factor("infrastructure_context_priority", "Tor-exit infrastructure is investigative context, not proof of malicious activity", RISK_WEIGHTS.infrastructureContext, "infrastructure_correlation", null));

  let score = hasThreatEvidence ? factors.reduce((total, item) => total + item.contribution, 0) : null;
  if (score !== null) {
    const bounded = Math.max(0, Math.min(100, Math.round(score)));
    const current = factors.reduce((total, item) => total + item.contribution, 0);
    if (bounded !== current) factors.push(factor("score_bound_adjustment", "Clamp to the 0–100 range", bounded - current, "risk_engine", null));
    score = bounded;
  }

  // Confidence measures completeness and source quality separately from the
  // threat score. Missing environmental telemetry lowers overall confidence,
  // but never reduces the external threat score.
  const planned = Math.max(1, investigation?.coverage?.planned || investigation?.sources?.filter(source => !["skipped", "not_required"].includes(source.status)).length || 1);
  const meaningfulRatio = threatSources.length > 0 ? 1 : 0;
  const freshnessWeights = { recent: 1, fresh: 1, aging: 0.7, stale: 0.25, unknown: 0.45 };
  const averageFreshness = threatSources.length
    ? threatSources.reduce((total, source) => total + (freshnessWeights[source.quality?.freshness?.status || source.freshness] ?? freshnessWeights.unknown), 0) / threatSources.length
    : 0;
  const corroborationQuality = independentProviderCount >= 2 ? 1 : independentProviderCount === 1 ? 0.4 : 0;
  const conflictPenalty = Math.min(20, (investigation?.conflicts?.length || 0) * 8);
  const failurePenalty = Math.min(15, failed.length * 2.5);
  const targetQuality = investigation?.targetIdentity?.normalized ? 5 : 0;
  const environmentPenalty = environmentalRefs.length ? 0 : 10;
  const externalConfidence = Math.round(Math.max(0, Math.min(100, 15 + meaningfulRatio * 25 + averageFreshness * 20 + corroborationQuality * 20 + targetQuality - conflictPenalty - failurePenalty)));
  const confidenceScore = Math.max(0, Math.min(100, externalConfidence - environmentPenalty));
  const currentStatusConfidenceScore = currentStatusConfidence(threatSources, failed);
  const confidenceFactors = {
    meaningfulEvidence: Math.round(meaningfulRatio * 25),
    evidenceFreshness: Math.round(averageFreshness * 20),
    independentCorroboration: Math.round(corroborationQuality * 20),
    targetAttribution: targetQuality,
    conflictAdjustment: -conflictPenalty,
    providerFailureAdjustment: -failurePenalty,
    missingEnvironmentalTelemetry: -environmentPenalty,
  };

  const rationale = [];
  if (threatProviders.size) rationale.push(`${threatProviders.size} independent provider source(s) supplied direct threat reputation evidence; multiple engines within one provider count as one source.`);
  else rationale.push("No provider supplied a confirmed direct malicious or phishing match.");
  if (failed.length) rationale.push(`${failed.length} provider(s) failed or were unavailable; those results were not treated as benign.`);
  if (investigation?.conflicts?.length) rationale.push(`${investigation.conflicts.length} unresolved provider signal conflict(s) reduced confidence and risk.`);
  if (threatSources.some(source => (source.quality?.freshness?.status || source.freshness) === "stale")) rationale.push("Some threat evidence is stale historical intelligence and does not establish current malicious activity.");
  if (!environmentalRefs.length) rationale.push("Environmental risk remains unknown because no internal telemetry was supplied.");

  return {
    score,
    baseScore: factors.find(item => item.name === "direct_reputation_base")?.contribution || 0,
    factors,
    riskFactors: factors,
    finalScore: score,
    level: riskBand(score, independentProviderCount),
    externalThreat: riskBand(score, independentProviderCount),
    independentProviderCount,
    environmentalRisk: environmentalRefs.length ? "elevated" : "unknown",
    evidenceCoverage: sources.length ? (failed.length || successful.length < planned ? "partial" : sources.length >= 2 ? "broad" : "limited") : "none",
    rationale,
    confidenceScore,
    externalConfidenceScore: externalConfidence,
    confidenceFactors,
    scoreSemantics: "Bounded additive heuristic for external threat severity; it is not a probability of compromise or environmental impact.",
    confidenceSemantics: "Bounded evidence-quality heuristic using direct reputation evidence, freshness, independent-provider corroboration, target attribution, conflicts, and failed-source penalties; it is not a statistical probability and does not rise from query count alone.",
    currentStatusConfidenceSemantics: "Freshness and independent direct-reputation corroboration heuristic; it does not establish live activity or environmental impact.",
    calibratedProbability: false,
    confidenceLevel: confidenceBand(confidenceScore),
    externalConfidenceLevel: confidenceBand(externalConfidence),
    currentStatusConfidenceScore,
    currentStatusConfidenceLevel: currentStatusConfidenceScore === null ? "unknown" : confidenceBand(currentStatusConfidenceScore),
    environmentalConfidenceLevel: environmentalRefs.length ? "low" : "unknown",
    environmentalConfidenceScore: environmentalRefs.length ? Math.min(100, Math.round(25 + Math.min(60, environmentalRefs.length * 20))) : null,
  };
}

module.exports = { calculateRisk, RISK_WEIGHTS, riskBand, confidenceBand };
