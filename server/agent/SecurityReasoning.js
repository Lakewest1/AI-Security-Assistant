/** Evidence-first structured reasoning summary. No private chain-of-thought. */
function buildSecurityReasoning({ investigation, rawToolEvidence = [] } = {}) {
  const evidence = (Array.isArray(rawToolEvidence) ? rawToolEvidence : []).filter(Boolean);
  const successful = evidence.filter((e) => e.ok === true && e.output);
  const failed = evidence.filter((e) => e.ok !== true);
  const keyFindings = Array.isArray(investigation?.observations) ? investigation.observations.map((o) => ({ ...o })) : [];
  const unknowns = [];
  if (!successful.length) unknowns.push('No successful provider evidence was returned.');
  if (failed.length) unknowns.push('One or more requested sources were unavailable or failed; absence of their evidence is not evidence of absence.');
  unknowns.push('Internal telemetry, asset criticality, business impact, and confirmed exploitation were not established by passive external intelligence alone.');

  const hypotheses = [];
  if (investigation?.threatIntelligence?.length) hypotheses.push({
    statement: 'Some discovered infrastructure may warrant additional review if it is associated with the organization’s assets or traffic.',
    supportingEvidence: investigation.threatIntelligence.map((x) => ({ source: x.provider })),
    contradictingEvidence: [], confidence: 0.65,
  });

  return {
    mission: `Assess the observable security posture and external exposure of ${investigation?.target?.value || 'the supplied domain'}.`,
    keyFindings,
    evidence: evidence.map((e) => ({ tool: e.toolName, status: e.ok ? 'success' : 'error', reference: e.callId || null })),
    hypotheses,
    riskFactors: keyFindings.map((f) => ({ statement: f.statement, confidence: f.confidence })),
    contradictions: [],
    unknowns,
    confidence: investigation?.confidence || { level: 'low', rationale: 'Insufficient evidence.' },
    priorityActions: investigation?.recommendedActions || [],
    nextInvestigativeActions: investigation?.recommendedActions || [],
  };
}

function validateSecurityReasoning(value) {
  if (!value || typeof value !== 'object') return false;
  return typeof value.mission === 'string' && Array.isArray(value.keyFindings) && Array.isArray(value.evidence) && Array.isArray(value.hypotheses) && Array.isArray(value.unknowns) && Array.isArray(value.priorityActions);
}

module.exports = { buildSecurityReasoning, validateSecurityReasoning };
