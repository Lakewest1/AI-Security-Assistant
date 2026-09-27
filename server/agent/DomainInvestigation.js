/**
 * DomainInvestigation
 *
 * Domain-specific planning and evidence normalization. It deliberately does
 * not execute tools; AgentLoop remains the single execution controller.
 */
const net = require('net');

const CAPABILITIES = Object.freeze({
  consumer: ['url_reputation', 'email_analysis', 'domain_check'],
  developer: ['url_reputation', 'dependency_scan', 'secret_scan', 'iac_scan'],
  professional: ['virustotal', 'shodan', 'censys', 'ipinfo', 'securitytrails'],
  cloud: ['aws_read', 'azure_read'],
  soc: ['cloudtrail', 'sentinel', 'defender', 'mitre'],
});

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

const DOMAIN_TOOLS = [
  'securitytrails_lookup',
  'viewdns_lookup',
  'urlscan_lookup',
  'mozilla_observatory_scan',
];

const IP_TOOLS = [
  'virustotal_ip_lookup',
  'abuseipdb_ip_lookup',
  'ipinfo_ip_lookup',
  'shodan_ip_lookup',
  'censys_ip_lookup',
];

function normalizeDomain(value) {
  if (typeof value !== 'string') return null;
  let raw = value.trim();
  if (!raw) return null;

  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
      const parsed = new URL(raw);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      raw = parsed.hostname;
    } else {
      raw = raw.split('/')[0].split('?')[0].split('#')[0];
    }
  } catch {
    return null;
  }

  raw = raw.replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!DOMAIN_RE.test(raw)) return null;
  if (net.isIP(raw)) return null;
  return raw;
}

function validIPv4(value) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value))) return false;
  return String(value).split('.').every((x) => Number(x) >= 0 && Number(x) <= 255);
}

function collectIPs(value, set = new Set(), depth = 0) {
  if (depth > 6 || value == null) return set;
  if (typeof value === 'string') {
    for (const candidate of value.match(IPV4_RE) || []) if (validIPv4(candidate)) set.add(candidate);
    return set;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 100)) collectIPs(item, set, depth + 1);
    return set;
  }
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value).slice(0, 200)) {
      if (/^(api[-_]?key|token|secret|authorization|password|cookie)$/i.test(key)) continue;
      collectIPs(child, set, depth + 1);
    }
  }
  return set;
}

function sourceProvider(toolName) {
  return {
    securitytrails_lookup: 'securitytrails', viewdns_lookup: 'viewdns', urlscan_lookup: 'urlscan',
    mozilla_observatory_scan: 'mozilla_observatory', virustotal_ip_lookup: 'virustotal',
    abuseipdb_ip_lookup: 'abuseipdb', ipinfo_ip_lookup: 'ipinfo', shodan_ip_lookup: 'shodan',
    censys_ip_lookup: 'censys',
  }[toolName] || toolName;
}

function successfulEvidence(rawToolEvidence) {
  return (Array.isArray(rawToolEvidence) ? rawToolEvidence : []).filter((e) => e?.ok === true && e?.output);
}

function evidenceRef(entry, field, value) {
  return { source: sourceProvider(entry.toolName), tool: entry.toolName, field, value };
}

function flattenProviderFindings(entry) {
  const output = entry?.output || {};
  if (output.findings && typeof output.findings === 'object') return output.findings;
  if (output.data && typeof output.data === 'object') return output.data;
  return output;
}

function buildPlan({ domain, toolRegistry, capabilities = [] } = {}) {
  const registered = new Set((toolRegistry?.list?.() || []).map((t) => t.name));
  const permitted = new Set(Array.isArray(capabilities) ? capabilities : []);
  const initial = DOMAIN_TOOLS.filter((name) => registered.has(name));

  // Domain-level public checks remain available to existing users. Capability
  // restrictions are enforced by ToolPolicy when a capability context exists;
  // this resolver never grants capabilities from the user's wording.
  const requiredCapabilities = initial.map((name) => name === 'securitytrails_lookup' ? 'securitytrails' : name === 'urlscan_lookup' ? 'url_reputation' : 'domain_check');
  return {
    type: 'domain',
    target: { type: 'domain', value: domain },
    objectives: ['dns', 'infrastructure', 'certificates', 'http_security', 'threat_intelligence', 'exposed_services'],
    tools: initial,
    requiredCapabilities,
    capabilityContextProvided: permitted.size > 0,
    executionMode: 'controller',
    concurrency: 'parallel',
    failurePolicy: 'all-settled',
  };
}

function dependentTools({ domain, rawToolEvidence = [], toolRegistry, capabilities = [] } = {}) {
  const registered = new Set((toolRegistry?.list?.() || []).map((t) => t.name));
  const ips = [...collectIPs(successfulEvidence(rawToolEvidence).map(flattenProviderFindings))].slice(0, 2);
  const available = IP_TOOLS.filter((name) => registered.has(name));
  const tools = [];
  const argumentsByTool = {};
  for (const ip of ips) {
    for (const name of available) {
      const fingerprintKey = `${name}:${ip}`;
      if (tools.some((x) => x.fingerprintKey === fingerprintKey)) continue;
      tools.push({ name, ip, fingerprintKey });
      argumentsByTool[`${name}:${ip}`] = { ip };
    }
  }
  return { domain, ips, tools, argumentsByTool, capabilities: Array.isArray(capabilities) ? capabilities : [] };
}

function normalize({ domain, rawToolEvidence = [], baseInvestigation = null } = {}) {
  const evidence = successfulEvidence(rawToolEvidence);
  const sections = { dns: [], infrastructure: [], certificates: [], httpSecurity: [], threatIntelligence: [], exposedServices: [] };
  const observations = [];
  const recommendations = [];
  const evidenceRefs = [];

  for (const entry of evidence) {
    const findings = flattenProviderFindings(entry);
    const provider = sourceProvider(entry.toolName);
    const refBase = evidenceRef(entry, 'provider', provider);
    evidenceRefs.push(refBase);

    if (['securitytrails_lookup', 'viewdns_lookup'].includes(entry.toolName)) sections.dns.push({ provider, findings });
    if (['securitytrails_lookup', 'ipinfo_ip_lookup', 'shodan_ip_lookup', 'censys_ip_lookup'].includes(entry.toolName)) sections.infrastructure.push({ provider, findings });
    if (entry.toolName === 'censys_ip_lookup') {
      const services = findings.services || [];
      for (const service of services) if (service?.certificate || service?.tls) sections.certificates.push({ provider, certificate: service.certificate || service.tls, evidence: evidenceRef(entry, 'services', service) });
      if (services.length) sections.exposedServices.push({ provider, services });
    }
    if (['mozilla_observatory_scan', 'urlscan_lookup'].includes(entry.toolName)) sections.httpSecurity.push({ provider, findings });
    if (['virustotal_ip_lookup', 'abuseipdb_ip_lookup'].includes(entry.toolName)) sections.threatIntelligence.push({ provider, findings });
    if (entry.toolName === 'shodan_ip_lookup') sections.exposedServices.push({ provider, services: findings.services || findings.ports || findings });
  }

  const addObservation = (statement, type, refs, confidence = 0.8) => {
    observations.push({ statement, type, confidence, evidence: refs });
  };

  if (sections.httpSecurity.length) addObservation('HTTP security posture evidence was returned by the available web-security providers.', 'FACT', sections.httpSecurity.map((x) => ({ source: x.provider })));
  if (sections.threatIntelligence.length) addObservation('Threat-intelligence evidence was returned for one or more discovered IP addresses.', 'FACT', sections.threatIntelligence.map((x) => ({ source: x.provider })));
  if (sections.exposedServices.length) addObservation('One or more providers returned externally observable service or port data for discovered infrastructure.', 'FACT', sections.exposedServices.map((x) => ({ source: x.provider })));
  if (!sections.dns.length) recommendations.push('Obtain authoritative DNS and historical DNS evidence before drawing infrastructure conclusions.');
  if (sections.httpSecurity.length) recommendations.push('Review returned HTTP security-header and web-configuration observations against the organization\'s baseline.');
  if (sections.exposedServices.length) recommendations.push('Validate exposed services against the intended public attack surface and remove unnecessary exposure through the normal change process.');
  if (sections.threatIntelligence.length) recommendations.push('Correlate any elevated IP reputation signals with internal DNS, proxy, firewall, EDR, or SIEM telemetry before taking containment action.');
  if (!recommendations.length) recommendations.push('Collect additional approved security evidence before making a material risk decision.');

  const result = {
    investigationType: 'domain',
    target: { type: 'domain', value: domain },
    collectedAt: new Date().toISOString(),
    dns: sections.dns,
    infrastructure: sections.infrastructure,
    certificates: sections.certificates,
    httpSecurity: sections.httpSecurity,
    threatIntelligence: sections.threatIntelligence,
    exposedServices: sections.exposedServices,
    observations,
    recommendedActions: recommendations,
    evidence: evidenceRefs,
    toolStatus: (Array.isArray(rawToolEvidence) ? rawToolEvidence : []).map((e) => ({ tool: e.toolName, status: e.ok ? (e.output?.status || 'success') : (e.error?.code || 'error'), reason: e.ok ? (e.output?.message || null) : (e.error?.message || null) })),
    confidence: { level: observations.length ? 'moderate' : 'low', rationale: observations.length ? 'Based on returned provider evidence; environmental impact remains unestablished without internal telemetry.' : 'Insufficient successful provider evidence.' },
    limitations: [],
  };

  for (const status of result.toolStatus) if (!['success', 'partial'].includes(String(status.status).toLowerCase())) result.limitations.push(`${status.tool} was ${status.status}${status.reason ? `: ${status.reason}` : ''}.`);
  if (!result.infrastructure.length) result.limitations.push('No discovered infrastructure evidence was returned by the available providers.');
  if (!result.threatIntelligence.length) result.limitations.push('No IP threat-intelligence evidence was available for this domain.');
  if (baseInvestigation?.risk) result.risk = baseInvestigation.risk;
  return result;
}

class DomainInvestigation {
  constructor({ toolRegistry, toolValidator, toolPolicy, auditLogger } = {}) {
    this.toolRegistry = toolRegistry;
    this.toolValidator = toolValidator;
    this.toolPolicy = toolPolicy;
    this.auditLogger = auditLogger;
  }
  normalizeTarget(value) { return normalizeDomain(value); }
  createPlan(args) { return buildPlan(args); }
  resolveCapabilities(userContext = {}) { return Array.isArray(userContext.capabilities) ? [...new Set(userContext.capabilities)] : []; }
  getDependentTools(args) { return dependentTools(args); }
  normalize(args) { return normalize(args); }
}

module.exports = { DomainInvestigation, CAPABILITIES, normalizeDomain, validIPv4, collectIPs, buildPlan, dependentTools, normalize };
