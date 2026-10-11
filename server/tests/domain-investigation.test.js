const test = require('node:test');
const assert = require('node:assert/strict');
const { DomainInvestigation, CAPABILITIES, normalizeDomain, buildPlan, dependentTools, normalize } = require('../agent/DomainInvestigation');
const { resolveRequiredTools } = require('../agent/RequiredToolResolver');
const ToolRegistry = require('../agent/ToolRegistry');
const ToolPolicy = require('../agent/ToolPolicy');
const ToolValidator = require('../agent/ToolValidator');
const { buildSecurityReasoning, validateSecurityReasoning } = require('../agent/SecurityReasoning');
const SecurityReportGenerator = require('../reports/SecurityReportGenerator');

test('valid domain normalization and URL to domain normalization', () => {
  assert.equal(normalizeDomain('Example.COM'), 'example.com');
  assert.equal(normalizeDomain('https://Example.COM/path?q=1'), 'example.com');
  assert.equal(normalizeDomain('ftp://example.com'), null);
});

test('invalid domain rejection', () => {
  assert.equal(normalizeDomain('not-a-domain'), null);
  assert.equal(normalizeDomain('http://'), null);
});

test('domain investigation plan is dynamic and only includes registered tools', () => {
  const registry = new ToolRegistry();
  registry.register({ name: 'securitytrails_lookup', execute: async () => ({status:'success'}), targetTypes:['domain'], riskLevel:'read' });
  registry.register({ name: 'urlscan_lookup', execute: async () => ({status:'success'}), targetTypes:['domain'], riskLevel:'read' });
  const plan = buildPlan({domain:'example.com', toolRegistry:registry});
  assert.deepEqual(plan.tools, ['securitytrails_lookup', 'urlscan_lookup']);
  assert.equal(plan.type, 'domain');
  assert.ok(plan.objectives.includes('dns'));
});

test('capability model does not grant capabilities from user text', () => {
  assert.ok(CAPABILITIES.professional.includes('shodan'));
  const investigation = new DomainInvestigation();
  assert.deepEqual(investigation.resolveCapabilities({}), []);
  assert.deepEqual(investigation.resolveCapabilities({capabilities:['domain_check']}), ['domain_check']);
});

test('domain resolver classifies example.com as a domain investigation', () => {
  const result = resolveRequiredTools([{role:'user', content:'Investigate example.com'}]);
  assert.deepEqual(result.targets, [{type:'domain', value:'example.com', valid:true}]);
  assert.equal(result.requiredTools.length, 7);
  assert.ok(!result.requiredTools.includes('securitytrails_lookup'));
});

test('dependent IP tools are deduplicated', () => {
  const registry = new ToolRegistry();
  for (const name of ['ipinfo_ip_lookup','shodan_ip_lookup','censys_ip_lookup']) registry.register({name,execute:async()=>({status:'success'}),riskLevel:'read'});
  const evidence = [
    {ok:true,toolName:'urlscan_lookup',output:{status:'success',findings:{ip:'93.184.216.34'}}},
    {ok:true,toolName:'securitytrails_lookup',output:{status:'success',findings:{records:['93.184.216.34']}}},
  ];
  const plan = dependentTools({domain:'example.com',rawToolEvidence:evidence,toolRegistry:registry});
  assert.equal(plan.ips.length, 1);
  assert.equal(plan.tools.length, 3);
});

test('tool failure becomes status and does not fabricate observations', () => {
  const data = normalize({domain:'example.com',rawToolEvidence:[
    {ok:false,toolName:'securitytrails_lookup',error:{code:'AUTHORIZATION_FAILED',message:'API key unavailable'}},
    {ok:true,toolName:'urlscan_lookup',output:{status:'success',findings:{results:[]}}},
  ]});
  assert.ok(data.toolStatus.some(x => x.tool === 'securitytrails_lookup' && x.status === 'AUTHORIZATION_FAILED'));
  assert.equal(data.threatIntelligence.length, 0);
  assert.ok(data.limitations.some(x => /securitytrails/i.test(x)));
});

test('conflicting evidence is preserved as source evidence rather than resolved by invention', () => {
  const data = normalize({domain:'example.com',rawToolEvidence:[
    {ok:true,toolName:'urlscan_lookup',output:{status:'success',findings:{ip:'93.184.216.34',httpSecurity:'present'}}},
    {ok:true,toolName:'mozilla_observatory_scan',output:{status:'success',findings:{httpSecurity:'different'}}},
  ]});
  assert.equal(data.httpSecurity.length, 2);
  assert.equal(data.observations.some(x => /contradiction|conflict/i.test(x.statement)), false);
});

test('security reasoning schema is evidence-first', () => {
  const investigation = normalize({domain:'example.com',rawToolEvidence:[]});
  const reasoning = buildSecurityReasoning({investigation,rawToolEvidence:[]});
  assert.equal(validateSecurityReasoning(reasoning), true);
  assert.ok(reasoning.unknowns.length > 0);
  assert.equal(reasoning.hypotheses.length, 0);
});

test('existing security report generator returns a PDF for a domain investigation', async () => {
  const pdf = await new SecurityReportGenerator().generateSecurityReport({
    investigation: { target:'example.com', targetType:'domain', sources:[], findings:[], correlations:[], limitations:['No provider evidence'] },
  });
  assert.ok(Buffer.isBuffer(pdf));
  assert.equal(pdf.subarray(0,5).toString(), '%PDF-');
});

test('unauthorized tool is blocked by existing policy gate', () => {
  const registry = new ToolRegistry();
  registry.register({name:'securitytrails_lookup',execute:async()=>({status:'success'}),riskLevel:'read',requiredCapability:'securitytrails'});
  const tool = registry.get('securitytrails_lookup');
  const policy = new ToolPolicy({allowedRiskLevels:['read']});
  const denied = policy.check({tool,userContext:{capabilities:['domain_check']},input:{domain:'example.com'}});
  assert.equal(denied.allowed,false);
  const validator = new ToolValidator();
  assert.equal(validator.validate(tool,{domain:'example.com'}).valid,false);
});
