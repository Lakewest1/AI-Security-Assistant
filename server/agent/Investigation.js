/**
 * Canonical first-class Investigation object.
 *
 * Design goals:
 * - provider responses remain evidence, never conclusions
 * - empty/unavailable sources are not treated as positive evidence
 * - external threat and environmental impact remain separate dimensions
 * - every derived finding/correlation carries source traceability
 * - qualitative evidence quality is based on characteristics, not provider count
 */
function nowIso(){return new Date().toISOString();}

const TOOL_PROVIDERS={
  virustotal_ip_lookup:"virustotal", abuseipdb_ip_lookup:"abuseipdb",
  urlscan_lookup:"urlscan", shodan_ip_lookup:"shodan", ipinfo_ip_lookup:"ipinfo",
  censys_ip_lookup:"censys", securitytrails_lookup:"securitytrails",
  mozilla_observatory_scan:"mozilla_observatory", viewdns_lookup:"viewdns", hibp_lookup:"hibp"
};
const PROVIDER_LABELS={
  virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",urlscan:"URLScan",shodan:"Shodan",ipinfo:"IPinfo",
  censys:"Censys",securitytrails:"SecurityTrails",mozilla_observatory:"Mozilla Observatory",
  viewdns:"ViewDNS",hibp:"Have I Been Pwned"
};
const STATUS_SET=new Set(["success","partial","not_configured","unauthorized","rate_limited","timeout","unavailable","not_found","empty","error","skipped","not_required"]);
const REPUTATION_PROVIDERS=new Set(["virustotal","abuseipdb"]);
const INFRA_PROVIDERS=new Set(["shodan","censys","securitytrails","viewdns","urlscan"]);

function createInvestigation({target,targetType="ip",startedAt=nowIso()}={}) {
  return {
    target:target||null,targetType,startedAt,completedAt:null,
    status:"running",
    sources:[],findings:[],correlations:[],conflicts:[],
    confidence:{level:"low",rationale:[],externalIntelligence:"low",environmentalAssessment:"low"},
    risk:{level:"unknown",overallAssessment:"insufficient_evidence",rationale:[],externalThreat:"unknown",environmentalRisk:"unknown",evidenceCoverage:"none"},
    mitre:[],limitations:[]
  };
}
function providerFromTool(toolName){return TOOL_PROVIDERS[toolName]||toolName;}
function providerLabel(provider){return PROVIDER_LABELS[provider]||provider;}
function statusFromError(error){
  const c=String(error?.code||error?.category||"").toUpperCase();
  if(c.includes("TIMEOUT"))return "timeout";
  if(c.includes("RATE_LIMIT"))return "rate_limited";
  if(c.includes("AUTH")||c.includes("FORBIDDEN"))return "unauthorized";
  if(c.includes("NOT_FOUND"))return "not_found";
  if(c.includes("UNAVAILABLE")||c.includes("UPSTREAM")||c.includes("NETWORK"))return "unavailable";
  return "error";
}
function sourceStatus(evidence){
  if(!evidence)return "error";
  if(!evidence.ok)return statusFromError(evidence.error);
  let status=String(evidence.output?.status||"success").toLowerCase();
  if(status==="unauthorized" && /not configured|not configured|missing|credentials? are not configured|api key is not configured|token is not configured/i.test(String(evidence.output?.message||evidence.error?.message||""))) status="not_configured";
  return STATUS_SET.has(status)?status:"error";
}
function sourceFindings(output){
  if(!output||typeof output!=="object")return {};
  if(output.findings&&typeof output.findings==="object")return output.findings;
  const ignored=new Set(["ok","success","provider","status","message","collectedAt","evidence","limitations"]);
  return Object.fromEntries(Object.entries(output).filter(([k,v])=>!ignored.has(k)&&v!==undefined&&v!==null&&v!==""));
}
function isMeaningfulValue(v){
  if(v===undefined||v===null||v==="")return false;
  if(Array.isArray(v))return v.length>0;
  if(typeof v==="object")return Object.keys(v).length>0;
  return true;
}
function meaningfulFields(source){
  const f=source.findings||{};
  return Object.entries(f).filter(([,v])=>isMeaningfulValue(v));
}
function hasMeaningfulInfrastructure(source){
  if(!source || !INFRA_PROVIDERS.has(source.provider) || !["success","partial"].includes(source.status)) return false;
  const f=source.findings||{};
  if(source.provider==="viewdns") return Number(f.reverseIpDomainCount)>0 || Number(f.whoisResultCount)>0 || isMeaningfulValue(f.reverseIpDomains) || isMeaningfulValue(f.reverseWhoisMatches) || isMeaningfulValue(f.whoisRecords) || isMeaningfulValue(f.owner);
  if(source.provider==="shodan") return isMeaningfulValue(f.ports)||isMeaningfulValue(f.services)||isMeaningfulValue(f.hostnames)||isMeaningfulValue(f.organization)||isMeaningfulValue(f.asn)||isMeaningfulValue(f.country);
  if(source.provider==="ipinfo") return isMeaningfulValue(f.hostname)||isMeaningfulValue(f.organization)||isMeaningfulValue(f.asn)||isMeaningfulValue(f.privacy);
  if(source.provider==="censys") return isMeaningfulValue(f.services)||isMeaningfulValue(f.autonomousSystem)||isMeaningfulValue(f.location)||isMeaningfulValue(f.lastUpdated);
  if(source.provider==="securitytrails") return meaningfulFields(source).length>0;
  if(source.provider==="urlscan") return meaningfulFields(source).length>0;
  return meaningfulFields(source).length>0;
}
function hasMeaningfulEvidence(source){
  if(!source || !["success","partial"].includes(source.status)) return false;
  if(source.provider==="viewdns") return hasMeaningfulInfrastructure(source);
  if(["shodan","censys","securitytrails","urlscan"].includes(source.provider)) return hasMeaningfulInfrastructure(source);
  return meaningfulFields(source).length>0;
}
function evidenceStrength({direct=false,corroborated=false,contextual=false,inconclusive=false}={}){
  if(inconclusive)return "inconclusive";
  if(corroborated)return "corroborated";
  if(direct)return "direct";
  if(contextual)return "contextual";
  return "inconclusive";
}
function freshnessInfo(source){
  const f=source.findings||{};
  const raw=f.lastReportedAt||f.lastAnalysisDate||f.providerObservedAt||f.lastUpdated||f.scanDate||null;
  if(!raw)return {status:"unknown",observedAt:null};
  const d=new Date(typeof raw==="number" ? raw*1000 : raw);
  if(Number.isNaN(d.getTime()))return {status:"unknown",observedAt:String(raw)};
  const ageMs=Math.max(0,Date.now()-d.getTime());
  const ageDays=ageMs/86400000;
  return {status:ageDays<=7?"fresh":ageDays<=30?"recent":"stale",observedAt:d.toISOString(),ageDays:Number(ageDays.toFixed(1))};
}
function providerQuality(source){
  const meaningful=hasMeaningfulEvidence(source);
  const freshness=freshnessInfo(source);
  const directness=REPUTATION_PROVIDERS.has(source.provider)?"reputation":hasMeaningfulInfrastructure(source)?"observational/contextual":"contextual";
  let score=0;
  if(source.status==="success")score+=0.35; else if(source.status==="partial")score+=0.20;
  if(meaningful)score+=0.25;
  if(freshness.status==="fresh")score+=0.20; else if(freshness.status==="recent")score+=0.12;
  if(REPUTATION_PROVIDERS.has(source.provider))score+=0.10;
  if(hasMeaningfulInfrastructure(source))score+=0.10;
  return {score:Number(Math.min(score,1).toFixed(2)),meaningful,freshness,directness};
}
function sourceTrace(source,field,value){
  return {provider:source.provider,tool:source.tool,field,value,collectedAt:source.collectedAt,providerObservedAt:source.quality?.freshness?.observedAt||null};
}
function addFinding(inv,type,description,sourceRefs=[],severity="informational",evidenceType="context",strength="contextual",extra={}){
  inv.findings.push({type,description,providers:[...new Set(sourceRefs.map(r=>typeof r==="string"?r:r.provider))],severity,evidenceType,strength,...extra,evidence:sourceRefs.map(r=>typeof r==="string"?{provider:r}:r)});
}
function addCorrelation(inv,type,description,sourceRefs,strength="corroborated",evidenceType="correlation",extra={}){
  inv.correlations.push({type,description,providers:[...new Set(sourceRefs.map(r=>typeof r==="string"?r:r.provider))],confidence:strength,evidenceType,strength,...extra,evidence:sourceRefs.map(r=>typeof r==="string"?{provider:r}:r)});
}
function dedupePush(list,values){for(const v of values||[])if(v&&!list.includes(v))list.push(v);}
function reputationAssessment(inv,vt,abuse){
  const vtM=vt?Number(vt.findings.malicious):NaN, vtS=vt?Number(vt.findings.suspicious):NaN;
  const abScore=abuse?Number(abuse.findings.abuseConfidenceScore):NaN;
  const vtElevated=Number.isFinite(vtM)&&vtM>0 || Number.isFinite(vtS)&&vtS>0;
  const abElevated=Number.isFinite(abScore)&&abScore>0;
  if(vtElevated) addFinding(inv,"reputation_signal",`VirusTotal reports ${Number.isFinite(vtM)?vtM:"an unspecified number of"} malicious and ${Number.isFinite(vtS)?vtS:"an unspecified number of"} suspicious detections.`,[sourceTrace(vt,"malicious",vt.findings.malicious),sourceTrace(vt,"suspicious",vt.findings.suspicious)],"elevated","reputation",evidenceStrength({direct:true}));
  else if(vt && (Number.isFinite(vtM)||Number.isFinite(vtS))) addFinding(inv,"reputation_observation","VirusTotal reports no malicious or suspicious detections in the supplied result.",[sourceTrace(vt,"malicious",vt.findings.malicious),sourceTrace(vt,"suspicious",vt.findings.suspicious)],"informational","reputation",evidenceStrength({inconclusive:true}));
  if(abElevated) addFinding(inv,"abuse_history",`AbuseIPDB reports an abuse confidence score of ${abScore}${Number.isFinite(Number(abuse.findings.totalReports))?` with ${Number(abuse.findings.totalReports)} total reports.`:"."}`,[sourceTrace(abuse,"abuseConfidenceScore",abuse.findings.abuseConfidenceScore),...(abuse.findings.totalReports!==undefined?[sourceTrace(abuse,"totalReports",abuse.findings.totalReports)]:[])],"elevated","reputation",evidenceStrength({direct:true}));
  else if(abuse && Number.isFinite(abScore)) addFinding(inv,"reputation_observation",`AbuseIPDB reports an abuse confidence score of ${abScore}; no elevated abuse-confidence signal was observed in the supplied result.`,[sourceTrace(abuse,"abuseConfidenceScore",abScore)],"informational","reputation",evidenceStrength({inconclusive:true}));
  if(vtElevated&&abElevated) addCorrelation(inv,"reputation_corroboration","Independent reputation providers report elevated threat-related indicators.",[sourceTrace(vt,"malicious",vt.findings.malicious),sourceTrace(abuse,"abuseConfidenceScore",abuse.findings.abuseConfidenceScore)],"corroborated","reputation");
  return {vtElevated,abElevated,elevated:vtElevated||abElevated,both:vtElevated&&abElevated};
}
function identityCorrelation(inv,sources){
  const hostnameSources=[];
  for(const s of sources){
    const h=s.findings?.hostname || (Array.isArray(s.findings?.hostnames)?s.findings.hostnames[0]:null);
    if(h)hostnameSources.push(sourceTrace(s,"hostname",h));
  }
  const normalized=new Map();
  for(const ref of hostnameSources){const h=String(ref.value).toLowerCase();if(!normalized.has(h))normalized.set(h,[]);normalized.get(h).push(ref);}
  for(const [hostname,refs] of normalized){if(refs.length>=2)addCorrelation(inv,"identity_corroboration",`Multiple independent sources associate the target with the hostname ${hostname}.`,refs,"corroborated","identity");}
  const torRefs=[];
  for(const s of sources){for(const [field,value] of Object.entries(s.findings||{})){if(typeof value==="string" && /tor[- ]?exit/i.test(value))torRefs.push(sourceTrace(s,field,value));}}
  if(torRefs.length>=2)addCorrelation(inv,"tor_infrastructure_context","Multiple independent sources associate the target with Tor-exit infrastructure. This is infrastructure context and does not by itself establish malicious activity.",torRefs,"corroborated","infrastructure");
  return {hostnameSources,torRefs};
}
function infrastructureCorrelation(inv,sources){
  const meaningful=sources.filter(hasMeaningfulInfrastructure);
  for(const s of meaningful){
    if(s.provider==="shodan"){
      if(isMeaningfulValue(s.findings.ports))addFinding(inv,"service_exposure",`Shodan observed ${Array.isArray(s.findings.ports)?s.findings.ports.length:"one or more"} exposed port observations for the target.`,[sourceTrace(s,"ports",s.findings.ports)],"informational","exposure",evidenceStrength({direct:true}));
      if(isMeaningfulValue(s.findings.services))addFinding(inv,"service_observation","Shodan returned service/banner observations for the target.",[sourceTrace(s,"services",s.findings.services)],"informational","network",evidenceStrength({direct:true}));
    }
  }
  if(meaningful.length>=2)addCorrelation(inv,"infrastructure_corroboration","Multiple providers returned meaningful infrastructure observations for the target.",meaningful.map(s=>({provider:s.provider,tool:s.tool,field:"meaningfulFindings",value:Object.keys(s.findings||{}),collectedAt:s.collectedAt})),"corroborated","infrastructure");
}
function detectEnvironmentalEvidence(sources){
  const refs=[];
  for(const s of sources){for(const [field,value] of Object.entries(s.findings||{})){if(/environment|firewall|proxy|dns|edr|endpoint|authentication|auth|connection|networkFlow|packet|c2|malware/i.test(field)){if(isMeaningfulValue(value))refs.push(sourceTrace(s,field,value));}}}
  return refs;
}
function buildConfidence(inv,{successful,failed,environmentalRefs,reputation}){
  const meaningful=successful.filter(s=>s.quality?.meaningful);
  const independent=new Set(inv.findings.flatMap(f=>f.providers||[]));
  const conflicts=inv.conflicts.length;
  const external = reputation.both && conflicts===0 ? "high" : reputation.elevated ? (conflicts?"moderate":"high") : meaningful.length>=2 ? "moderate" : meaningful.length===1 ? "low" : "low";
  const environmental=environmentalRefs.length ? (environmentalRefs.length>=2?"high":"moderate") : "low";
  let level="low";
  if(external==="high" && environmental==="low")level="moderate";
  else if(external==="high" && environmental!=="low")level="high";
  else if(external==="moderate" && meaningful.length>=2)level="moderate";
  inv.confidence={level,externalIntelligence:external,environmentalAssessment:environmental,rationale:[
    `${meaningful.length} source(s) returned meaningful evidence across ${independent.size} provider(s).`,
    `External-intelligence confidence reflects evidence quality, freshness, independence and consistency rather than provider count.`,
    environmentalRefs.length?"Direct environmental telemetry was present in the supplied evidence.":"No direct environmental telemetry was present in the supplied evidence.",
    ...(conflicts?["One or more same-dimension conflicts remain unresolved."]:[])
  ]};
}
function buildInvestigationFromEvidence({target,targetType="ip",rawToolEvidence=[],startedAt,completed=true,expectedTools=[]}={}){
  const inv=createInvestigation({target,targetType,startedAt});
  const evidence=Array.isArray(rawToolEvidence)?rawToolEvidence:[];
  const latest=new Map();
  for(const item of evidence){if(item?.toolName)latest.set(providerFromTool(item.toolName),item);}
  for(const tool of expectedTools||[]) if(!latest.has(providerFromTool(tool))) latest.set(providerFromTool(tool),{toolName:tool,ok:true,output:{status:"skipped",message:"Required provider was not attempted."},startedAt:null,completedAt:null});
  for(const item of latest.values()){
    const source=normalizeSource(item);
    source.quality=providerQuality(source);
    inv.sources.push(source);
  }
  const successful=inv.sources.filter(s=>["success","partial"].includes(s.status));
  const failed=inv.sources.filter(s=>!["success","partial","skipped","not_required"].includes(s.status));
  const vt=inv.sources.find(s=>s.provider==="virustotal"&&["success","partial"].includes(s.status));
  const abuse=inv.sources.find(s=>s.provider==="abuseipdb"&&["success","partial"].includes(s.status));
  const reputation=reputationAssessment(inv,vt,abuse);
  infrastructureCorrelation(inv,inv.sources);
  identityCorrelation(inv,inv.sources);

  const environmentalRefs=detectEnvironmentalEvidence(inv.sources);
  const meaningful=successful.filter(s=>s.quality?.meaningful);
  const coverage=successful.length===0?"none":failed.length>0?"partial":"broad";
  const externalThreat=reputation.elevated?"elevated":meaningful.length?"unknown":"unknown";
  const environmentalRisk=environmentalRefs.length?"elevated":"unknown";
  let overallAssessment="insufficient_evidence";
  if(environmentalRefs.length){overallAssessment=reputation.elevated?"elevated_concern":"suspicious";}
  else if(reputation.elevated)overallAssessment="elevated_concern";
  inv.risk={
    level:reputation.elevated?"medium":environmentalRefs.length?"medium":"unknown",
    overallAssessment,
    externalThreat,
    environmentalRisk,
    evidenceCoverage:coverage,
    rationale:reputation.elevated?[
      "Multiple independent reputation signals are elevated in the supplied external intelligence.",
      "External reputation is kept separate from environmental impact.",
      ...(environmentalRefs.length?["Direct environmental evidence was also present in the supplied data."]:["No internal/environmental telemetry was provided to establish current malicious activity or compromise."])
    ]:[meaningful.length?"No elevated external reputation conclusion was established from the available evidence; absence of elevated reputation does not prove benignness.":"Relevant external security intelligence was unavailable."]
  };
  if(reputation.both && vt?.findings?.lastAnalysisDate) inv.findings.find(f=>f.type==="reputation_signal")?.evidence.push(sourceTrace(vt,"lastAnalysisDate",vt.findings.lastAnalysisDate));

  // Same-dimension conflict detection only. Different measurements are not conflicts.
  if(vt&&abuse && reputation.vtElevated!==reputation.abElevated){
    inv.conflicts.push({type:"reputation_signal_difference",providers:["virustotal","abuseipdb"],description:"The reputation providers differ in whether their supplied results contain an elevated reputation signal; they use different datasets and scoring methods, so this is treated as a signal difference rather than a direct contradiction.",resolution:"unresolved",significance:"moderate",evidenceType:"reputation"});
  }
  for(const source of failed)dedupePush(inv.limitations,[`${providerLabel(source.provider)} was ${source.status} during this investigation.`]);
  for(const source of inv.sources.filter(s=>s.status==="skipped"))dedupePush(inv.limitations,[`${providerLabel(source.provider)} was not attempted; no provider evidence is available from this source.`]);
  if(!environmentalRefs.length)dedupePush(inv.limitations,["No internal telemetry was provided; environmental impact cannot be determined from external intelligence alone.","No firewall, proxy, DNS, endpoint, identity, packet-capture, or historical activity telemetry was provided."]);
  if(successful.some(s=>s.findings?.lastAnalysisDate||s.findings?.lastReportedAt||s.findings?.lastUpdated))dedupePush(inv.limitations,["Provider observations have provider-specific timestamps; older reputation or infrastructure data may not reflect the target's current state."]);
  if(inv.sources.some(s=>s.status!=="success"&&s.status!=="skipped"&&s.status!=="not_required"))dedupePush(inv.limitations,["Investigation completed with partial source availability."]);
  if(inv.sources.some(s=>["success","partial"].includes(s.status)))dedupePush(inv.limitations,["No behavioral telemetry was available to support a confident MITRE ATT&CK mapping from reputation, infrastructure, posture, or breach intelligence alone."]);
  buildConfidence(inv,{successful,failed,environmentalRefs,reputation});
  inv.mitre=[];
  inv.status=completed?"completed":"collecting";
  inv.completedAt=completed?nowIso():null;
  inv.limitations=[...new Set(inv.limitations)];
  return inv;
}
function normalizeSource(evidence){
  const provider=providerFromTool(evidence?.toolName), output=evidence?.output||{};
  let status=sourceStatus(evidence);
  const source={provider,tool:evidence?.toolName,status,collectedAt:output.collectedAt||evidence?.completedAt||evidence?.startedAt||nowIso(),findings:{},confidence:"low",limitations:[],errors:[]};
  if(status==="success"||status==="partial"||status==="empty"){
    source.findings=sourceFindings(output);
    if(provider==="viewdns" && status==="success" && !hasMeaningfulInfrastructure(source)) status="empty";
    source.status=status;
    const qualityHint=hasMeaningfulEvidence(source)?"moderate":"low";
    source.confidence=qualityHint;
    if(REPUTATION_PROVIDERS.has(provider))source.limitations.push("External reputation intelligence does not establish compromise in the user's environment.");
    if(provider==="ipinfo")source.limitations.push("Network, ownership and geolocation context do not establish maliciousness.");
    if(provider==="mozilla_observatory")source.limitations.push("Web security posture is not threat reputation and does not establish maliciousness.");
    if(provider==="hibp")source.limitations.push("Breach exposure indicates historical exposure of an account, not current compromise.");
    if(INFRA_PROVIDERS.has(provider))source.limitations.push("Infrastructure observations do not by themselves establish malicious activity.");
    if(status==="empty")source.limitations.push("The provider returned no records; this is absence of evidence, not evidence that the target is benign.");
  } else {
    const message=output.message||evidence?.error?.message;
    if(message)source.limitations.push(String(message).slice(0,500));
    source.errors=[{category:status,message:String(message||`Provider returned status: ${status}`).slice(0,500)}];
  }
  if(status!=="success"&&!source.limitations.length)source.limitations.push(`Provider returned status: ${status}.`);
  return source;
}

module.exports={createInvestigation,buildInvestigationFromEvidence,normalizeSource,providerFromTool,providerLabel,hasMeaningfulInfrastructure,hasMeaningfulEvidence,providerQuality};
