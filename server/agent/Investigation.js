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
const { normalizeTimestamp } = require("./Timestamps");
const { calculateRisk } = require("./RiskScoring");
const { buildCurator } = require("./InvestigationNarrative");

function canonicalTargetIdentity(target,targetType){
  const raw=typeof target==="string"?target:null;
  const identity={type:targetType,raw,normalized:raw,hostname:null,path:null,query:null,port:null};
  if(!raw)return identity;
  if(targetType==="email"){
    // Keep the canonical value used by existing confidence checks, but avoid
    // storing a second identical copy in the generic raw field.
    identity.raw=null;
    return identity;
  }
  if(targetType==="url"){
    try{const parsed=new URL(raw.includes("://")?raw:`https://${raw}`);identity.normalized=parsed.href;identity.hostname=parsed.hostname.toLowerCase();identity.path=parsed.pathname;identity.query=parsed.search||null;identity.port=parsed.port||null;}catch{}
  }else if(targetType==="domain"){identity.normalized=raw.toLowerCase();identity.hostname=identity.normalized;}
  else if(targetType==="ip")identity.normalized=raw.trim();
  return identity;
}

const TOOL_PROVIDERS={
  virustotal_ip_lookup:"virustotal", virustotal_domain_lookup:"virustotal", virustotal_url_lookup:"virustotal", abuseipdb_ip_lookup:"abuseipdb",
  urlscan_lookup:"urlscan", shodan_ip_lookup:"shodan", ipinfo_ip_lookup:"ipinfo",
  censys_ip_lookup:"censys", securitytrails_lookup:"securitytrails",
  mozilla_observatory_scan:"mozilla_observatory", viewdns_lookup:"viewdns", hibp_lookup:"hibp",
  google_web_risk_lookup:"google-web-risk", urlhaus_lookup:"urlhaus",
  phishtank_lookup:"phishtank", threatfox_lookup:"threatfox", phishing_database_lookup:"phishing_database"
};
const PROVIDER_LABELS={
  virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",urlscan:"URLScan",shodan:"Shodan",ipinfo:"IPinfo",
  censys:"Censys",securitytrails:"SecurityTrails",mozilla_observatory:"Mozilla Observatory",
  viewdns:"ViewDNS",hibp:"Have I Been Pwned","google-web-risk":"Google Web Risk",
  urlhaus:"URLhaus",phishtank:"PhishTank",threatfox:"ThreatFox"
};
const STATUS_SET=new Set(["success","partial","not_configured","unauthorized","forbidden","invalid_request","rate_limited","timeout","unavailable","not_found","no_match","empty","error","skipped","not_required"]);
const IP_REPUTATION_PROVIDERS=new Set(["virustotal","abuseipdb"]);
const URL_REPUTATION_PROVIDERS=new Set(["google-web-risk","urlhaus","phishtank","threatfox","phishing_database"]);
const REPUTATION_PROVIDERS=new Set([...IP_REPUTATION_PROVIDERS,...URL_REPUTATION_PROVIDERS]);
const INFRA_PROVIDERS=new Set(["shodan","censys","securitytrails","viewdns","urlscan"]);

function createInvestigation({target,targetType="ip",startedAt=nowIso(),investigationId=null}={}) {
  return {
    investigationId:investigationId||null,target:target||null,targetType,targetIdentity:canonicalTargetIdentity(target,targetType),startedAt,completedAt:null,
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
  const f=source.findings||{};
  // Provider success describes transport/API execution. A no-match is a
  // successful lookup, but it is not meaningful positive security evidence.
  if(source.provider==="virustotal") return (numericValue(f.malicious)||0)>0 || (numericValue(f.suspicious)||0)>0;
  if(source.provider==="abuseipdb") return (numericValue(f.abuseConfidenceScore)||0)>0 || (numericValue(f.totalReports)||0)>0;
  if(source.provider==="phishing_database" || source.provider==="urlhaus") return f.match===true;
  if(source.provider==="phishtank") return f.match===true && Array.isArray(f.matches) && f.matches.some(match=>boolEvidence(match?.verified));
  if(source.provider==="threatfox" || source.provider==="google-web-risk") return Array.isArray(f.matches) && f.matches.some(Boolean);
  if(source.provider==="urlscan") {
    const observations=Array.isArray(f.results)?f.results:Array.isArray(f.observations)?f.observations:Array.isArray(f.scans)?f.scans:[];
    return observations.length>0 || [f.observedIp,f.observedIP,f.server,f.latestObservation,f.ip].some(isMeaningfulValue);
  }
  if(["shodan","censys","securitytrails"].includes(source.provider)) return hasMeaningfulInfrastructure(source);
  return meaningfulFields(source).length>0;
}
function numericValue(value){const n=Number(value);return Number.isFinite(n)?n:null;}
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
  const normalized=normalizeTimestamp(raw);
  if(!normalized)return {status:"unknown",observedAt:null};
  const d=new Date(normalized);
  const ageMs=Math.max(0,Date.now()-d.getTime());
  const ageDays=ageMs/86400000;
  return {status:ageDays<=7?"recent":ageDays<=90?"aging":"stale",observedAt:d.toISOString(),ageDays:Number(ageDays.toFixed(1))};
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
function boolEvidence(value){
  return value === true || /^(?:true|yes|y|1)$/i.test(String(value || ""));
}
function urlReputationAssessment(inv,sources,targetType){
  if(!["url","domain"].includes(targetType)) return {strongProviders:[],strongCount:0,evidenceConfidence:null,classification:"UNKNOWN",elevated:false};
  const byProvider=new Map(sources.filter(s=>URL_REPUTATION_PROVIDERS.has(s.provider)&&["success","partial"].includes(s.status)).map(s=>[s.provider,s]));
  const strong=[];
  const google=byProvider.get("google-web-risk");
  const googleMatches=Array.isArray(google?.findings?.matches)?google.findings.matches.filter(Boolean):[];
  if(googleMatches.length) strong.push({provider:"google-web-risk",source:google,field:"matches",value:googleMatches,reason:`Google Web Risk returned ${googleMatches.join(", ")} threat-list match(es).`});
  const urlhaus=byProvider.get("urlhaus");
  if(urlhaus?.findings?.match===true && Array.isArray(urlhaus.findings.matches) && urlhaus.findings.matches.length) strong.push({provider:"urlhaus",source:urlhaus,field:"matches",value:urlhaus.findings.matches,reason:"URLhaus returned a matching malware URL/host record."});
  const phishingDatabase=byProvider.get("phishing_database");
  if(phishingDatabase?.findings?.match===true) strong.push({provider:"phishing_database",source:phishingDatabase,field:"match",value:true,reason:"Phishing Database returned a phishing-domain match."});
  const phishtank=byProvider.get("phishtank");
  const phishMatch=Array.isArray(phishtank?.findings?.matches)?phishtank.findings.matches[0]:null;
  if(phishtank?.findings?.match===true && phishMatch && boolEvidence(phishMatch.verified)) strong.push({provider:"phishtank",source:phishtank,field:"matches",value:phishtank.findings.matches,reason:"PhishTank returned a verified phishing match."});
  const threatfox=byProvider.get("threatfox");
  if(Array.isArray(threatfox?.findings?.matches) && threatfox.findings.matches.length) strong.push({provider:"threatfox",source:threatfox,field:"matches",value:threatfox.findings.matches,reason:"ThreatFox returned an exact matching IOC."});

  const strongCount=strong.length;
  let evidenceConfidence=null;
  let classification="UNKNOWN";
  const availableCount=byProvider.size;
  if(strongCount>=2){
    evidenceConfidence=Math.min(100,97+strongCount);
    classification="CONFIRMED_MALICIOUS";
  } else if(strongCount===1){
    evidenceConfidence=70;
    classification="HIGH_CONFIDENCE_SUSPICIOUS";
  } else if(availableCount===URL_REPUTATION_PROVIDERS.size){
    classification="NO_KNOWN_MALICIOUS_REPUTATION";
  }
  if(strongCount>=2){
    const refs=strong.map(item=>sourceTrace(item.source,item.field,item.value));
    addCorrelation(inv,"url_reputation_corroboration",`Multiple independent URL reputation sources corroborate the target as malicious or phishing-related. Evidence confidence ${evidenceConfidence}/100 is a heuristic corroboration score, not a statistically calibrated probability.`,refs,"corroborated","reputation",{evidenceConfidence,classification,calibratedProbability:false});
    addFinding(inv,"url_reputation_classification",`Classification: ${classification}. The highest-confidence classification requires corroborating direct reputation evidence from at least two independent sources.`,refs,"elevated","reputation","corroborated",{evidenceConfidence,calibratedProbability:false});
  } else if(strongCount===1){
    const item=strong[0];
    addFinding(inv,"url_reputation_signal",item.reason,[sourceTrace(item.source,item.field,item.value)],"elevated","reputation","direct",{evidenceConfidence,calibratedProbability:false});
  } else if(availableCount===URL_REPUTATION_PROVIDERS.size){
    addFinding(inv,"url_reputation_observation","All configured URL reputation providers returned no strong malicious/phishing match. This is absence of known reputation, not proof that the target is safe.",Array.from(byProvider.values()).map(source=>sourceTrace(source,"matches",source.findings?.matches||[])),"informational","reputation","inconclusive",{classification,calibratedProbability:false});
  }
  return {strongProviders:strong.map(x=>x.provider),strongCount,evidenceConfidence,classification,elevated:strongCount>0,corroborated:strongCount>=2,availableCount};
}

function reputationAssessment(inv,vt,abuse){
  const vtM=vt?Number(vt.findings.malicious):NaN, vtS=vt?Number(vt.findings.suspicious):NaN;
  const abScore=abuse?Number(abuse.findings.abuseConfidenceScore):NaN;
  const vtElevated=Number.isFinite(vtM)&&vtM>0 || Number.isFinite(vtS)&&vtS>0;
  const abElevated=Number.isFinite(abScore)&&abScore>0;
  if(vtElevated){
    addFinding(inv,"reputation_signal",`VirusTotal reports ${Number.isFinite(vtM)?vtM:"an unspecified number of"} malicious and ${Number.isFinite(vtS)?vtS:"an unspecified number of"} suspicious detections.`,[sourceTrace(vt,"malicious",vt.findings.malicious),sourceTrace(vt,"suspicious",vt.findings.suspicious)],"elevated","reputation",evidenceStrength({direct:true}));
    if((Number.isFinite(vtM)?vtM:0)+(Number.isFinite(vtS)?vtS:0)>1){
      addCorrelation(inv,"multi_engine_corroboration","VirusTotal reports detections from multiple engines within its own analysis. This is multi-engine corroboration from one provider, not independent-provider corroboration.",[sourceTrace(vt,"malicious",vt.findings.malicious),sourceTrace(vt,"suspicious",vt.findings.suspicious)],"corroborated","single_provider_multi_engine");
    }
  }
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
  for(const s of sources){for(const [field,value] of Object.entries(s.findings||{})){const candidates=Array.isArray(value)?value:[value];for(const candidate of candidates)if(typeof candidate==="string"&&/tor[- ]?exit/i.test(candidate))torRefs.push(sourceTrace(s,field,candidate));}}
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
const EXTERNAL_INTELLIGENCE_PROVIDERS=new Set([
  "virustotal","abuseipdb","urlscan","shodan","ipinfo","censys","securitytrails",
  "mozilla_observatory","viewdns","google-web-risk","urlhaus","phishtank","threatfox","phishing_database","hibp"
]);
function detectEnvironmentalEvidence(sources){
  const refs=[];
  for(const s of sources){
    const provider=String(s?.provider||"").toLowerCase();
    if(EXTERNAL_INTELLIGENCE_PROVIDERS.has(provider)) continue;
    const sourceType=String(s?.sourceType||s?.category||s?.evidenceSource||"").trim().toLowerCase();
    if(!/^(internal|environmental|telemetry)$/.test(sourceType)) continue;
    for(const [field,value] of Object.entries(s.findings||{})){
      if(isMeaningfulValue(value)) refs.push(sourceTrace(s,field,value));
    }
  }
  return refs;
}
function confidenceBand(score){
  const n=Math.max(0,Math.min(100,Math.round(Number(score)||0)));
  if(n>=90)return "very_high";
  if(n>=75)return "high";
  if(n>=50)return "moderate";
  if(n>=25)return "low";
  return "very_low";
}
function sourceFreshnessFactor(source){
  const status=source?.quality?.freshness?.status;
  if(status==="fresh")return 1;
  if(status==="recent")return 0.9;
  if(status==="stale")return 0.55;
  return 0.5;
}
function numeric(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function buildLegacyCanonicalRisk(inv,{successful,failed,environmentalRefs,reputation,urlReputation}){
  const meaningful=successful.filter(s=>s.quality?.meaningful);
  const direct=[];
  const contextual=[];
  const noMatch=[];

  const vt=successful.find(s=>s.provider==="virustotal");
  if(vt){
    const m=numeric(vt.findings?.malicious), su=numeric(vt.findings?.suspicious);
    if(m!==null&&m>0)direct.push({provider:"virustotal",score:Math.min(92,62+Math.min(30,m*5)),type:"malicious"});
    else if(su!==null&&su>0)direct.push({provider:"virustotal",score:Math.min(70,45+Math.min(25,su*4)),type:"suspicious"});
    else if(m===0&&su===0)noMatch.push("virustotal");
  }
  const abuse=successful.find(s=>s.provider==="abuseipdb");
  if(abuse){
    const score=numeric(abuse.findings?.abuseConfidenceScore);
    if(score!==null&&score>0)direct.push({provider:"abuseipdb",score:Math.min(92,40+score*0.52),type:"abuse"});
  }
  if(urlReputation?.strongCount){
    const score=urlReputation.strongCount>=2?92:82;
    for(const provider of urlReputation.strongProviders||[])direct.push({provider,score,type:"url_reputation"});
  } else {
    for(const provider of ["urlhaus","threatfox","phishing_database","phishtank","google-web-risk"]){
      const source=successful.find(s=>s.provider===provider);
      if(!source)continue;
      if(source.findings?.match===false || (provider==="threatfox" && Array.isArray(source.findings?.matches) && source.findings.matches.length===0) || (provider==="google-web-risk" && Array.isArray(source.findings?.matches) && source.findings.matches.length===0))noMatch.push(provider);
    }
  }
  for(const source of meaningful){
    if(["urlscan","securitytrails","viewdns","shodan","censys","ipinfo","mozilla_observatory"].includes(source.provider))contextual.push(source);
  }

  const directProviders=new Set(direct.map(x=>x.provider));
  const maxDirect=direct.reduce((m,x)=>Math.max(m,x.score),0);
  const corroboration=Math.min(16,Math.max(0,(directProviders.size-1)*8));
  for(const source of successful)if(source.findingType==="no_match"&&!noMatch.includes(source.provider))noMatch.push(source.provider);
  const conflictCount=inv.conflicts.length;
  const factors=[];
  let score=null;
  if(maxDirect>0){
    score=maxDirect+corroboration-(conflictCount*5);
    const strongest=direct.filter(signal=>signal.score===maxDirect);
    const strongestSource=successful.find(source=>source.provider===strongest[0]?.provider);
    factors.push({name:"Highest direct external signal",signal:strongest.map(item=>`${item.provider}: ${item.type}`).join("; "),contribution:maxDirect,evidenceSource:strongest[0]?.provider||null,evidenceId:strongestSource?.evidenceId||null,providers:strongest.map(signal=>signal.provider)});
    if(corroboration)factors.push({name:"Independent-provider corroboration",signal:`${directProviders.size} independent reputation providers`,contribution:corroboration,evidenceSource:[...directProviders].join(", "),evidenceId:null});
    if(conflictCount)factors.push({name:"Conflicting evidence",signal:`${conflictCount} unresolved conflict(s)`,contribution:-conflictCount*5,evidenceSource:"investigation",evidenceId:inv.investigationId||null});
    score=Math.max(0,Math.min(100,Math.round(score)));
    const factorTotal=factors.reduce((sum,factor)=>sum+factor.contribution,0);
    if(factorTotal!==score)factors.push({name:"Score bound adjustment",signal:"Clamp to the 0–100 score range",contribution:score-factorTotal,evidenceSource:"risk_engine",evidenceId:null});
  }

  let externalThreat="unknown";
  if(maxDirect>=90&&directProviders.size>=2&&conflictCount===0)externalThreat="critical";
  else if(score>=75&&direct.length)externalThreat="high";
  else if(score>=50&&direct.length)externalThreat="elevated";
  // No-match and contextual observations are not positive threat weight.

  const planned=inv.sources.filter(s=>s.status!=="not_required").length;
  const consulted=successful.length+failed.length;
  const meaningfulRatio=planned?meaningful.length/planned:0;
  const availabilityRatio=planned?successful.length/planned:0;
  const freshness=meaningful.length?meaningful.reduce((sum,s)=>sum+sourceFreshnessFactor(s),0)/meaningful.length:0;
  const agreement=direct.length?(directProviders.size>=2?0.9:0.75):noMatch.length?0.8:0.55;
  let confidenceScore=15+meaningfulRatio*25+availabilityRatio*15+freshness*15+agreement*20;
  if(conflictCount)confidenceScore-=Math.min(20,conflictCount*8);
  if(direct.length===1&&failed.length>0)confidenceScore-=Math.min(15,failed.length*4);
  if(!meaningful.length)confidenceScore=15;
  confidenceScore=Math.max(0,Math.min(100,Math.round(confidenceScore)));
  const confidenceFactors={
    meaningfulEvidence:Math.round(meaningfulRatio*25),
    providerAvailability:Math.round(availabilityRatio*15),
    freshness:Math.round(freshness*15),
    agreement:Math.round(agreement*20),
    conflictAdjustment:conflictCount?-Math.min(20,conflictCount*8):0,
    singleDirectSourceFailureAdjustment:direct.length===1&&failed.length>0?-Math.min(15,failed.length*4):0,
  };

  const rationale=[];
  const skipped=inv.sources.filter(s=>s.status==="skipped");
  if(direct.length)rationale.push(`${directProviders.size} provider(s) supplied direct reputation or phishing indicators.`);
  if(noMatch.length)rationale.push(`${noMatch.length} provider(s) returned no-match evidence; no-match is not treated as proof of safety.`);
  if(contextual.length&&!direct.length)rationale.push(`${contextual.length} provider(s) supplied contextual infrastructure or posture observations without direct malicious evidence.`);
  if(failed.length)rationale.push(`${failed.length} consulted provider(s) were unavailable or unsuccessful and did not contribute clean evidence.`);
  if(skipped.length)rationale.push(`${skipped.length} planned provider(s) were not attempted and reduced completeness confidence.`);
  if(conflictCount)rationale.push(`${conflictCount} unresolved contradiction(s) reduced confidence.`);
  if(!rationale.length)rationale.push("Available evidence was insufficient to establish a stronger external threat classification.");

  return {
    score,
    baseScore:factors[0]?.contribution||0,
    factors,
    finalScore:score,
    riskFactors:factors,
    level:externalThreat,
    externalThreat,
    environmentalRisk:environmentalRefs.length?"elevated":"unknown",
    evidenceCoverage:meaningful.length ? (failed.length || skipped.length ? "partial" : meaningful.length>=2 ? "broad" : "limited") : "none",
    rationale,
    confidenceScore,
    confidenceFactors,
    confidenceLevel:confidenceBand(confidenceScore),
    externalConfidenceLevel:confidenceBand(confidenceScore),
    environmentalConfidenceLevel:environmentalRefs.length?"low":"unknown",
    environmentalConfidenceScore:environmentalRefs.length?Math.min(100,Math.round(25+Math.min(60,environmentalRefs.length*20))):null,
  };
}
function buildCanonicalRisk(inv, options){
  return calculateRisk({ investigation: inv, ...options, urlReputation: options.urlReputation });
}
function buildConfidence(inv,{successful,failed,environmentalRefs,reputation,urlReputation}){
  const risk=buildCanonicalRisk(inv,{successful,failed,environmentalRefs,reputation,urlReputation});
  inv.risk={
    ...(inv.risk||{}),
    score:risk.score,
    baseScore:risk.baseScore,
    factors:risk.factors,
    riskFactors:risk.riskFactors,
    level:risk.level,
    externalThreat:risk.externalThreat,
    independentProviderCount:risk.independentProviderCount,
    environmentalRisk:risk.environmentalRisk,
    evidenceCoverage:inv.risk?.evidenceCoverage||risk.evidenceCoverage,
    scoreSemantics:risk.scoreSemantics,
    calibratedProbability:risk.calibratedProbability,
    rationale:risk.rationale,
  };
  inv.confidence={
    score:risk.confidenceScore,
    level:risk.confidenceLevel,
    semantics:risk.confidenceSemantics,
    externalIntelligence:risk.externalConfidenceLevel,
    externalConfidence:risk.externalConfidenceLevel,
    externalIntelligenceScore:risk.externalConfidenceScore,
    evidenceConfidenceScore:risk.externalConfidenceScore,
    evidenceConfidenceLevel:risk.externalConfidenceLevel,
    currentStatusConfidenceScore:risk.currentStatusConfidenceScore,
    currentStatusConfidenceLevel:risk.currentStatusConfidenceLevel,
    currentStatusConfidenceSemantics:risk.currentStatusConfidenceSemantics,
    environmentalAssessment:risk.environmentalConfidenceLevel,
    environmentalConfidence:risk.environmentalConfidenceLevel,
    environmentalAssessmentScore:risk.environmentalConfidenceScore,
    rationale:[
      `${risk.independentProviderCount} independent provider(s) supplied direct reputation evidence; contextual identity, service, and posture observations are reported separately.`,
      "Confidence is a bounded evidence-quality heuristic based on direct reputation evidence, freshness, independent-provider corroboration, target attribution, conflicts, and failed-source penalties; it is not a statistical probability and does not rise from query count alone.",
      environmentalRefs.length?"Direct environmental telemetry was present in the supplied evidence.":"No direct environmental telemetry was present in the supplied evidence; environmental risk remains UNKNOWN.",
      ...risk.rationale,
    ]
  };
  if(urlReputation&&["url","domain"].includes(inv.targetType)){
    inv.confidence.reputationClassification=urlReputation.classification;
    inv.confidence.reputationProviders=urlReputation.strongProviders;
    if(urlReputation.evidenceConfidence!==null){
      inv.confidence.reputationEvidenceScore=urlReputation.evidenceConfidence;
      inv.confidence.reputationEvidenceScoreType="heuristic_corroboration";
      inv.confidence.rationale.push("URL reputation evidence confidence is a heuristic corroboration score, not a statistically calibrated probability.");
    }
  }
}
function buildInvestigationFromEvidence({target,targetType="ip",rawToolEvidence=[],startedAt,completed=true,expectedTools=[],investigationId=null}={}){
  const inv=createInvestigation({target,targetType,startedAt,investigationId});
  const evidence=Array.isArray(rawToolEvidence)?rawToolEvidence:[];
  const latest=new Map();
  for(const item of evidence){if(item?.toolName)latest.set(providerFromTool(item.toolName),item);}
  for(const tool of expectedTools||[]) if(!latest.has(providerFromTool(tool))) latest.set(providerFromTool(tool),{toolName:tool,ok:true,output:{status:"skipped",message:"Required provider was not attempted."},startedAt:null,completedAt:null});
  for(const item of latest.values()){
    const source=normalizeSource(item,{investigationId:inv.investigationId,target:inv.target,targetType:inv.targetType});
    source.quality=providerQuality(source);
    inv.sources.push(source);
  }
  const successful=inv.sources.filter(s=>["success","partial","not_found","no_match","empty"].includes(s.status));
  const failed=inv.sources.filter(s=>!["success","partial","not_found","no_match","empty","skipped","not_required"].includes(s.status));
  const skipped=inv.sources.filter(s=>s.status==="skipped");
  const vt=inv.sources.find(s=>s.provider==="virustotal"&&["success","partial"].includes(s.status));
  const abuse=inv.sources.find(s=>s.provider==="abuseipdb"&&["success","partial"].includes(s.status));
  const reputation=reputationAssessment(inv,vt,abuse);
  const urlReputation=urlReputationAssessment(inv,inv.sources,targetType);
  if(reputation.vtElevated&&urlReputation.strongProviders?.length){
    const reputationSources=inv.sources.filter(source=>urlReputation.strongProviders.includes(source.provider));
    addCorrelation(inv,"independent_provider_reputation_corroboration","VirusTotal and an independent URL reputation provider returned matching threat-related evidence. VirusTotal engine counts remain multi-engine evidence from one provider.",[sourceTrace(vt,"malicious",vt.findings.malicious),...reputationSources.map(source=>sourceTrace(source,"reputationMatch",source.findings?.matches||source.findings?.match))],"corroborated","reputation",{independentProviderCorroboration:true});
  }
  infrastructureCorrelation(inv,inv.sources);
  identityCorrelation(inv,inv.sources);

  const environmentalRefs=detectEnvironmentalEvidence(inv.sources);
  const meaningful=successful.filter(s=>s.quality?.meaningful);
  const coverage=successful.length===0?(skipped.length?"partial":"none"):failed.length>0||skipped.length>0?"partial":"broad";
  const consulted=inv.sources.filter(s=>!['skipped','not_required'].includes(s.status));
  const coverageDetails={
    planned:(expectedTools||[]).length,
    consulted:consulted.length,
    providersConsulted:consulted.length,
    successful:successful.length,
    providersSuccessful:successful.length,
    meaningful:meaningful.length,
    providersMeaningful:meaningful.length,
    contextual:meaningful.filter(s=>s.quality?.directness==="contextual"||s.findingType==="context_only").length,
    threatEvidence:meaningful.filter(s=>REPUTATION_PROVIDERS.has(s.provider)).length,
    noMatch:successful.filter(s=>s.findingType==="no_match").length,
    providersNoMatch:successful.filter(s=>s.findingType==="no_match").length,
    notFound:successful.filter(s=>s.findingType==="not_found").length,
    failed:failed.length,
    providersFailed:failed.length,
    unavailable:consulted.filter(s=>['unauthorized','forbidden','invalid_request','not_configured','timeout','unavailable','rate_limited','error'].includes(s.status)).length,
    coveragePercent:(expectedTools||[]).length?Math.round(meaningful.length/(expectedTools||[]).length*100):0,
    executionPercent:(expectedTools||[]).length?Math.round(consulted.length/(expectedTools||[]).length*100):0,
  };
  const externalThreat=(reputation.elevated||urlReputation.elevated)?"elevated":meaningful.length?"unknown":"unknown";
  const environmentalRisk=environmentalRefs.length?"elevated":"unknown";
  let overallAssessment="insufficient_evidence";
  if(environmentalRefs.length){overallAssessment=(reputation.elevated||urlReputation.elevated)?"elevated_concern":"suspicious";}
  else if(reputation.elevated||urlReputation.elevated)overallAssessment="elevated_concern";
  // Detect same-dimension signal differences before scoring so any conflict
  // adjustment is included in the deterministic risk factors.
  if(vt&&abuse && reputation.vtElevated!==reputation.abElevated){
    inv.conflicts.push({type:"reputation_signal_difference",providers:["virustotal","abuseipdb"],description:"The reputation providers differ in whether their supplied results contain an elevated reputation signal; they use different datasets and scoring methods, so this is treated as a signal difference rather than a direct contradiction.",resolution:"unresolved",significance:"moderate",evidenceType:"reputation"});
  }
  const canonicalRisk=buildCanonicalRisk(inv,{successful,failed,environmentalRefs,reputation,urlReputation});
  inv.risk={
    ...canonicalRisk,
    level:canonicalRisk.externalThreat,
    overallAssessment,
    externalThreat:canonicalRisk.externalThreat,
    environmentalRisk,
    evidenceCoverage:coverage,
    rationale:[...canonicalRisk.rationale,...((reputation.elevated||urlReputation.elevated)?[
      "One or more direct reputation signals are elevated in the supplied external intelligence.",
      "External reputation is kept separate from environmental impact.",
      ...(environmentalRefs.length?["Direct environmental evidence was also present in the supplied data."]:["No internal/environmental telemetry was provided to establish current malicious activity or compromise."])
    ]:[meaningful.length?"No elevated external reputation conclusion was established from the available evidence; absence of elevated reputation does not prove benignness.":"Relevant external security intelligence was unavailable."])],
    factors:canonicalRisk.riskFactors
  };
  inv.coverage=coverageDetails;
  if(reputation.both && vt?.findings?.lastAnalysisDate) inv.findings.find(f=>f.type==="reputation_signal")?.evidence.push(sourceTrace(vt,"lastAnalysisDate",vt.findings.lastAnalysisDate));

  for(const source of failed)dedupePush(inv.limitations,[`${providerLabel(source.provider)} was ${source.status} during this investigation.`]);
  for(const source of inv.sources.filter(s=>s.status==="skipped"))dedupePush(inv.limitations,[`${providerLabel(source.provider)} was not attempted; no provider evidence is available from this source.`]);
  if(!environmentalRefs.length)dedupePush(inv.limitations,["No internal telemetry was provided; environmental impact cannot be determined from external intelligence alone.","No firewall, proxy, DNS, endpoint, identity, packet-capture, or historical activity telemetry was provided."]);
  if(["url","domain"].includes(targetType) && urlReputation.strongCount===0) dedupePush(inv.limitations,["No strong malicious/phishing reputation corroboration was established; no-match results are absence of known reputation, not proof of safety."]);
  if(["url","domain"].includes(targetType) && urlReputation.strongCount===1) dedupePush(inv.limitations,["Only one strong URL reputation source matched; the heuristic evidence confidence remains below the corroborated threshold."]);
  if(successful.some(s=>s.findings?.lastAnalysisDate||s.findings?.lastReportedAt||s.findings?.lastUpdated))dedupePush(inv.limitations,["Provider observations have provider-specific timestamps; older reputation or infrastructure data may not reflect the target's current state."]);
  if(inv.sources.some(s=>!["success","no_match","skipped","not_required"].includes(s.status)))dedupePush(inv.limitations,["Investigation completed with partial source availability."]);
  if(inv.sources.some(s=>["success","partial"].includes(s.status)))dedupePush(inv.limitations,["No behavioral telemetry was available to support a confident MITRE ATT&CK mapping from reputation, infrastructure, posture, or breach intelligence alone."]);
  buildConfidence(inv,{successful,failed,environmentalRefs,reputation,urlReputation});
  inv.mitre=[];
  inv.status=completed?(coverageDetails.executionPercent===100&&failed.length===0?"completed":"partial"):"collecting";
  inv.completedAt=completed?nowIso():null;
  inv.limitations=[...new Set(inv.limitations)];
  inv.curator=buildCurator(inv);
  return inv;
}
function normalizeSource(evidence,{investigationId=null,target=null,targetType=null}={}){
  const provider=providerFromTool(evidence?.toolName), output=evidence?.output||{};
  let status=sourceStatus(evidence);
  const source={investigationId:investigationId||null,target:target||null,targetType:targetType||null,provider,tool:evidence?.toolName,status,meaningful:false,evidence:Array.isArray(output.evidence)?output.evidence:[],observedAt:output.providerObservedAt||null,analysisAt:null,retrievedAt:output.collectedAt||evidence?.completedAt||null,collectedAt:output.collectedAt||evidence?.completedAt||evidence?.startedAt||null,findings:{},confidence:"low",limitations:[],errors:[],errorCode:null,errorMessage:null};
  if(status==="success"||status==="partial"||status==="empty"||status==="no_match"){
    source.findings=sourceFindings(output);
    source.observedAt=normalizeTimestamp(source.observedAt||source.findings.providerObservedAt||source.findings.lastReportedAt||null);
    source.analysisAt=normalizeTimestamp(source.findings.lastAnalysisDate||source.findings.analysisDate||null);
    source.providerObservedAt=source.observedAt;
    source.providerAnalysisAt=source.analysisAt;
    source.evidenceId=source.findings.evidenceId||source.findings.analysisId||source.findings.id||source.evidence.find(item=>item&&typeof item==="object"&&item.id)?.id||null;
    source.findingType=status==="no_match"?"no_match":classifyFindingType(source);
    source.freshness=source.quality?.freshness?.status||freshnessInfo(source).status;
    source.evidenceAgeDays=freshnessInfo(source).ageDays??null;
    if(provider==="viewdns" && status==="success" && !hasMeaningfulInfrastructure(source)) status="empty";
    source.status=status;
    const qualityHint=hasMeaningfulEvidence(source)?"moderate":"low";
    source.confidence=qualityHint;
    if(status==="no_match"){
      source.meaningful=false;
      source.limitations.push("The provider explicitly returned no_match; this result was not treated as positive threat evidence.");
    }
    if(REPUTATION_PROVIDERS.has(provider))source.limitations.push("External reputation intelligence does not establish compromise in the user's environment.");
    if(provider==="ipinfo")source.limitations.push("Network, ownership and geolocation context do not establish maliciousness.");
    if(provider==="mozilla_observatory")source.limitations.push("Web security posture is not threat reputation and does not establish maliciousness.");
    if(provider==="hibp")source.limitations.push("Breach exposure indicates historical exposure of an account, not current compromise.");
    if(INFRA_PROVIDERS.has(provider))source.limitations.push("Infrastructure observations do not by themselves establish malicious activity.");
    if(status==="empty")source.limitations.push("The provider returned no records; this is absence of evidence, not evidence that the target is benign.");
  } else if(status==="not_found"){
    source.findings=sourceFindings(output);
    source.findingType="not_found";
    source.providerObservedAt=null;
    source.providerAnalysisAt=null;
    source.evidenceId=source.findings.evidenceId||source.findings.analysisId||source.findings.id||null;
    source.freshness="unknown";
    source.evidenceAgeDays=null;
    source.limitations.push(String(output.message||"No existing provider record was returned; this is not evidence that the target is safe.").slice(0,500));
  } else {
    const message=output.message||evidence?.error?.message;
    source.errorCode=evidence?.error?.code||output.errorCode||status;
    source.errorMessage=String(message||`Provider returned status: ${status}`).slice(0,500);
    if(message)source.limitations.push(String(message).slice(0,500));
    source.errors=[{category:source.errorCode,message:source.errorMessage}];
  }
  source.meaningful=hasMeaningfulEvidence(source);
  source.findingType=source.findingType||classifyFindingType(source);
  if(!source.evidence.length&&Object.keys(source.findings||{}).length)source.evidence=Object.entries(source.findings).map(([field,value])=>({source:provider,field,value}));
  if(status!=="success"&&!source.limitations.length)source.limitations.push(`Provider returned status: ${status}.`);
  return source;
}

function classifyFindingType(source){
  if(!source)return "error";
  if(source.status==="not_found")return "not_found";
  if(source.status==="no_match")return "no_match";
  if(!["success","partial"].includes(source.status))return "error";
  if(!hasMeaningfulEvidence(source))return "no_match";
  if(source.provider==="virustotal"||source.provider==="abuseipdb"||REPUTATION_PROVIDERS.has(source.provider))return "reputation";
  if(["urlscan","shodan","censys","ipinfo","viewdns","securitytrails","mozilla_observatory"].includes(source.provider))return "context_only";
  return "meaningful";
}

module.exports={createInvestigation,buildInvestigationFromEvidence,normalizeSource,providerFromTool,providerLabel,hasMeaningfulInfrastructure,hasMeaningfulEvidence,providerQuality,canonicalTargetIdentity};
