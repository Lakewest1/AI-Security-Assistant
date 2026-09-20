const net=require("net");
const {fetchWithRetry,statusForHttp,publicResult,successResult}=require("./provider-utils");
const DEFAULT_TIMEOUT_MS=Number(process.env.VIEWDNS_TIMEOUT_MS)||8000;
function target(input){const d=String(input?.domain||"").trim();const ip=String(input?.ip||"").trim();if(d&&/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))return {kind:"domain",value:d};if(ip&&net.isIP(ip))return {kind:"ip",value:ip};return null;}
function createViewDNSTool({apiKey,timeoutMs=DEFAULT_TIMEOUT_MS}={}) {
 return {name:"viewdns_lookup",description:"Look up DNS, reverse-DNS, WHOIS and infrastructure relationships using ViewDNS.",
 inputSchema:{type:"object",properties:{domain:{type:"string",minLength:3,maxLength:253},ip:{type:"string",minLength:2,maxLength:45}},additionalProperties:false,minProperties:1},
 category:"threat-intelligence",targetTypes:["domain","ip"],readOnly:true,destructive:false,riskLevel:"read",requiresApproval:false,
 async execute(input){
   const t=target(input);
   if(!t)return publicResult("viewdns","error","Invalid domain or IP target");
   if(!apiKey)return publicResult("viewdns","unauthorized","ViewDNS API key is not configured");
   const host=t.value;
   const endpoints=[
     `https://api.viewdns.info/reverseip/?host=${encodeURIComponent(host)}&apikey=${encodeURIComponent(apiKey)}&output=json`,
     `https://api.viewdns.info/whois/v2/?domain=${encodeURIComponent(host)}&apikey=${encodeURIComponent(apiKey)}&output=json`,
   ];
   try {
     const settled=await Promise.allSettled(endpoints.map(url=>fetchWithRetry(url,{timeoutMs,headers:{Accept:"application/json"}})));
     const findings={target:host,lookupType:t.kind};
     let successes=0, lastFailure=null;
     for(const result of settled){
       if(result.status==="fulfilled"){
         const {response,payload}=result.value;
         if(response.status===200 && payload && typeof payload==="object"){
           successes+=1;
           if(payload.response?.domains) findings.reverseIpDomains=payload.response.domains;
           if(payload.response?.matches) findings.reverseWhoisMatches=payload.response.matches;
           if(payload.response?.records) findings.whoisRecords=payload.response.records;
           if(payload.response?.domain_count!==undefined) findings.reverseIpDomainCount=payload.response.domain_count;
           if(payload.response?.result_count!==undefined) findings.whoisResultCount=payload.response.result_count;
           if(payload.response?.owner!==undefined) findings.owner=payload.response.owner;
         } else lastFailure=statusForHttp(response.status);
       } else lastFailure=result.reason?.category==="tool_timeout"?"timeout":"unavailable";
     }
     if(successes===2)return successResult("viewdns",findings);
     if(successes===1){
       return {...successResult("viewdns",findings),status:"partial",limitations:["One of the requested ViewDNS lookups was unavailable."]};
     }
     return publicResult("viewdns",lastFailure||"unavailable","ViewDNS did not return usable lookup data");
   } catch(error){
     return publicResult("viewdns",error.category==="tool_timeout"?"timeout":"unavailable",error.message);
   }
 }};
}
module.exports={createViewDNSTool};
