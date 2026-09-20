const {fetchWithRetry,statusForHttp,publicResult,successResult,compactObject}=require("./provider-utils");
const DEFAULT_TIMEOUT_MS=Number(process.env.SECURITYTRAILS_TIMEOUT_MS)||8000;
function domain(input){const d=String(input?.domain||input?.subdomain||"").trim().toLowerCase();return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)?d:null;}
function createSecurityTrailsTool({apiKey,timeoutMs=DEFAULT_TIMEOUT_MS}={}) {
 return {name:"securitytrails_lookup",description:"Look up DNS and historical domain infrastructure relationships in SecurityTrails.",
 inputSchema:{type:"object",properties:{domain:{type:"string",minLength:3,maxLength:253},subdomain:{type:"string",minLength:3,maxLength:253},ip:{type:"string",minLength:2,maxLength:45}},additionalProperties:false,minProperties:1},
 category:"threat-intelligence",targetTypes:["domain","subdomain","ip"],readOnly:true,destructive:false,riskLevel:"read",requiresApproval:false,
 async execute(input){const d=domain(input);const ip=String(input?.ip||"").trim();if(!d&&!/^[0-9a-f:.]+$/i.test(ip))return publicResult("securitytrails","error","Invalid domain or IP target");if(!apiKey)return publicResult("securitytrails","unauthorized","SecurityTrails API key is not configured");
 const endpoint=d?`https://api.securitytrails.com/v1/domain/${encodeURIComponent(d)}/history/a`:`https://api.securitytrails.com/v1/ips/${encodeURIComponent(ip)}/whois`;
 try{const {response,payload}=await fetchWithRetry(endpoint,{timeoutMs,headers:{Accept:"application/json",APIKEY:apiKey}});
 if(response.status!==200)return publicResult("securitytrails",statusForHttp(response.status),`SecurityTrails returned HTTP ${response.status}`);
 if(!payload||typeof payload!=="object")return publicResult("securitytrails","error","SecurityTrails returned an unexpected response shape");
 return successResult("securitytrails",compactObject({target:d||ip,records:payload.records,recordsCount:payload.records?.length,organizations:payload.organizations,history:payload}));
 }catch(error){return publicResult("securitytrails",error.category==="tool_timeout"?"timeout":"unavailable",error.message);}
 }};
}
module.exports={createSecurityTrailsTool};
