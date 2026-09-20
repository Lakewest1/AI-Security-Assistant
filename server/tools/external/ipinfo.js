const net=require("net");
const {fetchWithRetry,statusForHttp,publicResult,successResult,compactObject}=require("./provider-utils");
const DEFAULT_TIMEOUT_MS=Number(process.env.IPINFO_TIMEOUT_MS)||8000;
function createIPInfoTool({token,timeoutMs=DEFAULT_TIMEOUT_MS}={}) {
 return {name:"ipinfo_ip_lookup",description:"Look up network and privacy context for an IP using IPinfo.",
 inputSchema:{type:"object",properties:{ip:{type:"string",minLength:2,maxLength:45}},required:["ip"],additionalProperties:false},
 category:"threat-intelligence",targetTypes:["ip"],readOnly:true,destructive:false,riskLevel:"read",requiresApproval:false,
 async execute(input){const ip=String(input?.ip||"").trim();if(!net.isIP(ip))return publicResult("ipinfo","error","Invalid IP address");if(!token)return publicResult("ipinfo","unauthorized","IPinfo token is not configured");
 try{const {response,payload}=await fetchWithRetry(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(token)}`,{timeoutMs,headers:{Accept:"application/json"}});
 if(response.status!==200)return publicResult("ipinfo",statusForHttp(response.status),`IPinfo returned HTTP ${response.status}`);
 if(!payload||typeof payload!=="object")return publicResult("ipinfo","error","IPinfo returned an unexpected response shape");
 return successResult("ipinfo",compactObject({ip:payload.ip||ip,country:payload.country,region:payload.region,city:payload.city,hostname:payload.hostname,organization:payload.org,asn:payload.asn?.asn||payload.org?.match(/^AS\d+/)?.[0],privacy:payload.privacy}));
 }catch(error){return publicResult("ipinfo",error.category==="tool_timeout"?"timeout":"unavailable",error.message);}
 }};
}
module.exports={createIPInfoTool};
