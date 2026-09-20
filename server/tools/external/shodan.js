const net = require("net");
const { fetchWithRetry, statusForHttp, publicResult, successResult, compactObject } = require("./provider-utils");
const DEFAULT_TIMEOUT_MS = Number(process.env.SHODAN_TIMEOUT_MS) || 8000;
function createShodanTool({apiKey,timeoutMs=DEFAULT_TIMEOUT_MS}={}) {
  return {
    name:"shodan_ip_lookup", description:"Look up internet-exposed services for an IP in Shodan.",
    inputSchema:{type:"object",properties:{ip:{type:"string",minLength:2,maxLength:45}},required:["ip"],additionalProperties:false},
    category:"threat-intelligence",targetTypes:["ip"],readOnly:true,destructive:false,riskLevel:"read",requiresApproval:false,
    async execute(input){
      const ip=String(input?.ip||"").trim();
      if (!net.isIP(ip)) return publicResult("shodan","error","Invalid IP address");
      if (!apiKey) return publicResult("shodan","unauthorized","Shodan API key is not configured");
      try {
        const {response,payload}=await fetchWithRetry(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`,{timeoutMs,headers:{Accept:"application/json"}});
        if(response.status!==200) return publicResult("shodan",statusForHttp(response.status),`Shodan returned HTTP ${response.status}`);
        if(!payload||typeof payload!=="object") return publicResult("shodan","error","Shodan returned an unexpected response shape");
        return successResult("shodan",compactObject({
          ip:payload.ip_str||ip, organization:payload.org, asn:payload.asn,
          country:payload.country_code, hostnames:payload.hostnames,
          ports:payload.ports, services:Array.isArray(payload.data)?payload.data.slice(0,20).map(x=>compactObject({
            port:x.port,transport:x.transport,product:x.product,version:x.version,banner:x.data,
          })):[],
        }));
      } catch(error){ return publicResult("shodan",error.category==="tool_timeout"?"timeout":"unavailable",error.message); }
    }
  };
}
module.exports={createShodanTool};
