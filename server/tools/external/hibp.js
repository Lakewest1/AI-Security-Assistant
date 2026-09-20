const {fetchWithRetry,statusForHttp,publicResult,successResult}=require("./provider-utils");
const DEFAULT_TIMEOUT_MS=Number(process.env.HIBP_TIMEOUT_MS)||8000;
function validEmail(email){return typeof email==="string"&&email.length<=320&&/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());}
function createHIBPTool({apiKey,timeoutMs=DEFAULT_TIMEOUT_MS,userAgent=process.env.HIBP_USER_AGENT||"AI-Security-Assistant"}={}) {
 return {name:"hibp_lookup",description:"Check whether an email address appears in Have I Been Pwned breach intelligence.",
 inputSchema:{type:"object",properties:{email:{type:"string",minLength:3,maxLength:320}},required:["email"],additionalProperties:false},
 category:"identity-intelligence",targetTypes:["email"],readOnly:true,destructive:false,riskLevel:"read",requiresApproval:false,
 async execute(input){const email=String(input?.email||"").trim();if(!validEmail(email))return publicResult("hibp","error","Invalid email address");if(!apiKey)return publicResult("hibp","unauthorized","HIBP API key is not configured");
 try{const {response,payload}=await fetchWithRetry(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,{timeoutMs,headers:{Accept:"application/json","hibp-api-key":apiKey,"user-agent":userAgent}});
 if(response.status===404)return successResult("hibp",{email,breached:false,breachCount:0,breaches:[]});
 if(response.status!==200)return publicResult("hibp",statusForHttp(response.status),`HIBP returned HTTP ${response.status}`);
 if(!Array.isArray(payload))return publicResult("hibp","error","HIBP returned an unexpected response shape");
 const breaches=payload.map(b=>({name:b.Name,title:b.Title,domain:b.Domain,breachDate:b.BreachDate,addedDate:b.AddedDate,dataClasses:b.DataClasses,verified:b.IsVerified}));
 return successResult("hibp",{email,breached:breaches.length>0,breachCount:breaches.length,breaches});
 }catch(error){return publicResult("hibp",error.category==="tool_timeout"?"timeout":"unavailable",error.message);}
 }};
}
module.exports={createHIBPTool};
