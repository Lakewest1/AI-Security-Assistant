const {fetchWithRetry,statusForHttp,publicResult,successResult,compactObject}=require("./provider-utils");
const DEFAULT_TIMEOUT_MS=Number(process.env.MOZILLA_OBSERVATORY_TIMEOUT_MS)||8000;
function hostFor(input){const raw=String(input?.url||input?.domain||"").trim();if(!raw)return null;try{return new URL(raw.includes("://")?raw:`https://${raw}`).hostname;}catch{return null;}}
function createMozillaObservatoryTool({timeoutMs=DEFAULT_TIMEOUT_MS}={}) {
 return {name:"mozilla_observatory_scan",description:"Assess web security posture and headers using Mozilla Observatory.",
 inputSchema:{type:"object",properties:{domain:{type:"string",minLength:3,maxLength:253},url:{type:"string",minLength:4,maxLength:2048}},additionalProperties:false,minProperties:1},
 category:"security-posture",targetTypes:["domain","url"],readOnly:true,destructive:false,riskLevel:"read",requiresApproval:false,
 async execute(input){const host=hostFor(input);if(!host)return publicResult("mozilla_observatory","error","Invalid domain or URL");
 try{const {response,payload}=await fetchWithRetry("https://observatory-api.mdn.mozilla.net/api/v2/scan",{method:"POST",timeoutMs,headers:{"Accept":"application/json","Content-Type":"application/json"},body:JSON.stringify({host,rescan:false})});
 if(![200,201].includes(response.status))return publicResult("mozilla_observatory",statusForHttp(response.status),`Mozilla Observatory returned HTTP ${response.status}`);
 if(!payload||typeof payload!=="object")return publicResult("mozilla_observatory","error","Mozilla Observatory returned an unexpected response shape");
 return successResult("mozilla_observatory",compactObject({host,scanId:payload.scan_id,score:payload.score,status:payload.state||payload.status,grade:payload.grade,testsFailed:payload.tests_failed,testsPassed:payload.tests_passed,tests:payload.tests}));
 }catch(error){return publicResult("mozilla_observatory",error.category==="tool_timeout"?"timeout":"unavailable",error.message);}
 }};
}
module.exports={createMozillaObservatoryTool};
