const { fetchWithRetry, statusForHttp, publicResult, successResult, compactObject } = require("./provider-utils");

const DEFAULT_TIMEOUT_MS = Number(process.env.URLSCAN_TIMEOUT_MS) || 8000;

function validTarget(input) {
  if (!input || typeof input !== "object") return null;
  const value = String(input.url || input.domain || input.ip || "").trim();
  if (!value || value.length > 2048) return null;
  if (input.ip && !/^[0-9a-f:.]+$/i.test(value)) return null;
  if (input.domain && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return null;
  if (input.url && !/^https?:\/\//i.test(value)) return null;
  return value;
}
function queryFor(input, value) {
  if (input.ip) return `ip:${value}`;
  if (input.domain) return `domain:${value}`;
  try { return `domain:${new URL(value).hostname}`; } catch { return value; }
}
function normalize(body, target) {
  const results = Array.isArray(body?.results) ? body.results : [];
  return compactObject({
    target,
    totalResults: body?.total,
    observations: results.slice(0, 10).map((r) => compactObject({
      scanId: r?._id || r?.task?.uuid,
      pageUrl: r?.page?.url,
      domain: r?.page?.domain,
      ip: r?.page?.ip,
      country: r?.page?.country,
      server: r?.page?.server,
      verdicts: r?.verdicts,
      scanDate: r?.task?.time || r?.page?.tlsValidDays,
    })),
  });
}
function createURLScanTool({ apiKey, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return {
    name: "urlscan_lookup",
    description: "Look up URL, domain, or IP observations in URLScan.",
    inputSchema: { type:"object", properties:{
      url:{type:"string",minLength:4,maxLength:2048},
      domain:{type:"string",minLength:3,maxLength:253},
      ip:{type:"string",minLength:2,maxLength:45},
    }, additionalProperties:false, minProperties:1 },
    category:"threat-intelligence", targetTypes:["url","domain","ip"],
    readOnly:true, destructive:false, riskLevel:"read", requiresApproval:false,
    async execute(input) {
      const target = validTarget(input);
      if (!target) return publicResult("urlscan","error","Invalid URL, domain, or IP target");
      if (!apiKey) return publicResult("urlscan","unauthorized","URLScan API key is not configured");
      const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(queryFor(input,target))}&size=10`;
      try {
        const {response,payload}=await fetchWithRetry(url,{timeoutMs,headers:{Accept:"application/json","API-Key":apiKey}});
        if (response.status !== 200) return publicResult("urlscan",statusForHttp(response.status),`URLScan returned HTTP ${response.status}`);
        if (!payload || !Array.isArray(payload.results)) return publicResult("urlscan","error","URLScan returned an unexpected response shape");
        return successResult("urlscan",normalize(payload,target));
      } catch(error) {
        return publicResult("urlscan",error.category==="tool_timeout"?"timeout":"unavailable",error.message);
      }
    },
  };
}
module.exports={createURLScanTool};
