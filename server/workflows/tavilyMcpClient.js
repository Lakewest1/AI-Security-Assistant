"use strict";

const { createResponseTimeout, limitResponseStream } = require("../tools/external/provider-utils");
const net = require("node:net");

const TAVILY_ENDPOINT = "https://mcp.tavily.com/mcp/";
const TAVILY_SEARCH_TOOL = "tavily_search";
const MAX_MCP_RESPONSE_BYTES = 128 * 1024;
const MAX_NORMALIZED_BYTES = 64 * 1024;
const MAX_TIMEOUT_MS = 10_000;
const MAX_CONCURRENT_REQUESTS = 2;
const MAX_RESULTS = 5;
const OFFLINE_ONLY_STAGE = true;
const KNOWN_TAVILY_TOOLS = new Set(["tavily_search", "tavily_research", "tavily_extract", "tavily_map", "tavily_crawl"]);

class McpWorkflowError extends Error {
  constructor(code) {
    super(code);
    this.name = "McpWorkflowError";
    this.code = code;
  }
}

function isSupportedRuntime(version = process.versions.node) {
  const major = Number(String(version).split(".")[0]);
  return Number.isInteger(major) && major >= 20;
}

function isLiveEnablementSatisfied(env = process.env) {
  return !OFFLINE_ONLY_STAGE
    && env.RESEARCH_MCP_ENABLED === "true"
    && env.RESEARCH_MCP_LIVE_CALLS_ALLOWED === "true"
    && isSupportedRuntime();
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function combineSignals(first, second) {
  if (!first) return second;
  if (!second) return first;
  if (typeof AbortSignal.any === "function") return AbortSignal.any([first, second]);
  const combined = new AbortController();
  const abort = (signal) => { if (!combined.signal.aborted) combined.abort(signal.reason); };
  if (first.aborted) abort(first);
  else first.addEventListener("abort", () => abort(first), { once: true });
  if (second.aborted) abort(second);
  else second.addEventListener("abort", () => abort(second), { once: true });
  return combined.signal;
}

function createBoundedMcpFetch({ fetchImpl = globalThis.fetch, maxBytes = MAX_MCP_RESPONSE_BYTES, timeoutMs = MAX_TIMEOUT_MS, parentSignal } = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("Fetch implementation required");
  return async function boundedMcpFetch(input, init = {}) {
    let requestUrl;
    try { requestUrl = new URL(typeof input === "string" || input instanceof URL ? input : input.url); }
    catch { throw new McpWorkflowError("PROVIDER_UNAVAILABLE"); }
    if (requestUrl.origin !== new URL(TAVILY_ENDPOINT).origin || requestUrl.pathname !== new URL(TAVILY_ENDPOINT).pathname || requestUrl.search || requestUrl.hash) {
      throw new McpWorkflowError("PROVIDER_UNAVAILABLE");
    }
    const controller = new AbortController();
    const timeout = createResponseTimeout(controller, Math.min(timeoutMs, MAX_TIMEOUT_MS));
    const signal = combineSignals(combineSignals(init.signal, parentSignal), controller.signal);
    try {
      const response = await fetchImpl(requestUrl, { ...init, redirect: "error", signal });
      if (response.status >= 300 && response.status < 400) {
        try { await response.body?.cancel?.(); } catch { /* best-effort cancellation */ }
        timeout.finish();
        throw new McpWorkflowError("PROVIDER_UNAVAILABLE");
      }
      timeout.bind(response);
      return limitResponseStream(response, { maxBytes, highWaterMark: 0 });
    } catch (error) {
      timeout.finish();
      if (controller.signal.aborted && !parentSignal?.aborted) throw new McpWorkflowError("REQUEST_TIMEOUT");
      if (parentSignal?.aborted || init.signal?.aborted) throw new McpWorkflowError("REQUEST_TIMEOUT");
      if (error?.category === "response_too_large" || error?.code === "RESPONSE_TOO_LARGE") throw new McpWorkflowError("RESPONSE_TOO_LARGE");
      if (error?.category === "tool_timeout" || error?.code === "REQUEST_TIMEOUT") throw new McpWorkflowError("REQUEST_TIMEOUT");
      throw new McpWorkflowError("PROVIDER_UNAVAILABLE");
    }
  };
}

function validateToolSchema(tool) {
  if (!tool || tool.name !== TAVILY_SEARCH_TOOL || !isPlainObject(tool.inputSchema)) return false;
  const schema = tool.inputSchema;
  if (schema.type !== "object" || !isPlainObject(schema.properties) || !Array.isArray(schema.required)) return false;
  if (Object.keys(schema).some((key) => key.toLowerCase().includes("mcp-header"))) return false;
  if (schema.required.length !== 1 || schema.required[0] !== "query") return false;
  const query = schema.properties.query;
  if (!query || query.type !== "string") return false;
  const types = {
    search_depth: "string", topic: "string", time_range: "string", max_results: "integer",
    include_images: "boolean", include_image_descriptions: "boolean", include_raw_content: "boolean",
    include_domains: "array", exclude_domains: "array", country: "string", include_favicon: "boolean",
    start_date: "string", end_date: "string", exact_match: "boolean",
  };
  for (const [name, property] of Object.entries(schema.properties)) {
    if (name === "query") continue;
    if (Object.keys(property || {}).some((key) => key.toLowerCase().includes("mcp-header"))) return false;
    if (!(name in types) && name !== "query") return false;
    if (property?.type !== types[name]) return false;
    if (["search_depth"].includes(name) && Array.isArray(property.enum) && !property.enum.includes("basic")) return false;
    if (name === "topic" && Array.isArray(property.enum) && !property.enum.includes("general")) return false;
    if (name === "max_results" && property.minimum !== undefined && property.minimum > 1) return false;
    if (name === "max_results" && property.maximum !== undefined && property.maximum < MAX_RESULTS) return false;
    if (["include_domains", "exclude_domains"].includes(name) && property.items?.type !== "string") return false;
  }
  return true;
}

function validateInventory(inventory) {
  if (!inventory || !Array.isArray(inventory.tools) || inventory.nextCursor) throw new McpWorkflowError("TOOL_SCHEMA_MISMATCH");
  if (inventory.tools.some((tool) => !KNOWN_TAVILY_TOOLS.has(tool?.name))) throw new McpWorkflowError("TOOL_SCHEMA_MISMATCH");
  const matches = inventory.tools.filter((tool) => tool.name === TAVILY_SEARCH_TOOL);
  if (matches.length !== 1 || !validateToolSchema(matches[0])) throw new McpWorkflowError("TOOL_SCHEMA_MISMATCH");
}

function safePublicUrl(value) {
  if (typeof value !== "string" || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (!(["http:", "https:"].includes(url.protocol)) || url.username || url.password) return null;
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname === "metadata.google.internal") return null;
    if (net.isIP(hostname) === 6) return null;
    if (net.isIP(hostname) === 4) {
      const [a, b, c, d] = hostname.split(".").map(Number);
      if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254)
        || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
        || (a === 100 && b >= 64 && b <= 127) || (a === 192 && (b === 0 || b === 2))
        || (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100))
        || (a === 203 && b === 0 && c === 113) || (a === 255 && b === 255 && c === 255 && d === 255)) return null;
    }
    return url.toString();
  } catch { return null; }
}

function parseToolPayload(result) {
  if (!result || typeof result !== "object" || result.isError === true) throw new McpWorkflowError("INVALID_PROVIDER_RESPONSE");
  if (isPlainObject(result.structuredContent)) return result.structuredContent;
  if (!Array.isArray(result.content) || result.content.length !== 1 || result.content[0]?.type !== "text" || typeof result.content[0].text !== "string") {
    throw new McpWorkflowError("INVALID_PROVIDER_RESPONSE");
  }
  try {
    const parsed = JSON.parse(result.content[0].text);
    if (!isPlainObject(parsed)) throw new Error();
    return parsed;
  } catch { throw new McpWorkflowError("INVALID_PROVIDER_RESPONSE"); }
}

function normalizeSearchResult(result) {
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > MAX_NORMALIZED_BYTES) throw new McpWorkflowError("RESPONSE_TOO_LARGE");
  const payload = parseToolPayload(result);
  if (!Array.isArray(payload.results)) throw new McpWorkflowError("INVALID_PROVIDER_RESPONSE");
  if (payload.results.length === 0) return { status: "empty", result: { summary: null, evidence: [] }, sources: [], limitations: [] };
  const sources = [];
  let rejected = Math.max(0, payload.results.length - MAX_RESULTS);
  const seenSourceIds = new Map();
  for (const item of payload.results.slice(0, MAX_RESULTS)) {
    if (!isPlainObject(item)) { rejected += 1; continue; }
    const url = safePublicUrl(item.url);
    if (!url) { rejected += 1; continue; }
    if (typeof item.id === "string" && item.id.length > 0 && item.id.length <= 128) {
      if (seenSourceIds.has(item.id)) { rejected += 1; continue; }
      seenSourceIds.set(item.id, url);
    }
    const source = { url };
    if (typeof item.id === "string" && item.id.length > 0 && item.id.length <= 128) source.id = item.id;
    if (typeof item.title === "string" && item.title.length <= 500) source.title = item.title;
    if (typeof item.content === "string" && item.content.length <= 4000) source.excerpt = item.content;
    const timestamp = item.retrieved_at ?? item.retrievedAt;
    if (typeof timestamp === "string" && Number.isFinite(Date.parse(timestamp))) source.retrievedAt = new Date(timestamp).toISOString();
    sources.push(source);
  }
  if (!sources.length) throw new McpWorkflowError("INVALID_PROVIDER_RESPONSE");
  const status = rejected ? "partial" : "success";
  return {
    status,
    result: { summary: null, evidence: sources.filter((source) => source.id && source.excerpt).map((source) => ({ sourceId: source.id, excerpt: source.excerpt })) },
    sources,
    limitations: ["Search output is provider-supplied evidence; no independent source verification or additional synthesis was performed."],
  };
}

async function defaultClientFactory({ apiKey, fetchImpl, timeoutMs, signal }) {
  const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
  const client = new Client({ name: "lakewest-research", version: "1.0.0", listMaxPages: 2 });
  const transport = new StreamableHTTPClientTransport(new URL(TAVILY_ENDPOINT), createTransportOptions(apiKey, { fetchImpl, timeoutMs, signal }));
  try {
    await client.connect(transport);
    return client;
  } catch (error) {
    try { await client.close(); } catch { /* cleanup after a failed handshake */ }
    throw error;
  }
}

function createTransportOptions(apiKey, { fetchImpl = globalThis.fetch, timeoutMs = MAX_TIMEOUT_MS, signal } = {}) {
  if (typeof apiKey !== "string" || apiKey.trim() === "") throw new McpWorkflowError("PROVIDER_DISABLED");
  return {
    fetch: createBoundedMcpFetch({ fetchImpl, timeoutMs, parentSignal: signal }),
    requestInit: { headers: { Authorization: `Bearer ${apiKey}` } },
    reconnectionOptions: { initialReconnectionDelay: 0, maxReconnectionDelay: 0, reconnectionDelayGrowFactor: 1, maxRetries: 0 },
    onInsufficientScope: "throw",
    maxStepUpRetries: 0,
  };
}

function createTavilyMcpManager({
  enabled = isLiveEnablementSatisfied(),
  clientFactory = defaultClientFactory,
  fetchImpl = globalThis.fetch,
  timeoutMs = MAX_TIMEOUT_MS,
  maxBytes = MAX_MCP_RESPONSE_BYTES,
  maxConcurrent = MAX_CONCURRENT_REQUESTS,
} = {}) {
  let active = 0;
  return {
    async search(question, { maxResults = 3, signal } = {}) {
      if (!enabled || !isSupportedRuntime() || (OFFLINE_ONLY_STAGE && clientFactory === defaultClientFactory)) {
        throw new McpWorkflowError("PROVIDER_DISABLED");
      }
      if (active >= maxConcurrent) throw new McpWorkflowError("CONCURRENCY_LIMIT");
      if (typeof question !== "string" || question.length < 1 || question.length > 1000 || !Number.isInteger(maxResults) || maxResults < 1 || maxResults > MAX_RESULTS) {
        throw new McpWorkflowError("INVALID_PROVIDER_RESPONSE");
      }
      active += 1;
      const controller = new AbortController();
      const operationSignal = combineSignals(signal, controller.signal);
      const timer = setTimeout(() => controller.abort(), Math.min(timeoutMs, MAX_TIMEOUT_MS));
      let client;
      try {
        const apiKey = process.env.TAVILY_API_KEY;
        if (typeof apiKey !== "string" || apiKey.trim() === "") throw new McpWorkflowError("PROVIDER_DISABLED");
        client = await clientFactory({ apiKey, endpoint: TAVILY_ENDPOINT, fetchImpl, timeoutMs, maxBytes, signal: operationSignal });
        const requestOptions = { signal: operationSignal, timeout: Math.min(timeoutMs, MAX_TIMEOUT_MS), maxTotalTimeout: Math.min(timeoutMs, MAX_TIMEOUT_MS) };
        const inventory = await client.listTools({}, requestOptions);
        validateInventory(inventory);
        const searchTool = inventory.tools.find((tool) => tool.name === TAVILY_SEARCH_TOOL);
        const searchSchema = searchTool.inputSchema;
        const args = { query: question.trim() };
        if (searchSchema.properties.search_depth) args.search_depth = "basic";
        if (searchSchema.properties.topic) args.topic = "general";
        if (searchSchema.properties.max_results) args.max_results = maxResults;
        const result = await client.callTool({ name: TAVILY_SEARCH_TOOL, arguments: args }, {
          ...requestOptions,
          // Prevent the SDK's header-mismatch recovery path from retrying a tool invocation.
          toolDefinition: { name: TAVILY_SEARCH_TOOL, inputSchema: searchSchema },
        });
        if (Buffer.byteLength(JSON.stringify(result), "utf8") > maxBytes) throw new McpWorkflowError("RESPONSE_TOO_LARGE");
        return result;
      } catch (error) {
        if (operationSignal.aborted) throw new McpWorkflowError("REQUEST_TIMEOUT");
        if (error instanceof McpWorkflowError) throw error;
        if (error?.category === "response_too_large" || error?.cause?.category === "response_too_large") throw new McpWorkflowError("RESPONSE_TOO_LARGE");
        if (error?.category === "tool_timeout" || error?.cause?.category === "tool_timeout") throw new McpWorkflowError("REQUEST_TIMEOUT");
        throw new McpWorkflowError("PROVIDER_UNAVAILABLE");
      } finally {
        clearTimeout(timer);
        try { await client?.close?.(); } catch { /* resource cleanup is best effort */ }
        active -= 1;
      }
    },
  };
}

module.exports = {
  TAVILY_ENDPOINT,
  TAVILY_SEARCH_TOOL,
  MAX_MCP_RESPONSE_BYTES,
  MAX_NORMALIZED_BYTES,
  MAX_TIMEOUT_MS,
  McpWorkflowError,
  isSupportedRuntime,
  isLiveEnablementSatisfied,
  createBoundedMcpFetch,
  createTransportOptions,
  validateToolSchema,
  validateInventory,
  safePublicUrl,
  normalizeSearchResult,
  createTavilyMcpManager,
};
