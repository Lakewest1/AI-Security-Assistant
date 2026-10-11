# Lakewest tool contract (Stage 2C)

This document records the current implementation and proposes a shared contract for future tools. Proposed fields are not all implemented by the current registry.

## Current implementation

`server/agent/ToolRegistry.js` stores tools by stable `name`. A registered tool must be an object with a string `name` and an `execute(input, context)` function. It normalizes `description`, `inputSchema` (or `input_schema`), `category`, `targetTypes`, `riskLevel` (`read`, `write`, or `destructive`), `requiresApproval`, `requiredCapability`, `timeout`, and `retryable`. Defaults are permissive metadata defaults (`riskLevel: read`, empty schema, `retryable: true`); tools should therefore always specify their input schema and risk explicitly. Provider definitions expose only name, description, input schema, and required capability.

`ToolValidator` accepts a plain object and checks required fields, unknown fields when `additionalProperties: false`, direct property types, string length/pattern/IPv4, enum, and custom field validators. It is a limited schema validator, not full JSON Schema validation (notably nested values are not recursively validated).

`ToolPolicy` defaults to allowing only `read` risk. It denies risks outside its allow-list, denies a missing/untrusted/expired context or an ungranted `requiredCapability`, and denies every `requiresApproval` tool (there is no approval workflow here). Controller execution independently requires `riskLevel === read`. Security lookups remain read-risk and do not set `requiredCapability`; `mozilla_observatory_scan` is the exception: it is a remote scan action, declares `riskLevel: write`, requires `security_remote_scan`, and sets `requiresApproval: true`. The active server policy allows only read-risk operations, and there is no scan consent/approval workflow, so Observatory remains disabled even for an authenticated user or allowlisted capability holder.

The active `server/agent-server.js` verifies the bearer token on `/api/agent` with the Supabase Auth user endpoint (`server/auth/SupabaseAuth.js`). Middleware stores a frozen identity object that is privately branded in a `WeakSet`; a request-created `{ userId }` object is not trusted. Authentication alone grants no capability. `server/agent/CapabilityContext.js` resolves the verified user ID against the server-only `AGENT_CAPABILITY_ALLOWLIST` JSON map, then issues a five-minute trusted context. The unset/empty default grants nothing. Invalid JSON or malformed entries disable the entire allowlist (fail closed). Example syntax is `{"<verified-supabase-user-id>":["web_search"]}`. The map must be maintained only by trusted server/deployment operators; do not source it from a request, frontend state, email, Supabase user metadata, or a user-controlled endpoint. The current registered tools do not declare `requiredCapability`, so no tool currently consumes an allowlist grant. No capability is granted by default.

Current authorization inventory: registered Security lookup IDs and aliases are read-risk, do not require explicit capabilities, and do not require approval. They access external provider APIs; HIBP accepts sensitive email input. URLScan performs a historical-result GET lookup. Mozilla Observatory is a write-risk remote scan action, requires the exact `security_remote_scan` capability, and is marked approval-required. It remains denied by the active read-only policy and the absence of an approval workflow. `ToolPolicy` checks exact `requiredCapability` against an unexpired branded context when declared, and denies approval-required tools. AgentLoop applies validation and the policy before execution for model-proposed and controller-required calls. Controller execution additionally requires `riskLevel === read`.

`AgentLoop` validates before policy and executes only after both pass. Unknown tools produce `UNKNOWN_TOOL`; invalid input produces `INVALID_TOOL_ARGUMENTS`; policy denial produces `TOOL_DENIED`. Execution is raced against the lower of the configured tool timeout and remaining agent deadline. The race bounds the agent's wait but does not cancel an arbitrary tool promise; implementations that perform I/O need their own abort/cancellation handling. Default controls are 10 seconds per tool, 45 seconds per agent, 12 calls, 3 repeated calls per tool, and 12,000 serialized result characters (environment-overridable). Repeated successful identical calls reuse evidence. Tool failures are converted to evidence error codes including `TIMEOUT`, `RATE_LIMITED`, `AUTHORIZATION_FAILED`, `UPSTREAM_ERROR`, and `TOOL_EXECUTION_FAILED`.

Successful provider outputs are preserved as `evidence.output`; the outer evidence also carries `ok`, investigation/request IDs, tool/call IDs, validated input, error, start/completion timestamps, duration, fingerprint, and controller-execution flag. Tool-result content is serialized for the model. Security investigation normalization consumes this evidence and retains provider-specific findings/provenance; the shared contract must not flatten those domain fields.

## Proposed contract for new tools

```js
{
  name,                 // stable, unique identifier
  displayName,          // proposed, human-readable
  description,
  inputSchema,          // object schema; server-side validation required
  category,
  targetTypes,
  riskLevel,            // read | write | destructive
  requiredCapability,   // explicit permission; fail closed when absent
  requiresApproval,
  timeout,              // finite positive milliseconds
  resourceLimits,       // proposed: response bytes, memory, calls, etc.
  externalNetwork,      // proposed explicit declaration
  handlesSensitiveData, // proposed explicit declaration
  externalSideEffects,  // proposed explicit declaration
  execute(input, context)
}
```

The executor receives only validated input and an explicit, scoped context (request identity, granted capabilities, deadline/signal, and approved workspace scope as applicable). It must not receive unrestricted environment secrets or arbitrary server access. Authorization is checked before execution. Limits must be enforced at the execution boundary; a timeout must cancel work where the implementation supports cancellation.

The proposed stable outer result is `{ ok, status, data, error, provenance }`. `status` distinguishes `success`, `partial`, `invalid_arguments`, `permission_denied`, `timeout`, `cancelled`, `rate_limited`, `unavailable`, and `execution_error`. `error` contains a safe stable code, bounded message, and retryability; `data` remains tool-specific. `provenance` retains source URLs/provider, collection timestamps, and evidence references. The current loop uses existing provider envelopes directly, so adoption requires a thin boundary adapter that preserves current evidence and Security behavior; this proposal does not change those existing envelopes.

## Existing Security-tool compatibility

Current names below are the registered identifiers in `server/agent-server.js`. Aliases share an implementation. All are classified `read`; their provider-specific inputs and output shapes remain intact. The registry does not enforce `externalNetwork`, sensitive-data, side-effect, or resource-limit metadata because those fields do not yet exist.

| Provider / current IDs | Contract fit | Compatibility note |
|---|---|---|
| VirusTotal: `virustotal_ip_lookup`, `virustotal_domain_lookup`, `virustotal_url_lookup` | Core executor/schema/risk fields present | Domain and URL IDs are thin registration adapters over the domain endpoint; IP implementation is separate. Provider envelope/evidence must be preserved. |
| AbuseIPDB: `abuseipdb_ip_lookup` | Core fields present | Existing IP schema and provider status/output shape remain authoritative. |
| URLScan: `urlscan_lookup` | Core fields present | External network lookup; retain existing URL and evidence fields. |
| Shodan: `shodan_ip_lookup` | Core fields present | External network lookup; retain provider-specific host data. |
| IPInfo: `ipinfo_ip_lookup` | Core fields present | External network lookup; retain its result shape. |
| Censys: `censys_ip_lookup` | Core fields present | Requires token and organization configuration; no shared result remapping. |
| SecurityTrails: `securitytrails_lookup` | Core fields present | External network lookup; preserve DNS/provider evidence. |
| Mozilla Observatory: `mozilla_observatory_scan` | Core fields present; server-side request adapter | Adapter adjusts request construction while preserving result/status shape. |
| ViewDNS: `viewdns_lookup` | Core fields present | External network lookup; preserve existing lookup-specific fields. |
| HIBP: `hibp_email_lookup` | Core fields present | Handles sensitive email input; access policy and retention need explicit treatment in the future metadata. |
| Google Web Risk: `google-web-risk`, `google_web_risk_lookup` | Core fields present; alias and response adapter | Factory ID is `google_web_risk_lookup`; canonical registry ID is renamed `google-web-risk`; both registrations share execution. |
| URLhaus: `urlhaus`, `urlhaus_lookup` | Core fields present; alias | Factory ID is `urlhaus_lookup`; canonical registry ID is renamed `urlhaus`; aliases share execution. |
| Phishing.Database: `phishing_database`, `phishing_database_lookup` | Core fields present; alias | Factory ID is `phishing_database`; alias is registered as `phishing_database_lookup`; schema permits an empty object, then execution returns an `ok: true` envelope with `status: error` for a missing target. Preserve feed provenance and refresh behavior. |
| ThreatFox: `threatfox`, `threatfox_lookup` | Core fields present; alias | Factory ID is `threatfox_lookup`; canonical registry ID is renamed `threatfox`; aliases share execution. |

The imported PhishTank factory is not registered in the canonical registry and is not counted as an available tool. No adapter is required for the current shared execution path; the future outer result should be introduced through a compatibility adapter and tested against existing evidence fixtures before migration.

## Future capability boundaries

* Web search: read-only user-facing action, but external network and provider cost require explicit capability, bounded query/result count, and safe attribution.
* Page fetch: external network, untrusted content, SSRF exposure, redirects and response bytes must be bounded; resolve/check addresses and re-check redirects at the fetch boundary.
* Code analysis/generation: model-produced text is not execution. Keep workspace access and code execution as separate capabilities.
* Sandboxed code execution: high-risk execution capability with isolated process/container, CPU/memory/time/filesystem limits, no ambient secrets, and network disabled unless separately granted.
* Image generation: external provider cost and outbound prompt/data transfer; enforce capability, quota, timeout and content limits.
* Artifact creation: filesystem write side effect; restrict writes to an approved workspace path, bound size and lifetime, and require an explicit write capability.

Read-only metadata alone is not authorization for network access, sensitive-data handling, provider charges, code execution, or file creation. Each needs an explicit permission and a boundary-specific resource policy.
