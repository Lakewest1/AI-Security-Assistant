# Lakewest AI Local Security Verification

**Scope:** Local source and offline-test review of the active backend `server/agent-server.js`, the canonical tool execution path, the React client auth lifecycle, and the locally built Vite bundle. No live provider, scan, internal service, metadata endpoint, or production log was accessed. Stage 2H.23 updated the AI-provider timeout lifecycle and oversized-response fallback classification as documented below; it did not change provider request payloads or external behavior for ordinary failures.

## Checklist

- [x] Enumerated application `fetch` call sites, configured fetch destinations, DNS-related code, and URL/IP normalization.
- [x] Traced registered security tools through `ToolRegistry`, `ToolValidator`, `ToolPolicy`, `AgentLoop`, `AgentOrchestrator`, the active `/api/agent` handler, and `AgentAuditLogger`.
- [x] Reviewed HIBP and tools accepting URLs, domains, IP addresses, and email addresses; reviewed credential placement and error paths.
- [x] Inspected frontend environment access and scanned the successful production bundle for common server credential identifiers and high-confidence token prefixes. The scan did not print values and is not a general secret scanner.
- [x] Traced Supabase initialization, session restore, auth listener cleanup, refresh-on-401, logout, and `/api/agent` bearer verification.
- [x] Ran the current offline root suite and client build.
- [ ] Did not test DNS rebinding or redirect-to-private destinations by network simulation: there is no active user-URL fetch helper or DNS validation layer to exercise. These remain missing regression tests if a general fetch tool is introduced.
- [ ] Did not inspect hosting logs, production bundles, deployed environment configuration, provider retention terms, or production identity settings.

## Architecture and request flow

The active path is `client/src/App.jsx` → `client/src/lib/agentRequest.js` → `POST /api/agent` in `server/agent-server.js` → `requireAuthenticatedSupabaseUser` in `server/auth/SupabaseAuth.js` → the server-side capability resolver → `AgentOrchestrator` / `AgentLoop` → validation and policy → registered provider tools → provider adapters. The route returns a sanitized reply and investigation metadata. The legacy server files were not treated as active.

Tools execute through `AgentLoop` (`server/agent/AgentLoop.js`): it resolves a registered tool, validates its arguments, checks `ToolPolicy`, checks controller read-only constraints, and only then calls `tool.execute`. The active policy allows only `riskLevel: "read"`; it also denies approval-required tools. The Mozilla Observatory entry is write-risk, requires a capability, and requires approval, so the current active policy blocks it before its remote POST.

## SSRF and outbound request findings

### Confirmed source behavior

1. **No active tool uses the submitted URL as Lakewest's HTTP destination.** URLScan, Google Web Risk, URLhaus, PhishTank, and VirusTotal send a submitted indicator as query/body/path data to fixed provider hosts. Shodan, IPinfo, ViewDNS, SecurityTrails, HIBP, AbuseIPDB, Censys, and ThreatFox likewise build requests to fixed provider hosts. A submitted `http://127.0.0.1/...` or private IP can therefore be disclosed to the selected third-party provider, but the inspected active adapters do not directly connect Lakewest to that target. Relevant code includes `server/tools/external/provider-utils.js:21-45`, `server/tools/external/urlscan.js`, `google-web-risk.js`, `urlhaus.js`, `phishtank.js`, `virustotal.js`, `hibp.js`, `shodan.js`, `ipinfo.js`, `viewdns.js`, `securitytrails.js`, `censys.js`, `abuseipdb.js`, and `threatfox.js`.

2. **Historical finding — configurable feed destination and redirect behavior (pre-Stage 2H.11).** Earlier code read `PHISHING_DATABASE_FEED_URL` and fetched that value with default Fetch redirect behavior, making the path configuration-controlled and potentially SSRF-capable if an untrusted party could change the environment or redirecting feed. **Current code:** the variable is no longer read; `phishing-database.js` uses only an exact source-controlled HTTPS URL, rejects redirects with `redirect: 'error'`, aborts after the configured timeout (10s default), and caps streamed response bytes at 5 MiB. Offline tests cover approved/rejected URL cases, redirect responses, body limits, and malformed content. These are application-level mitigations, not complete SSRF protection: the runtime still resolves the fixed hostname and the application does not validate/pin DNS answers or enforce network egress restrictions.

3. **Submitted URLs are not normalized as safe public web destinations.** `normalizeHttpUrl` in `provider-utils.js:120-134` checks only HTTP(S), parseability, and length; it does not reject URL user-info, loopback/private/link-local IPs, IPv4-mapped IPv6, or internal hostnames. The accepted URL is sent to fixed external providers. `server/agent/Investigation.js:14-22` retains URL path and query in canonical target identity. This is not evidence of Lakewest-side SSRF in current read-only lookup adapters, but it means private indicators and query credentials can leave the application and that future direct fetching would be unsafe without a new validation design.

4. **Mozilla Observatory is a remote scan operation, currently blocked.** `server/agent-server.js:1070-1110` constructs a POST to the fixed Observatory API using the submitted hostname. This initiates a scan at the remote service; it is not a Lakewest fetch to the submitted host. Its tool contract is write-risk / capability-restricted / approval-required in `server/tools/external/mozilla-observatory.js`; active `ToolPolicy` permits only read risk and rejects approval-required operations. No live scan was sent. If enabled later, hostname scope, private/internal names, explicit user consent, and authorization must be resolved first.

5. **DNS behavior:** application source includes IP syntax checks via `net.isIP` and URL parsing via `new URL`, but no DNS lookup/resolution or post-resolution address validation was found in the active tool path. There is no implemented guard for A/AAAA answers, rebinding, alternate IPv4 encodings, IPv4-mapped IPv6, redirects to private IPs, or cloud metadata addresses. Those cases are not presently reachable through a Lakewest-controlled arbitrary-URL fetcher; they are untested and must be covered before one is added.

### Outbound request inventory

- Fixed provider destinations: VirusTotal, AbuseIPDB, URLScan, Shodan, IPinfo, Censys, SecurityTrails, Mozilla Observatory, ViewDNS, HIBP, Google Web Risk, URLhaus, ThreatFox, and PhishTank. The active registry includes canonical tools and compatibility aliases for Google Web Risk, URLhaus, Phishing.Database, and ThreatFox; aliases use the same fixed-provider implementations. The `phishtank_lookup` factory exists but was not shown among active registered tools in startup inventory.
- Source-controlled destination: Phishing.Database feed (`DEFAULT_FEED_URL` in `server/tools/external/phishing-database.js`); no request value or current environment variable selects the destination.
- AI provider SDK/network adapters: `server/providers/base.js`, `server/BaseProviderEnhanced.js`, and provider implementations under `server/providers/`; destinations are provider configuration endpoints, not user-supplied target URLs.
- Frontend calls: `App.jsx` calls configured `VITE_API_URL` routes for `/api/agent`, `/api/chat`, `/api/clear-conversation`, and `/api/security-report`. It does not fetch the user-supplied investigation target.
- Other outbound verification: `server/auth/SupabaseAuth.js` calls the configured Supabase project `/auth/v1/user` endpoint to verify bearer tokens.

`provider-utils.js` gives shared provider calls a timeout, defaults to one retry, and enforces a streamed response-byte limit. Stage 2H.16 applied it to security-tool providers. Stage 2H.21 also routes both AI-provider base classes and their adapters through the same bounded reader. The default is 2 MiB and `PROVIDER_MAX_RESPONSE_BYTES` can raise it only up to 10 MiB. Legacy raw-response streaming adapters use a byte-counting stream wrapper. Agent progress SSE is a separate server response containing the sanitized final reply.

## Sensitive data, logs, and responses

### Confirmed behavior

- Provider credentials are read server-side from environment variables in `server/agent-server.js` and tool constructors. Relevant names include `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`, `SHODAN_API_KEY`, `IPINFO_TOKEN`, `CENSYS_API_TOKEN`, `SECURITYTRAILS_API_KEY`, `VIEWDNS_API_KEY`, `HIBP_API_KEY`, `GOOGLE_WEB_RISK_API_KEY`, `URLHAUS_AUTH_KEY`, and `THREATFOX_AUTH_KEY`. `PHISHING_DATABASE_FEED_URL` was used by historical code but is ignored by the current source. Supabase server verification uses `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`. Client code reads only `VITE_API_URL`, `VITE_SUPABASE_URL`, and `VITE_SUPABASE_PUBLISHABLE_KEY`; the latter is intentionally publishable. `.gitignore` ignores `.env` files while allowing `.env.example`.
- The local production build succeeded. A non-disclosing scan found none of the checked server credential identifiers and none of the checked high-confidence secret-token patterns in generated JavaScript. This does not prove the bundle contains no arbitrary secret format or that a deployment build uses the same environment.
- `AgentAuditLogger` applies its recursive sanitizer before emitting reviewed audit payloads. Its current sanitizer redacts URL user-info credentials and configured sensitive query keys in URL text, masks email addresses, redacts secret-like field names, and omits request/config/response/body/data fields. Synthetic tests exercise audit and orchestrator paths, including malformed URL text. The earlier statement that this logger did not sanitize target values is historical and no longer describes the current implementation.
- The active route and orchestrator still pass target metadata to logging paths (`server/agent-server.js` and `server/agent/AgentOrchestrator.js`); reviewed audit/server calls sanitize those values before writing them. This protection is not global: direct `console` calls in provider adapters or other modules do not automatically use `AgentAuditLogger.sanitizeLogValue`. In particular, provider-controlled error detail in some adapter logs remains a separate review/remediation item. Do not infer that every console path is covered by the audit sanitizer.
- Censys non-success responses now return the fixed public message `Censys request failed` and log only a validated HTTP status and fixed internal category. Both diagnostic fields are primitive allowlisted values; their JSON size is capped at 128 bytes, and the regression checks the full captured log record stays within 256 bytes. Provider-controlled error fields and the requested IP are omitted from this path. The synthetic regression injects fake keys, bearer tokens, an email, and a long string and confirms none reach the result or log. This remediation is local to the Censys non-success path. Other direct adapter console calls, including ViewDNS tool error messages (`server/tools/external/viewdns.js`), do not inherit the `AgentAuditLogger` sanitizer and need separate review.
- HIBP validates email shape and maximum length and sends the exact address to HIBP in its lookup URL path (`server/tools/external/hibp.js`). Stage 2H.17 removes duplicate email fields from tool findings/evidence and masks duplicate stored-input copies in AgentLoop evidence. The address remains the investigation target/source attribution and is included in the user/agent context sent to the configured AI provider. No HIBP-specific raw-email console log was found; local audit values use the existing email sanitizer. Third-party retention is not established by source inspection.
- `server/agent-server.js` startup logs provider configured booleans and a configured provider's key length, not key values (`:1476-1482`). Health responses expose provider health/configuration status and model/provider labels, not credentials (`:2087-2108`). Auth middleware returns generic messages and does not echo bearer tokens. The `/api/security-report` and unexpected-error paths now pass errors through `sanitizeLogValue` before logging; this is verified by the synthetic logging regression test. Other direct console paths are not covered automatically.
- Browser auth errors are mapped to non-sensitive messages in `client/src/components/AuthControls.jsx`; no password, bearer token, or session payload is logged by the reviewed auth code. The account panel intentionally displays the signed-in account email.

### Logging and retention

Locally, source writes structured/plain-text messages through `console.log/info/warn/error`: startup/provider status, request IDs, chat intent and route, provider/tool names, durations/statuses, investigation target/coverage metadata, and selected provider error detail. There is no request-body logging middleware in the active server path. `AgentAuditLogger` writes to the console; no persistent audit database or application-controlled retention store was found in this path. Local terminal capture, hosting-provider log retention, backups, monitoring agents, and provider-side data retention cannot be determined from source code.

## Supabase refresh lifecycle (Stage 2H.10)

1. `client/src/lib/supabase.js` calls `createClient` once at module scope when valid Vite settings exist. `main.jsx` imports it for side effects and `App.jsx` imports the same ES module binding; module caching means those imports do not create separate clients.
2. `AuthControls.jsx` is the only reviewed caller of `subscribeToAuthState`. Its effect calls `onAuthStateChange` and requests `getSession`; cleanup deactivates the callback and unsubscribes (`client/src/lib/authState.js:1-22`). `main.jsx` wraps the app in React `StrictMode`. In development, StrictMode can run the effect setup/cleanup cycle an extra time; the prior listener is unsubscribed. The helper may issue a second local `getSession` read in that development cycle, but there is no evidence of multiple lasting listeners.
3. Login and logout call Supabase `signInWithPassword`, `signUp`, and `signOut` only in `AuthControls.jsx`. No app code manually persists tokens or invokes periodic `refreshSession`.
4. `App.jsx:2460-2490` aborts the previous chat request when a new request begins, then uses `fetchAgentRequest` for `/api/agent` only. That helper calls `getSession` to attach the current access token. It calls `refreshSession` only if the first HTTP response is 401, a token was attached, and the auth client supports refresh; it retries once. An HTTP 200 returns without an explicit refresh. Existing tests in `test/agent-request.test.js` cover 200 without refresh, one refresh/retry after 401, and refresh failure without exposing credentials.
5. The server checks `/api/agent` bearer tokens with `SupabaseAuth.js`; it does not refresh client sessions or return tokens. `/api/chat` is a separate public request path.

Supabase client creation does not override SDK token-refresh defaults. Periodic/near-expiry `/auth/v1/token?grant_type=refresh_token` requests are therefore consistent with the client SDK managing a persisted session. The user's reported successful `/api/agent` 200 responses do not trigger this helper's refresh branch. The most likely explanation for occasional successful refresh requests is normal SDK-managed refresh. This is an inference from the single client and code path; browser network timing and SDK internal scheduling were not independently captured.

No confirmed duplicate persistent client or auth listener was found. StrictMode can account for an extra mount-time session read/subscription setup in development, with cleanup; it is not evidence that it causes recurring refreshes. Multiple browser tabs can each run an SDK client against shared persisted session state; this app code does not coordinate tabs itself, and no multi-tab browser test or concurrent 401 race test exists. Concurrent `/api/agent` 401 responses could independently call `refreshSession` because `agentRequest.js` has no shared in-flight refresh promise, but this is a plausible race, not established as the observed cause. An expired session may also cause SDK work during session restoration; this path was not confirmed from network capture.

## Confirmed findings ranked by severity

### Medium

- **Historical — operator-controlled feed URL lacked SSRF protections (pre-Stage 2H.11).** This is not the current implementation. The current feed uses a fixed validated URL and refuses redirects; residual DNS and egress limitations are documented below.
- **Sensitive URL data is disclosed to provider APIs.** URL tool adapters send indicators to fixed provider endpoints, sometimes with full query/path data. Application log target values are sanitized by the Stage 2H.15 logger; provider disclosure and retention remain separate concerns.
- **HIBP email is sent to HIBP and remains in canonical investigation attribution.** Duplicate email fields in tool findings/evidence and stored AgentLoop input copies are minimized in Stage 2H.17. The exact target remains necessary to identify the investigated account and may be present in AI-provider context; external retention remains unverified.

### Low

- **Historical — provider response size was not bounded before parsing (pre-Stage 2H.16/2H.21).** Current security-tool and AI-provider adapter paths use the shared streamed byte limit. Other future direct fetch or SDK paths must be reviewed separately before claiming coverage.
- **Some provider credentials are placed in URL query strings.** Examples: Shodan (`shodan.js`), IPinfo (`ipinfo.js`), Google Web Risk (`google-web-risk.js`), and ViewDNS (`viewdns.js`). No local URL logging of these requests was found, so a leak is not confirmed. Query strings can be captured by outbound proxies/diagnostic systems; use provider-supported headers where available and keep URL logging disabled/redacted.
- **Whole error objects reach a local log on report-generation failure.** `server/agent-server.js:3559`. No secret was shown in the report-generation path, but sanitized error logging would reduce accidental disclosure risk.

### Informational

- **No request-controlled server-side fetch destination was found in the reviewed call sites.** Submitted indicators are sent as data to fixed provider hosts. There is no DNS resolver/address denylist in application code for the fixed feed host; this leaves infrastructure-level DNS and egress risks outside source-level controls and would need review before introducing any arbitrary-URL fetch feature.
- **Mozilla Observatory remains blocked by current policy.** No live remote scan was attempted.
- **No application-managed audit retention setting was found.** Hosting/monitoring retention is unknown.

## Missing tests

- Current mocked feed tests cover the fixed approved URL, invalid URL variants, redirect attempts (including private-address destinations), oversized responses, and malformed feed content. They do not test runtime DNS answers, DNS rebinding, IPv4-mapped DNS results, or actual egress/proxy enforcement; the current feed code has no DNS validation seam, and the URL is not request-configurable.
- Provider tests using synthetic URLs with user-info/query secrets and synthetic HIBP email values to assert: no sensitive values in captured logs/errors; expected values are disclosed only to the intended provider; response metadata contains only fields intentionally needed for reporting.
- Tests that prove provider credentials are never emitted in URL/headers/error output across all adapters; existing auth and Censys tests cover only specific cases.
- A test that rejects or redacts API keys in provider URL query strings where provider contracts permit header authentication.
- Bundle checks that compare production output against an approved set of public Vite variables and ensure server-only settings are absent. The local build check here used a limited identifier/prefix scan only.
- Auth-state integration tests with React StrictMode, overlapping 401 responses, multiple tabs, and real SDK scheduling mocked at the auth interface. Existing unit tests verify listener cleanup and the one-time 401 retry, but do not prove timing behavior in the browser.

## Deployment-only checks not performed

- Whether production is running the same source revision; whether an obsolete `PHISHING_DATABASE_FEED_URL` variable remains configured (current source ignores it); and the deployed `PHISHING_DATABASE_TIMEOUT_MS` value.
- Egress firewall/routing restrictions, DNS resolver integrity and answer policy, metadata endpoint blocking, proxy configuration/TLS inspection, outbound proxy redirect behavior, and whether outbound requests are logged. Application code refusing feed redirects does not establish these network controls.
- Production `VITE_*` values and generated bundle; server secret manager access policies and secret rotation.
- Hosting provider, reverse-proxy, CDN, error-monitoring, and log retention/access controls.
- Third-party retention and processing terms for HIBP email, investigation URLs/IPs/domains, AI prompts, and threat-intelligence requests.
- Production CORS/HTTPS settings, actual Supabase session expiry/refresh settings, multi-tab browser behavior, and whether deployed `client` and `server` versions match this working tree.
- Production logs. They were not accessed.

## Stage 2H.10 conclusion

The smallest next step is **no refresh-code change**: first capture a local browser network timeline with event timestamps and request initiators (without exporting headers or payloads) to correlate each refresh with session age, app startup, tab count, and preceding `/api/agent` status. If captures show multiple concurrent 401-triggered refreshes, add a shared in-flight refresh promise in `agentRequest.js` and an offline concurrency test. Keep Supabase automatic refresh enabled. No diagnostics were added in this audit.

## Verification results

- `npm test` — **130 passed, 0 failed** (root command: `node --test test/*.test.js server/tests/*.test.js`). The suite ran offline with its fixtures/mocks; no live AI or threat-intelligence requests were made by the test cases.
- `npm run build --prefix client` — **passed** with Vite 8.2.2. Vite emitted a non-fatal large-chunk warning for the main JavaScript bundle.
- Production bundle scan — **no checked server-credential identifiers and no checked high-confidence token patterns found**. This is a targeted check, not exhaustive secret scanning.
- `git diff --check` — passed with no whitespace errors. Git emitted existing LF-to-CRLF working-copy notices for pre-existing files; no changes were made to those files during this task.

## Recommended remediation order

1. Preserve the source-controlled feed URL, redirect refusal, timeout, and byte limit. Verify production egress/DNS/proxy controls; before adding any user-configurable fetch destination, design host/protocol/address validation and redirect-by-redirect controls with offline regression tests.
2. Redact URL credentials and sensitive query values from target/audit logs; preserve the sanitized indicator and investigation identifiers needed for evidence traceability.
3. Document and minimize third-party handling of submitted indicators and HIBP email; add synthetic data tests for logs, errors, provider boundaries, and returned metadata.
4. Cap provider response bytes and normalize whole-object error logging.
5. Investigate the refresh initiator with a sanitized local browser timeline. Only add refresh de-duplication if the capture demonstrates overlapping 401-driven refresh calls.

## Stage 2H.11 remediation update

The feed-fetch finding above describes the pre-Stage 2H.11 implementation. Stage 2H.11 removed `PHISHING_DATABASE_FEED_URL` configurability, fixed the feed to the source-controlled HTTPS URL on `raw.githubusercontent.com`, disabled redirects, and added a 5 MiB streaming response limit before parsing. Offline tests cover the approved destination, rejected URL variations, redirect responses, oversized bodies, and malformed content. Redirect refusal does not remove DNS resolution: the runtime still resolves the fixed hostname, and no DNS pinning/address validation or egress policy is established by this source. Thus Stage 2H.11 mitigates the previously configurable/redirectable path but does not claim complete SSRF protection.

## Stage 2H.18 — Current SSRF and egress status

The current feed protections were rechecked directly in `phishing-database.js` and the active server registration; no code discrepancy was found, so this stage makes documentation-only changes. Review of server `fetch()` call sites found no user-submitted URL used as the HTTP destination. Tool indicators appear in request data sent to fixed provider hosts. AI-provider endpoints and `SUPABASE_URL` are server configuration, not request-selected destinations; their production values and network routes are not verified here. A fixed feed hostname can still be affected by deployment DNS, proxy, routing, host, or provider/CDN compromise. Production outbound allowlists, resolver protections, proxy behavior, metadata blocking, and the deployed environment/source revision remain unverified.

## Stage 2H.19 — Safe archive policy and verification

`scripts/create-safe-archive.py` includes eligible files from the working tree, whether tracked, modified, or untracked. It excludes repository metadata, dependency/build/cache/coverage/log/temp directories and files, real `.env` variants, common private-key and local credential files, and archive/compiled artifacts. `.env.example` and other explicitly template-suffixed files are allowed; filename exclusions are path-specific so ordinary source names containing words such as `build` or `cache` are retained. Symlinks are not followed or archived. The script requires an explicit output path outside the source tree, refuses an existing destination, builds a temporary ZIP beside the destination, independently validates the completed ZIP member paths and content, and only then publishes it without overwriting a concurrently created destination. `--check-only` scans eligible candidate files without producing an archive.

ZIP validation does not extract members. It rejects absolute, drive-prefixed, traversal, noncanonical separator, prohibited, and symlink-member paths. A narrow in-memory scan checks for selected private-key headers and common cloud/source-control/chat token forms in eligible files, plus non-placeholder credential assignments in configuration-like files. Findings report only a relative path and rule identifier; matched values are never reported or persisted. The scan is intentionally incomplete: a passing archive check does not prove that all secrets or sensitive data are absent, nor does it establish the provenance or safety of every included file. Synthetic offline tests cover prohibited paths, separator/traversal variants, environment-file exceptions, filename false positives, secret-finding output, and output/failure behavior. The missing historical archive script and its exact policy were not recovered or inferred.

## Stage 2H.21 — AI-provider response-byte limits

The active agent imports the six adapters from `server/providers-updated.js`, which extends `BaseProviderEnhanced`; the separate six adapter modules under `server/providers/` extend `server/providers/base.js` and are used by fallback/legacy paths. Both bases use `readResponseBody` from `server/tools/external/provider-utils.js`, which counts streamed bytes before decoding and returning text for the existing JSON parsing logic. The shared default is 2 MiB, configurable through `PROVIDER_MAX_RESPONSE_BYTES` and capped at 10 MiB. Stage 2H.23 keeps each base's abort timer active from fetch initiation through buffered body consumption and releases it on completion/failure. Legacy raw-response streaming modes use a bounded stream and retain the timeout until consumption/cancellation; active `/api/agent` progress streaming remains separate from provider streaming.

Offline tests exercise successful parsing through all twelve adapter classes, oversize rejection through each class, byte-limit cancellation for each legacy raw-stream adapter, stalled-body timeouts, and timer cleanup after successful consumption. The protection applies only to the reviewed fetch-based provider adapters that call these base methods; it does not establish limits for future direct `fetch`, SDK-managed response paths, or third-party infrastructure. Oversized AI responses are classified as non-fallback errors and stop the automatic fallback chain; ordinary transient provider failures retain fallback behavior. The 2 MiB/10 MiB byte ceiling does not separately cap records after parsing.

