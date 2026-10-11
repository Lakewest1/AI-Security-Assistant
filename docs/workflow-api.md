# Workflow API foundation

## Endpoint

`POST /api/workflows` accepts a versioned JSON request. It is a separate endpoint and does not route to `/api/chat` or `/api/agent`.

```json
{
  "schemaVersion": 1,
  "mode": "research",
  "input": "A user-provided workflow request",
  "options": {}
}
```

`schemaVersion` must equal `1`. `mode` must be one of `research`, `code`, `build`, or `structure_learn`. `input` is a non-empty string of at most 12 KiB in UTF-8. `options` is optional and must be a JSON object with a maximum serialized size of 16 KiB, nesting depth of 8, and 512 total values. Unknown top-level fields are rejected. The shared JSON parser also rejects request bodies over 1 MiB. Research further allows only `maxResults` (1–5), `containsPersonalData`, and `containsConfidentialData`; question length is capped at 1,000 characters and 2 KiB UTF-8.

All workflow requests pass a workflow-specific in-memory limiter (20 requests per 15 minutes per client IP by default), then require the existing Supabase Bearer authentication. Authentication failures use the existing authentication response; rate-limit errors use the versioned workflow envelope. The limiter is per-process and relies on Express `req.ip`; it does not provide a shared or per-user quota. The server configures one trusted proxy hop, which must be checked against the actual Render proxy/origin configuration before relying on IP-based limits.

## Current contract

Code, Build, and Structure Learn requests receive HTTP `501` and this response envelope shape. Research behavior is described below and in the Research security guide.

```json
{
  "schemaVersion": 1,
  "mode": "code",
  "status": "not_implemented",
  "result": null,
  "sources": [],
  "limitations": [
    "The requested workflow is not implemented. No workflow execution or external source retrieval occurred."
  ],
  "metadata": {
    "requestId": "server-generated-id",
    "executionStatus": "not_started"
  }
}
```

Research uses a two-step backend confirmation lifecycle. First, authenticated `POST /api/workflows/research/prepare` accepts `{ "query": "...", "options": {} }`, screens the query, and returns a preview containing the exact trimmed query, provider, result count, random confirmation ID, and expiry. Preparation never contacts a provider. Then authenticated `POST /api/workflows/research/confirm` requires `{ "confirmationId": "...", "query": "...", "provider": "Tavily", "confirmed": true }`. The server binds the ID to the verified Supabase user, exact query, provider, options, and expiry; a successful match consumes it before calling the Research handler. IDs are single-use, expire after five minutes, and cannot be redeemed by another user or with changed fields. The ordinary `POST /api/workflows` Research form cannot invoke execution directly and returns `RESEARCH_CONFIRMATION_REQUIRED`.

Confirmation records are held in a bounded process-local store (1,000 pending records maximum). They are not persisted or shared across instances; restarts and requests routed to another instance invalidate/lose pending confirmations. The client must present the preview and obtain explicit user action; a client boolean alone does not authorize a query. Pattern screening rejects recognizable sensitive indicators but cannot prove that a query is safe. The hard offline-only gate still causes a valid confirmation to return provider-disabled without a Tavily connection. Request bodies and confirmation IDs are not logged by these routes. See [Research MCP security and status](research-mcp.md).

## Later phases

Future work may enable live Research only after production runtime and provider data-handling review, then implement a separately approved synthesis step. This API does not change the `/api/chat` contract or the `/api/agent` Security Investigation flow. It adds no persistence or generated-file execution.
