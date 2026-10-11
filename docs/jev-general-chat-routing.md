# Jev general-chat routing

Jev routing is an optional server-side recommendation for the existing `/api/chat` route. It can return only `fast`, `balanced`, or `powerful`; the existing `FallbackEngine` continues to perform generation and provider failover. It does not add Research, Build, or Image workflows and is not called by `/api/agent`.

## Default and runtime gates

The integration is unavailable unless both `JEV_GENERAL_CHAT_ROUTING=true` and `JEV_ROUTING_RUNTIME_APPROVED=true` are set. Neither variable is set by this change. The second variable is an explicit deployment-runtime attestation: set it only after confirming that the backend runtime is Node.js 20 or newer. The SDK is loaded lazily and refuses use below Node 20. The root package still declares Node.js `>=18`; that metadata and deployment configuration were not changed.

The inspected local runtime was Node.js 26.10. The checked-in Netlify configuration pins Node.js 20 for the client build only. No checked-in CI runtime or backend deployment runtime declaration was found, so the production backend runtime remains unverified. Leave `JEV_ROUTING_RUNTIME_APPROVED` unset there until the backend runtime is confirmed; setting the main feature flag alone cannot enable Jev. `JEV_API_KEY` is preferred; the SDK's `TYPESAFE_API_KEY` name is also supported. Keep credentials server-side.

## Data sent and privacy gate

The adapter never sends user message text, conversation history, targets, findings, logs, provider responses, or investigation results. It scans all submitted message entries locally and fails closed for malformed or non-text messages, security-related intents, URLs, domains, IP addresses, email addresses, credential-like strings, log/evidence terms, and other ambiguous inputs. For an eligible request, it sends only a fixed feature object: a small allowlisted task-category list and a short/medium/long message-size bucket derived from the latest user message. Jev's recommendation is validated against the three existing general-chat routes and a minimum confidence threshold. Any error, invalid answer, or absent configuration leaves deterministic routing in place.

The gate is intentionally conservative and may bypass Jev for ordinary prompts that resemble indicators or security content. The transmitted feature categories and length bucket still disclose limited metadata about a general-chat request. This source-level review cannot establish TypeSafe AI's retention or processing practices.

## SDK request protections

The official `@typesafe-ai/sdk` package is pinned to 0.6.0. SDK logs are disabled, retries are set to zero, and request timeout is 2.5 seconds. A custom fetch implementation wraps every SDK response with the existing `limitResponseStream` helper, which counts streamed bytes, checks declared content length as an early rejection only, cancels oversized streams, and caps the body at 64 KiB. The SDK's current implementation clones and buffers responses; offline tests exercise the wrapper through the installed SDK, including exact-limit, misleading-length, oversized, malformed, and stalled-body cases. No Jev endpoint was contacted in these tests.

The limit bounds bytes accepted by the SDK body reader. The fetch implementation must deliver a stream chunk before the wrapper can count it, so one already-delivered or prefetched transport chunk may be allocated before cancellation; the cap does not bound all transient memory used inside the networking stack.

The feature remains disabled by default. This document does not authorize activation; do not enable it or send real user messages until activation and privacy review are explicitly approved.
