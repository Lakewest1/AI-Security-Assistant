const { isVerifiedSupabaseIdentity } = require("../auth/SupabaseAuth");

// Contexts are minted only after Supabase middleware verifies the bearer token
// and the server resolves the principal against this server-controlled map.
const trustedContexts = new WeakSet();
const ANONYMOUS_CONTEXT = Object.freeze({ capabilities: Object.freeze([]) });
const CONTEXT_TTL_MS = 5 * 60 * 1000;

function parseCapabilityAllowlist(value) {
  if (value === undefined || value === null || value === "") return Object.create(null);
  if (typeof value !== "string") return null;

  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;

  const grants = Object.create(null);
  for (const [principalId, capabilities] of Object.entries(parsed)) {
    if (!principalId.trim() || ["__proto__", "prototype", "constructor"].includes(principalId)) return null;
    if (!Array.isArray(capabilities) || capabilities.some((capability) =>
      typeof capability !== "string" || !capability.trim() || capability !== capability.trim()
    )) return null;
    grants[principalId] = [...new Set(capabilities)];
  }
  return grants;
}

function createRequestCapabilityResolver({ allowlistJson = process.env.AGENT_CAPABILITY_ALLOWLIST } = {}) {
  // Invalid configuration disables grants for the entire process.
  const grants = parseCapabilityAllowlist(allowlistJson);
  return function getRequestCapabilityContext(request) {
    const identity = request?.auth;
    if (!isVerifiedSupabaseIdentity(identity) || !grants) return ANONYMOUS_CONTEXT;
    const capabilities = grants[identity.userId];
    if (!Array.isArray(capabilities) || capabilities.length === 0) return ANONYMOUS_CONTEXT;

    return createTrustedCapabilityContext({
      principalId: identity.userId,
      capabilities,
      expiresAt: Date.now() + CONTEXT_TTL_MS,
    }) || ANONYMOUS_CONTEXT;
  };
}

const getRequestCapabilityContext = createRequestCapabilityResolver();

function createTrustedCapabilityContext({ principalId, capabilities, expiresAt } = {}) {
  if (typeof principalId !== "string" || !principalId.trim()) return null;
  if (!Array.isArray(capabilities) || !capabilities.every((capability) => typeof capability === "string" && capability.trim())) return null;
  if (!Number.isFinite(expiresAt)) return null;

  const context = Object.freeze({
    principalId: principalId.trim(),
    capabilities: Object.freeze([...new Set(capabilities)]),
    expiresAt,
  });
  trustedContexts.add(context);
  return context;
}

function isTrustedCapabilityContext(context) {
  return Boolean(
    context &&
    trustedContexts.has(context) &&
    Number.isFinite(context.expiresAt) &&
    context.expiresAt > Date.now()
  );
}

module.exports = {
  createTrustedCapabilityContext,
  createRequestCapabilityResolver,
  getRequestCapabilityContext,
  isTrustedCapabilityContext,
  parseCapabilityAllowlist,
};
