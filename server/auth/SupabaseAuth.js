"use strict";

const DEFAULT_TIMEOUT_MS = 5000;
const verifiedIdentities = new WeakSet();

function createVerifiedIdentity(userId) {
  const identity = Object.freeze({ userId });
  verifiedIdentities.add(identity);
  return identity;
}

function isVerifiedSupabaseIdentity(identity) {
  return Boolean(identity && verifiedIdentities.has(identity));
}

function authError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function parseBearerToken(header) {
  if (typeof header !== "string") return { error: "missing" };
  const match = /^Bearer ([^\s,]+)$/i.exec(header.trim());
  return match ? { token: match[1] } : { error: "malformed" };
}

function validProjectUrl(value) {
  try {
    const url = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    return (url.protocol === "https:" || (local && url.protocol === "http:")) &&
      !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function validPublishableKey(value) {
  return typeof value === "string" && /^sb_publishable_[A-Za-z0-9_-]+$/.test(value.trim());
}

function createSupabaseTokenVerifier({
  supabaseUrl = process.env.SUPABASE_URL,
  publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  return async function verifySupabaseAccessToken(accessToken) {
    if (!validProjectUrl(supabaseUrl) || !validPublishableKey(publishableKey)) {
      throw authError(503, "auth_not_configured", "Authentication verification is not configured.");
    }
    if (typeof fetchImpl !== "function") {
      throw authError(503, "auth_unavailable", "Authentication verification is unavailable.");
    }

    let response;
    try {
      response = await fetchImpl(`${supabaseUrl.replace(/\/$/, "")}/auth/v1/user`, {
        method: "GET",
        headers: {
          apikey: publishableKey,
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      throw authError(503, "auth_unavailable", "Authentication verification is unavailable.");
    }

    if (response.status === 401 || response.status === 403) {
      throw authError(401, "invalid_token", "The access token is invalid or expired.");
    }
    if (!response.ok) {
      throw authError(503, "auth_unavailable", "Authentication verification is unavailable.");
    }

    let user;
    try {
      user = await response.json();
    } catch {
      throw authError(503, "auth_unavailable", "Authentication verification returned an invalid response.");
    }
    if (!user || typeof user.id !== "string" || !user.id.trim()) {
      throw authError(503, "auth_unavailable", "Authentication verification returned an invalid response.");
    }

    // Keep only the stable principal identifier; do not trust request-supplied
    // identity, roles, email, or capability fields.
    return Object.freeze({ userId: user.id.trim() });
  };
}

function createSupabaseAuthMiddleware({ verifyAccessToken = createSupabaseTokenVerifier() } = {}) {
  return async function requireSupabaseUser(req, res, next) {
    const parsed = parseBearerToken(req.headers?.authorization);
    if (parsed.error) {
      return res.status(401).json({
        error: parsed.error === "missing" ? "Authentication required." : "A valid Bearer authorization header is required.",
        code: parsed.error === "missing" ? "missing_token" : "malformed_authorization",
      });
    }

    try {
      const identity = await verifyAccessToken(parsed.token);
      if (!identity || typeof identity.userId !== "string" || !identity.userId.trim()) {
        throw authError(401, "invalid_token", "The access token is invalid or expired.");
      }
      req.auth = createVerifiedIdentity(identity.userId.trim());
      return next();
    } catch (error) {
      const status = error?.status === 401 ? 401 : 503;
      const invalidToken = status === 401;
      return res.status(status).json({
        error: invalidToken ? "The access token is invalid or expired." : "Authentication verification is unavailable.",
        code: invalidToken ? "invalid_token" : "auth_unavailable",
      });
    }
  };
}

module.exports = {
  createSupabaseTokenVerifier,
  createSupabaseAuthMiddleware,
  parseBearerToken,
  isVerifiedSupabaseIdentity,
};
