"use strict";

const { randomBytes } = require("node:crypto");

const DEFAULT_CONFIRMATION_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_PENDING_CONFIRMATIONS = 1000;
const CONFIRMATION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function createResearchConfirmationStore({
  ttlMs = DEFAULT_CONFIRMATION_TTL_MS,
  maxPending = DEFAULT_MAX_PENDING_CONFIRMATIONS,
  now = Date.now,
  createId = () => randomBytes(32).toString("base64url"),
} = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new TypeError("A positive confirmation TTL is required");
  if (!Number.isSafeInteger(maxPending) || maxPending < 1) throw new TypeError("A positive confirmation capacity is required");

  const records = new Map();

  function removeExpired(currentTime) {
    for (const [id, record] of records) {
      if (record.expiresAt <= currentTime) records.delete(id);
    }
  }

  return {
    prepare({ userId, query, provider, options = {} } = {}) {
      const currentTime = now();
      removeExpired(currentTime);
      if (records.size >= maxPending) return null;

      const id = createId();
      if (typeof id !== "string" || !CONFIRMATION_ID_PATTERN.test(id) || records.has(id)) return null;
      const expiresAt = currentTime + ttlMs;
      records.set(id, {
        userId,
        query,
        provider,
        options: Object.freeze({ ...options }),
        expiresAt,
      });
      return { id, expiresAt };
    },

    // This operation contains no await: lookup, exact binding checks, and
    // deletion happen atomically within one JavaScript turn before execution.
    consume({ id, userId, query, provider, confirmed } = {}) {
      if (typeof id !== "string" || !CONFIRMATION_ID_PATTERN.test(id) || confirmed !== true) return null;
      const record = records.get(id);
      if (!record) return null;
      if (record.expiresAt <= now()) {
        records.delete(id);
        return null;
      }
      if (record.userId !== userId || record.query !== query || record.provider !== provider) return null;

      records.delete(id);
      return { ...record, options: { ...record.options } };
    },

    get size() {
      removeExpired(now());
      return records.size;
    },
  };
}

module.exports = {
  DEFAULT_CONFIRMATION_TTL_MS,
  DEFAULT_MAX_PENDING_CONFIRMATIONS,
  CONFIRMATION_ID_PATTERN,
  createResearchConfirmationStore,
};
