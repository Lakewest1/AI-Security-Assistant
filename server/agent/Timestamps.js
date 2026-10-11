const MAX_FUTURE_MS = 10 * 365 * 24 * 60 * 60 * 1000;
const EARLIEST_VALID_MS = Date.UTC(2000, 0, 1);

/** Normalize provider timestamps (seconds, milliseconds, or ISO) to UTC. */
function normalizeTimestamp(value, { now = Date.now() } = {}) {
  if (value === undefined || value === null || value === "") return null;

  let milliseconds;
  if (typeof value === "number" || (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()))) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric <= 0) return null;
    milliseconds = Math.abs(numeric) < 1e12 ? numeric * 1000 : numeric;
  } else {
    milliseconds = Date.parse(value);
  }

  if (!Number.isFinite(milliseconds) || milliseconds < EARLIEST_VALID_MS || milliseconds > now + MAX_FUTURE_MS) return null;
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

module.exports = { normalizeTimestamp };
