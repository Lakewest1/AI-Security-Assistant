function isAllowedOrigin(origin, { allowedOrigins = [], nodeEnv = process.env.NODE_ENV || "development" } = {}) {
  if (allowedOrigins.includes(origin)) return true;
  if (nodeEnv !== "development" || typeof origin !== "string") return false;

  try {
    const parsed = new URL(origin);
    return parsed.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname) &&
      !parsed.username && !parsed.password &&
      parsed.pathname === "/" && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

module.exports = { isAllowedOrigin };
