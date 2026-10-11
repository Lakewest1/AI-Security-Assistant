/**
 * Base Provider Adapter
 * All providers extend this class
 */
const { readResponseBody, limitResponseStream, createResponseTimeout, finishResponseTimeout } = require("../tools/external/provider-utils");

class BaseProvider {
  constructor(config) {
    this.name = config.name;
    this.apiKey = config.apiKey;
    this.url = config.url;
    this.type = config.type;
    this.models = config.models;
    this.routePriority = config.routePriority;
    this.isFallbackOnly = config.isFallbackOnly || false;
    this.maxResponseBytes = config.maxResponseBytes;
  }

  async readResponseText(response) {
    if (!response?.body) {
      finishResponseTimeout(response);
      return "";
    }
    return readResponseBody(response, {
      parse: "text",
      maxBytes: this.maxResponseBytes,
    });
  }

  limitResponseStream(response) {
    return limitResponseStream(response, { maxBytes: this.maxResponseBytes });
  }

  /**
   * Normalize error for consistent handling
   */
  normalizeError(error) {
    const normalized = new Error(error.message || "Provider error");
    normalized.status = error.status || error.statusCode || 500;
    normalized.provider = this.name;
    if (error.category) normalized.category = error.category;
    normalized.originalError = error;
    return normalized;
  }

  /**
   * Check if error is transient (should fallback)
   */
  isTransientError(error) {
    const status = error?.status;
    if (!status) return true; // Network errors
    if (status === 408 || status === 429) return true;
    if (status >= 500 && status <= 599) return true;
    return false;
  }

  /**
   * Fetch with timeout
   */
  async fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const effectiveTimeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 10000;
    const timeout = createResponseTimeout(controller, effectiveTimeoutMs);
    
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      timeout.bind(response);
      return response;
    } catch (error) {
      timeout.finish();
      if (error.name === "AbortError") {
        const timeoutError = Object.assign(new Error("Provider request timed out"), {
          status: 408,
          code: "TIMEOUT",
          category: "tool_timeout",
        });
        throw this.normalizeError(timeoutError);
      }
      throw this.normalizeError(error);
    }
  }
}

module.exports = BaseProvider;
