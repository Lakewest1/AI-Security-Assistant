/**
 * Base Provider Adapter
 * All providers extend this class
 */
class BaseProvider {
  constructor(config) {
    this.name = config.name;
    this.apiKey = config.apiKey;
    this.url = config.url;
    this.type = config.type;
    this.models = config.models;
    this.routePriority = config.routePriority;
    this.isFallbackOnly = config.isFallbackOnly || false;
  }

  /**
   * Normalize error for consistent handling
   */
  normalizeError(error) {
    const normalized = new Error(error.message || "Provider error");
    normalized.status = error.status || error.statusCode || 500;
    normalized.provider = this.name;
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
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      return response;
    } catch (error) {
      if (error.name === "AbortError") {
        const timeoutError = new Error(`Request timed out after ${timeoutMs}ms`);
        timeoutError.status = 408;
        throw this.normalizeError(timeoutError);
      }
      throw this.normalizeError(error);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

module.exports = BaseProvider;