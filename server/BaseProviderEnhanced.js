/**
 * Enhanced BaseProvider
 * 
 * All provider adapters extend this class.
 * Provides consistent error handling, timeouts, and logging.
 */

const ProviderErrorClassifier = require('./ProviderErrorClassifier');

class BaseProvider {
  constructor(config) {
    this.name = config.name;
    this.apiKey = config.apiKey;
    this.url = config.url;
    this.type = config.type;
    this.models = config.models || {};
    this.isFallbackOnly = config.isFallbackOnly || false;
  }

  /**
   * Validate that provider is configured
   */
  isConfigured() {
    return !!this.apiKey;
  }

  /**
   * Fetch with timeout
   * 
   * Respects requestId for logging.
   * Enforces timeout to prevent one provider from consuming entire request budget.
   */
  async fetchWithTimeout(url, options, timeoutMs, requestId) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      return response;

    } catch (error) {
      clearTimeout(timeoutId);

      if (error.name === 'AbortError') {
        const timeoutError = new Error(
          `Request timed out after ${timeoutMs}ms`
        );
        timeoutError.code = 'TIMEOUT';
        timeoutError.status = 408;
        throw this.normalizeError(timeoutError);
      }

      throw this.normalizeError(error);
    }
  }

  /**
   * Normalize error for consistent handling across all providers
   * 
   * Preserves:
   * - status (HTTP status code)
   * - message (human readable error)
   * - originalError (for debugging)
   * - provider (which provider failed)
   * 
   * Does NOT expose:
   * - API keys
   * - Bearer tokens
   * - Authorization headers
   * - Sensitive request bodies
   */
  normalizeError(error) {
    if (!error) {
      return new Error('Unknown provider error');
    }

    const normalized = new Error(error.message || 'Provider error');
    
    // Preserve status
    normalized.status = 
      error.status || 
      error.statusCode || 
      error.status_code || 
      500;

    // Add provider info
    normalized.provider = this.name;
    
    // Preserve original error for logging
    normalized.originalError = error;

    // Don't expose sensitive data
    if (error.headers) {
      delete normalized.headers;
    }

    return normalized;
  }

  /**
   * Classify provider error for routing decision
   */
  classifyError(error) {
    return ProviderErrorClassifier.classify(error);
  }

  /**
   * Safely parse JSON response
   * Doesn't throw, returns null on parse failure
   */
  safeParseJson(text) {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  /**
   * Extract meaningful error message from provider response
   * Handles different error formats
   */
  extractErrorMessage(data, status) {
    if (!data) return `HTTP ${status}`;

    // OpenAI/DeepSeek/Groq format
    if (data.error?.message) {
      return data.error.message;
    }

    // Alternative error format
    if (data.error?.error?.message) {
      return data.error.error.message;
    }

    // Claude/Anthropic format
    if (data.error?.type && data.error?.message) {
      return `${data.error.type}: ${data.error.message}`;
    }

    // Gemini format
    if (data.error?.errors?.[0]?.message) {
      return data.error.errors[0].message;
    }

    // Generic error text
    if (typeof data.error === 'string') {
      return data.error;
    }

    // Message field
    if (data.message) {
      return data.message;
    }

    return `HTTP ${status}`;
  }

  /**
   * Log provider attempt
   * Safe - doesn't expose credentials
   */
  logAttempt(requestId, model, remaining) {
    console.log(
      `[${requestId}] Attempt: ${this.name} | model=${model} | remaining=${remaining}ms`
    );
  }

  /**
   * Log provider success
   */
  logSuccess(requestId, model, duration) {
    console.log(
      `[${requestId}] SUCCESS: ${this.name} | model=${model} | duration=${duration}ms`
    );
  }

  /**
   * Log provider failure
   */
  logFailure(requestId, model, classification, remaining) {
    console.log(
      `[${requestId}] FAIL: ${this.name} | model=${model} | ` +
      `category=${classification.category} | status=${classification.status} | ` +
      `fallback=${classification.shouldFallback} | remaining=${remaining}ms`
    );
  }

  /**
   * Abstract method - subclasses must implement
   */
  async call(messages, model, maxTokens, options = {}) {
    throw new Error(`${this.name} must implement call() method`);
  }
}

module.exports = BaseProvider;