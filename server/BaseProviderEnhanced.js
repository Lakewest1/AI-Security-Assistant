/**
 * Enhanced BaseProvider
 * 
 * All provider adapters extend this class.
 * Provides consistent error handling, timeouts, and logging.
 */

const ProviderErrorClassifier = require('./ProviderErrorClassifier');
const { readResponseBody, limitResponseStream, createResponseTimeout, finishResponseTimeout } = require('./tools/external/provider-utils');

class BaseProvider {
  constructor(config) {
    this.name = config.name;
    this.apiKey = config.apiKey;
    this.url = config.url;
    this.type = config.type;
    this.models = config.models || {};
    this.isFallbackOnly = config.isFallbackOnly || false;
    this.maxResponseBytes = config.maxResponseBytes;
  }

  async readResponseText(response) {
    if (!response?.body) {
      finishResponseTimeout(response);
      return '';
    }
    return readResponseBody(response, {
      parse: 'text',
      maxBytes: this.maxResponseBytes,
    });
  }

  limitResponseStream(response) {
    return limitResponseStream(response, { maxBytes: this.maxResponseBytes });
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

      if (error.name === 'AbortError' || controller.signal.aborted) {
        const timeoutError = Object.assign(new Error('Provider request timed out'), {
          code: 'TIMEOUT',
          status: 408,
          category: 'tool_timeout',
        });
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
    if (error.category) normalized.category = error.category;
    
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
