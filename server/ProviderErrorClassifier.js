/**
 * ProviderErrorClassifier
 * 
 * Central authority for classifying provider errors.
 * Determines whether to:
 * - Fallback to next provider
 * - Retry same provider
 * - Stop fallback chain
 * 
 * This is the single source of truth for provider reliability decisions.
 */

class ProviderErrorClassifier {
  /**
   * Classify a provider error
   * 
   * @param {Error} error - The error thrown by provider
   * @returns {Object} Classification with fallback decision
   * 
   * {
   *   shouldFallback: boolean,
   *   category: string,
   *   retrySameProvider: boolean,
   *   stopFallbackChain: boolean,
   *   status: number,
   *   reason: string
   * }
   */
  static classify(error) {
    if (!error) {
      return {
        shouldFallback: true,
        category: 'unknown_error',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 500,
        reason: 'Unknown error'
      };
    }

    const status = error.status || error.statusCode || 500;
    const message = (error.message || '').toLowerCase();
    const errorCode = error.code || '';

    // ========== NETWORK ERRORS ==========
    if (this._isNetworkError(error, message, errorCode)) {
      return {
        shouldFallback: true,
        category: 'network',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 503,
        reason: 'Network error - provider unreachable'
      };
    }

    // ========== TIMEOUT ==========
    if (this._isTimeout(error, message, errorCode)) {
      return {
        shouldFallback: true,
        category: 'timeout',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 408,
        reason: 'Provider timeout'
      };
    }

    // ========== BILLING / CREDITS ==========
    if (this._isBillingError(message)) {
      return {
        shouldFallback: true,
        category: 'billing',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 402,
        reason: 'Provider billing issue - insufficient balance/credits'
      };
    }

    // ========== AUTHENTICATION ==========
    if (status === 401 || status === 403) {
      return {
        shouldFallback: true,
        category: 'authentication',
        retrySameProvider: false,
        stopFallbackChain: false,
        status,
        reason: `Provider authentication failed (${status})`
      };
    }

    // ========== MODEL NOT FOUND / UNAVAILABLE ==========
    if (this._isModelUnavailable(message, status)) {
      return {
        shouldFallback: true,
        category: 'model_unavailable',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 404,
        reason: 'Model not found or unavailable'
      };
    }

    // ========== RATE LIMITING ==========
    if (status === 429 || this._isRateLimit(message)) {
      return {
        shouldFallback: true,
        category: 'rate_limit',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 429,
        reason: 'Provider rate limited'
      };
    }

    // ========== SERVER ERRORS (5xx) ==========
    if (status >= 500 && status <= 599) {
      return {
        shouldFallback: true,
        category: 'server_error',
        retrySameProvider: false,
        stopFallbackChain: false,
        status,
        reason: `Provider server error (${status})`
      };
    }

    // ========== EMPTY RESPONSE ==========
    if (this._isEmptyResponse(message)) {
      return {
        shouldFallback: true,
        category: 'empty_response',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 502,
        reason: 'Provider returned empty response'
      };
    }

    // ========== MALFORMED RESPONSE ==========
    if (this._isMalformedResponse(message)) {
      return {
        shouldFallback: true,
        category: 'invalid_response',
        retrySameProvider: false,
        stopFallbackChain: false,
        status: 502,
        reason: 'Provider returned malformed response'
      };
    }

    // ========== OTHER 4xx ERRORS ==========
    if (status >= 400 && status < 500) {
      return {
        shouldFallback: true,
        category: 'client_error',
        retrySameProvider: false,
        stopFallbackChain: false,
        status,
        reason: `Provider client error (${status})`
      };
    }

    // ========== PROVIDER ERROR (UNKNOWN) ==========
    return {
      shouldFallback: true,
      category: 'provider_error',
      retrySameProvider: false,
      stopFallbackChain: false,
      status: 503,
      reason: error.message || 'Provider error'
    };
  }

  /**
   * Check if error is network-related
   */
  static _isNetworkError(error, message, errorCode) {
    const networkErrors = [
      'econnrefused',
      'econnreset',
      'enotfound',
      'etimedout',
      'ehostunreach',
      'network error',
      'fetch error',
      'connection error',
      'unable to connect',
      'unreachable',
      'offline',
      'dns failure',
      'connection refused',
      'connection reset'
    ];

    return networkErrors.some(err => 
      message.includes(err) || 
      errorCode.toLowerCase().includes(err.replace(' ', ''))
    ) || error.name === 'TypeError' && message.includes('fetch');
  }

  /**
   * Check if error is timeout-related
   */
  static _isTimeout(error, message, errorCode) {
    const timeoutErrors = [
      'timeout',
      'timed out',
      'aborted',
      'abort',
      'deadline exceeded',
      'time limit exceeded',
      'request timeout'
    ];

    return (
      timeoutErrors.some(err => message.includes(err)) ||
      error.name === 'AbortError' ||
      errorCode.toLowerCase().includes('timeout')
    );
  }

  /**
   * Check if error is billing/credit related
   */
  static _isBillingError(message) {
    const billingPatterns = [
      'insufficient balance',
      'insufficient credit',
      'insufficient funds',
      'no credit',
      'no credits',
      'credit balance',
      'out of credits',
      'billing',
      'payment required',
      'quota exceeded',
      'quota exhausted',
      'insufficient quota',
      'exceeded your current quota',
      'account suspended',
      'account is suspended',
      'account not active',
      'please add credits',
      'please add funds',
      'purchase credits',
      'credit limit',
      'balance is too low'
    ];

    return billingPatterns.some(pattern => message.includes(pattern));
  }

  /**
   * Check if error is model-related
   */
  static _isModelUnavailable(message, status) {
    const modelPatterns = [
      'model not found',
      'invalid model',
      'unknown model',
      'unsupported model',
      'model unavailable',
      'model is unavailable',
      'model retired',
      'model has been retired',
      'model no longer available',
      'does not exist',
      'not supported',
      'is not found',
      'not found for api version',
      'model_not_found',
      'invalid_model'
    ];

    return (
      modelPatterns.some(pattern => message.includes(pattern)) ||
      status === 404
    );
  }

  /**
   * Check if error is rate limiting
   */
  static _isRateLimit(message) {
    const rateLimitPatterns = [
      'rate limit',
      'too many requests',
      'quota',
      'throttled',
      'please retry after',
      'rate_limit',
      'requests per minute'
    ];

    return rateLimitPatterns.some(pattern => message.includes(pattern));
  }

  /**
   * Check if error is empty response
   */
  static _isEmptyResponse(message) {
    return message.includes('empty') && message.includes('response');
  }

  /**
   * Check if error is malformed response
   */
  static _isMalformedResponse(message) {
    const malformedPatterns = [
      'malformed',
      'invalid json',
      'json parse',
      'unexpected token',
      'parse error',
      'invalid response'
    ];

    return malformedPatterns.some(pattern => message.includes(pattern));
  }

  /**
   * Determine if error should stop the entire fallback chain
   * (very rare - only genuine application errors)
   */
  static shouldStopFallback(error) {
    // These are APPLICATION errors, not provider errors
    // Provider errors should always fallback

    if (!error) return false;

    const message = (error.message || '').toLowerCase();

    // Malformed request from frontend
    if (error.isClientError || error.status === 400) {
      // But only if it's clearly our fault
      if (message.includes('invalid message') ||
          message.includes('missing messages') ||
          message.includes('invalid role') ||
          message.includes('oversized')) {
        return true;
      }
    }

    // Client explicitly cancelled
    if (error.name === 'AbortError' && error.isUserCancellation) {
      return true;
    }

    return false;
  }
}

module.exports = ProviderErrorClassifier;