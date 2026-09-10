/**
 * FallbackEngine
 * 
 * Core provider orchestration logic.
 * 
 * Responsibilities:
 * 1. Select providers for route (fast/balanced/powerful)
 * 2. Try each provider sequentially
 * 3. Stop on first success
 * 4. Fall back on provider failures
 * 5. Return 503 only when ALL configured providers have failed
 * 
 * CRITICAL CONTRACT:
 * IF AT LEAST ONE CONFIGURED PROVIDER SUCCEEDS:
 * - RETURN HTTP 200
 * 
 * ONLY return 503 when:
 * - Every configured provider failed
 * - No configured provider could be reached
 */

const ProviderErrorClassifier = require('./ProviderErrorClassifier');

class FallbackEngine {
  constructor(options = {}) {
    this.providers = options.providers || [];
    this.circuitBreakerPool = options.circuitBreakerPool;
    this.totalTimeoutMs = options.totalTimeoutMs || 55000;
    this.providerTimeoutMs = options.providerTimeoutMs || 10000;
  }

  /**
   * Call AI with full fallback support
   * 
   * @param {Array} messages - Chat messages
   * @param {String} route - 'fast', 'balanced', or 'powerful'
   * @param {Number} maxTokens - Max output tokens
   * @param {String} requestId - Request ID for logging
   * @param {Object} options - Additional options (stream, etc)
   * 
   * @returns {Object} Result with reply, provider, etc
   * @throws {Error} Only if:
   *   - All providers failed
   *   - Client cancelled request
   *   - Malformed client request
   */
  async callWithFallback(
    messages,
    route,
    maxTokens,
    requestId,
    options = {}
  ) {
    const requestStart = Date.now();
    const orderedProviders = this.getProvidersForRoute(route);

    // Validate we have at least one provider
    if (orderedProviders.length === 0) {
      const error = new Error('No AI providers configured');
      error.status = 503;
      error.isProviderExhaustion = true;
      throw error;
    }

    const attemptedProviders = [];
    let lastError = null;
    let lastClassification = null;

    // Try each provider
    for (const provider of orderedProviders) {
      // Check if we should skip this provider due to circuit breaker
      const shouldSkip =
        this.circuitBreakerPool &&
        !this.circuitBreakerPool.shouldAttempt(provider.name, route);

      if (shouldSkip) {
        console.log(
          `[${requestId}] SKIP: ${provider.name} (circuit breaker)`
        );
        continue;
      }

      // Calculate remaining budget
      const elapsed = Date.now() - requestStart;
      const remaining = this.totalTimeoutMs - elapsed;

      if (remaining <= 1500) {
        // Not enough time for another provider
        console.log(
          `[${requestId}] TIMEOUT: Request budget exhausted, ` +
          `${orderedProviders.length - attemptedProviders.length} ` +
          `providers remaining`
        );
        break;
      }

      attemptedProviders.push(provider.name);

      const model =
        provider.models[route] || 
        provider.models.balanced || 
        Object.values(provider.models)[0];

      const timeoutMs = Math.min(
        this.providerTimeoutMs,
        remaining
      );

      provider.logAttempt(requestId, model, remaining);

      try {
        const callStart = Date.now();

        const result = await provider.call(
          messages,
          model,
          maxTokens,
          {
            timeoutMs,
            requestId,
            ...options
          }
        );

        // Validate response has content
        if (!result?.reply?.trim()) {
          throw new Error('Empty provider response');
        }

        const duration = Date.now() - callStart;

        provider.logSuccess(requestId, model, duration);

        // Record success for circuit breaker
        if (this.circuitBreakerPool) {
          this.circuitBreakerPool.recordSuccess(provider.name, route);
        }

        // Return successful response
        return {
          ...result,
          attemptedProviders,
          fallbackUsed: attemptedProviders.length > 1,
          requestId
        };

      } catch (error) {
        // Client cancelled request
        if (error.name === 'AbortError' && options.isUserCancellation) {
          throw error;
        }

        // Normalize error
        const normalized = provider.normalizeError(error);
        
        // Classify error
        const classification = provider.classifyError(normalized);

        lastError = normalized;
        lastClassification = classification;

        provider.logFailure(
          requestId,
          model,
          classification,
          remaining - (Date.now() - requestStart)
        );

        // Record failure for circuit breaker
        if (this.circuitBreakerPool) {
          this.circuitBreakerPool.recordFailure(provider.name, route);
        }

        // If shouldFallback is false, stop the chain
        if (!classification.shouldFallback) {
          console.log(
            `[${requestId}] STOP: ${provider.name} error is not recoverable`
          );
          throw normalized;
        }

        // Continue to next provider
        console.log(
          `[${requestId}] FALLBACK: Trying next provider...`
        );
      }
    }

    // All configured providers failed
    console.log(
      `[${requestId}] EXHAUSTED: All ${attemptedProviders.length} ` +
      `providers failed`
    );

    const exhaustionError = new Error(
      'All configured AI providers failed'
    );
    exhaustionError.status = 503;
    exhaustionError.isProviderExhaustion = true;
    exhaustionError.attemptedProviders = attemptedProviders;
    exhaustionError.lastClassification = lastClassification;
    exhaustionError.originalError = lastError;

    throw exhaustionError;
  }

  /**
   * Get providers in order for this route
   * 
   * Respects provider priority and availability
   */
  getProvidersForRoute(route) {
    // Define provider order by route
    const providerOrder = {
      fast: [
        'Groq',
        'DeepSeek',
        'Gemini',
        'OpenAI',
        'Claude',
        'OpenRouter'
      ],
      balanced: [
        'DeepSeek',
        'Claude',
        'Gemini',
        'OpenAI',
        'Groq',
        'OpenRouter'
      ],
      powerful: [
        'OpenAI',
        'Claude',
        'Gemini',
        'DeepSeek',
        'Groq',
        'OpenRouter'
      ]
    };

    const order = providerOrder[route] || providerOrder.balanced;

    // Filter to configured providers only, maintain order
    return order
      .map(name => this.providers.find(p => p.name === name))
      .filter(p => p && p.isConfigured());
  }

  /**
   * Get health status of all providers
   * 
   * For /api/health endpoint
   */
  getHealthStatus() {
    const status = {
      healthy: false,
      providers: {}
    };

    for (const provider of this.providers) {
      const circuitState = this.circuitBreakerPool?.getBreaker(provider.name, 'balanced')?.state || 'UNKNOWN';
      
      status.providers[provider.name] = {
        configured: provider.isConfigured(),
        circuitState: circuitState
      };

      if (provider.isConfigured()) {
        status.healthy = true; // At least one provider configured
      }
    }

    return status;
  }

  /**
   * Get detailed diagnostic info
   * For debugging and monitoring
   */
  getDiagnostics() {
    const diagnostics = {
      totalTimeoutMs: this.totalTimeoutMs,
      providerTimeoutMs: this.providerTimeoutMs,
      providers: [],
      circuitBreakers: {}
    };

    for (const provider of this.providers) {
      diagnostics.providers.push({
        name: provider.name,
        configured: provider.isConfigured(),
        type: provider.type,
        isFallbackOnly: provider.isFallbackOnly,
        models: provider.models
      });
    }

    if (this.circuitBreakerPool) {
      diagnostics.circuitBreakers = 
        this.circuitBreakerPool.getAllStates();
    }

    return diagnostics;
  }
}

module.exports = FallbackEngine;