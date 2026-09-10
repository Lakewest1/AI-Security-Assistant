/**
 * CircuitBreaker
 * 
 * Optimization to avoid repeatedly calling known-broken providers.
 * 
 * CRITICAL: This is NOT the primary failure mechanism.
 * Circuit breaker state influences provider ordering/skipping.
 * But it MUST NEVER prevent fallback from trying a provider.
 * 
 * States:
 * CLOSED   - healthy, try immediately
 * OPEN     - broken, skip if cooldown hasn't expired
 * HALF_OPEN - testing after cooldown, one probe allowed
 */

const STATE = {
  CLOSED: 'CLOSED',
  OPEN: 'OPEN',
  HALF_OPEN: 'HALF_OPEN'
};

class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 3;
    this.successThreshold = options.successThreshold || 2;
    this.cooldownMs = options.cooldownMs || 30000; // 30 seconds
    
    // State: CLOSED, OPEN, HALF_OPEN
    this.state = STATE.CLOSED;
    
    // Counts
    this.failureCount = 0;
    this.successCount = 0;
    
    // When did we transition to OPEN?
    this.openedAt = null;
    
    // Half-open tracking
    this.halfOpenProbeInProgress = false;
  }

  /**
   * Check if we should attempt a provider
   * 
   * Returns true if provider should be tried.
   * Returns false if provider should be skipped (cooldown active).
   */
  shouldAttempt() {
    if (this.state === STATE.CLOSED) {
      return true; // Healthy, try it
    }

    if (this.state === STATE.OPEN) {
      const timeSinceOpen = Date.now() - this.openedAt;
      if (timeSinceOpen >= this.cooldownMs) {
        // Cooldown expired, try a controlled probe
        this.state = STATE.HALF_OPEN;
        this.halfOpenProbeInProgress = true;
        return true;
      }
      // Still in cooldown, skip
      return false;
    }

    if (this.state === STATE.HALF_OPEN) {
      // Already in probe, don't double-probe
      if (this.halfOpenProbeInProgress) {
        return false;
      }
      // Can try if previous probe completed
      return true;
    }

    return false;
  }

  /**
   * Record a successful call
   */
  recordSuccess() {
    this.failureCount = 0;
    
    if (this.state === STATE.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.reset();
      }
    } else if (this.state === STATE.CLOSED) {
      // Already closed, nothing to do
    }
  }

  /**
   * Record a failure
   */
  recordFailure() {
    this.failureCount++;
    
    if (this.state === STATE.HALF_OPEN) {
      // Probe failed, go back to OPEN
      this.state = STATE.OPEN;
      this.openedAt = Date.now();
      this.halfOpenProbeInProgress = false;
      this.successCount = 0;
    } else if (this.state === STATE.CLOSED) {
      if (this.failureCount >= this.failureThreshold) {
        // Threshold reached, open the circuit
        this.state = STATE.OPEN;
        this.openedAt = Date.now();
      }
    }
  }

  /**
   * Reset to CLOSED (healthy)
   */
  reset() {
    this.state = STATE.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.openedAt = null;
    this.halfOpenProbeInProgress = false;
  }

  /**
   * Get current state for debugging/monitoring
   */
  getState() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      openedAt: this.openedAt,
      cooldownExpiredAt: this.openedAt ? new Date(this.openedAt + this.cooldownMs) : null,
      timeSinceOpen: this.state === STATE.OPEN ? (Date.now() - this.openedAt) : null
    };
  }
}

/**
 * CircuitBreakerPool
 * 
 * Manages circuit breakers for all provider+model combinations
 */
class CircuitBreakerPool {
  constructor(options = {}) {
    this.breakers = new Map(); // key: "provider:model"
    this.options = options;
  }

  /**
   * Get or create a circuit breaker for this provider+model
   */
  getBreaker(provider, model) {
    const key = `${provider}:${model}`;
    if (!this.breakers.has(key)) {
      this.breakers.set(key, new CircuitBreaker(this.options));
    }
    return this.breakers.get(key);
  }

  /**
   * Check if provider+model should be attempted
   */
  shouldAttempt(provider, model) {
    const breaker = this.getBreaker(provider, model);
    return breaker.shouldAttempt();
  }

  /**
   * Record success
   */
  recordSuccess(provider, model) {
    const breaker = this.getBreaker(provider, model);
    breaker.recordSuccess();
  }

  /**
   * Record failure
   */
  recordFailure(provider, model) {
    const breaker = this.getBreaker(provider, model);
    breaker.recordFailure();
  }

  /**
   * Get state of all breakers
   */
  getAllStates() {
    const states = {};
    for (const [key, breaker] of this.breakers.entries()) {
      states[key] = breaker.getState();
    }
    return states;
  }

  /**
   * Get summary for health endpoint
   */
  getHealthSummary(providers) {
    const summary = {};
    for (const provider of providers) {
      summary[provider.name] = {};
      for (const [tier, model] of Object.entries(provider.models || {})) {
        const key = `${provider.name}:${model}`;
        const breaker = this.breakers.get(key);
        if (breaker) {
          summary[provider.name][tier] = breaker.state;
        }
      }
    }
    return summary;
  }
}

module.exports = { CircuitBreaker, CircuitBreakerPool, STATE };