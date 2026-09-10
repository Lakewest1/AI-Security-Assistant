/**
 * Provider Fallback Test Suite
 * 
 * Demonstrates that the system correctly:
 * 1. Falls back when providers fail
 * 2. Stops on first success
 * 3. Returns 503 only when all fail
 * 4. Handles different error types correctly
 */

const FallbackEngine = require('./FallbackEngine');
const { CircuitBreakerPool } = require('./CircuitBreaker');
const ProviderErrorClassifier = require('./ProviderErrorClassifier');
const BaseProvider = require('./BaseProviderEnhanced');

// ==========================================
// MOCK PROVIDER FOR TESTING
// ==========================================

class MockProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.responseType = config.responseType || 'success'; // 'success', 'billing', 'model', 'network', 'timeout'
    this.callCount = 0;
  }

  async call(messages, model, maxTokens, options = {}) {
    this.callCount++;

    switch (this.responseType) {
      case 'success':
        return {
          reply: `Response from ${this.name}`,
          provider: this.name,
          model,
          usage: null,
        };

      case 'billing':
        const billingError = new Error('Insufficient balance');
        billingError.status = 402;
        throw this.normalizeError(billingError);

      case 'model':
        const modelError = new Error('Model not found');
        modelError.status = 404;
        throw this.normalizeError(modelError);

      case 'network':
        const networkError = new Error('Connection refused');
        networkError.code = 'ECONNREFUSED';
        throw this.normalizeError(networkError);

      case 'timeout':
        const timeoutError = new Error('Request timeout');
        timeoutError.code = 'TIMEOUT';
        timeoutError.status = 408;
        throw this.normalizeError(timeoutError);

      case 'empty':
        return {
          reply: '', // Empty response
          provider: this.name,
          model,
          usage: null,
        };

      default:
        throw new Error('Unknown response type');
    }
  }
}

// ==========================================
// TEST SCENARIOS
// ==========================================

async function testScenario(name, providers, expectedProvider) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`TEST: ${name}`);
  console.log('='.repeat(60));

  const circuitBreakerPool = new CircuitBreakerPool();
  const engine = new FallbackEngine({
    providers,
    circuitBreakerPool,
    totalTimeoutMs: 30000,
    providerTimeoutMs: 5000,
  });

  const messages = [
    { role: 'system', content: 'You are helpful' },
    { role: 'user', content: 'Hello' },
  ];

  try {
    const result = await engine.callWithFallback(
      messages,
      'balanced',
      2000,
      'test-request'
    );

    console.log(`✅ SUCCESS`);
    console.log(`   Provider: ${result.provider}`);
    console.log(`   Reply: ${result.reply.substring(0, 50)}...`);
    console.log(`   Attempts: ${result.attemptedProviders.join(' → ')}`);
    console.log(`   Fallback used: ${result.fallbackUsed}`);

    if (result.provider !== expectedProvider) {
      console.log(`❌ ERROR: Expected ${expectedProvider}, got ${result.provider}`);
      return false;
    }

    return true;

  } catch (error) {
    if (error.isProviderExhaustion) {
      console.log(`✅ ALL PROVIDERS EXHAUSTED (Expected)`);
      console.log(`   Attempted: ${error.attemptedProviders.join(' → ')}`);
      console.log(`   Last error: ${error.originalError?.message}`);

      if (expectedProvider !== null) {
        console.log(`❌ ERROR: Expected success from ${expectedProvider}`);
        return false;
      }

      return true;

    } else {
      console.log(`❌ ERROR: ${error.message}`);
      return false;
    }
  }
}

// ==========================================
// RUN TESTS
// ==========================================

async function runAllTests() {
  console.log('\n' + '█'.repeat(60));
  console.log('PROVIDER FALLBACK TEST SUITE');
  console.log('█'.repeat(60));

  const results = [];

  // ==========================================
  // TEST A: DeepSeek fails (billing), Claude fails (billing), 
  //         Gemini fails (model), OpenAI fails (quota), Groq succeeds
  // ==========================================

  results.push(await testScenario(
    'A: Multiple providers fail, Groq succeeds',
    [
      new MockProvider({ name: 'DeepSeek', responseType: 'billing' }),
      new MockProvider({ name: 'Claude', responseType: 'billing' }),
      new MockProvider({ name: 'Gemini', responseType: 'model' }),
      new MockProvider({ name: 'OpenAI', responseType: 'timeout' }),
      new MockProvider({ name: 'Groq', responseType: 'success' }),
      new MockProvider({ name: 'OpenRouter', responseType: 'success' }),
    ],
    'Groq'
  ));

  // ==========================================
  // TEST B: All except OpenRouter fail, OpenRouter succeeds
  // ==========================================

  results.push(await testScenario(
    'B: All primary providers fail, OpenRouter succeeds',
    [
      new MockProvider({ name: 'DeepSeek', responseType: 'billing' }),
      new MockProvider({ name: 'Claude', responseType: 'billing' }),
      new MockProvider({ name: 'Gemini', responseType: 'model' }),
      new MockProvider({ name: 'OpenAI', responseType: 'network' }),
      new MockProvider({ name: 'Groq', responseType: 'timeout' }),
      new MockProvider({ name: 'OpenRouter', responseType: 'success' }),
    ],
    'OpenRouter'
  ));

  // ==========================================
  // TEST C: Single provider succeeds
  // ==========================================

  results.push(await testScenario(
    'C: Single provider configured, succeeds',
    [
      new MockProvider({ name: 'Groq', responseType: 'success' }),
    ],
    'Groq'
  ));

  // ==========================================
  // TEST D: Single provider fails
  // ==========================================

  results.push(await testScenario(
    'D: Single provider configured, fails → 503',
    [
      new MockProvider({ name: 'Groq', responseType: 'billing' }),
    ],
    null  // Expect failure
  ));

  // ==========================================
  // TEST E: DeepSeek succeeds immediately (no fallback)
  // ==========================================

  results.push(await testScenario(
    'E: First provider succeeds, no fallback needed',
    [
      new MockProvider({ name: 'DeepSeek', responseType: 'success' }),
      new MockProvider({ name: 'Claude', responseType: 'success' }),
      new MockProvider({ name: 'Gemini', responseType: 'success' }),
    ],
    'DeepSeek'
  ));

  // ==========================================
  // TEST F: All providers fail
  // ==========================================

  results.push(await testScenario(
    'F: All providers fail → 503',
    [
      new MockProvider({ name: 'DeepSeek', responseType: 'billing' }),
      new MockProvider({ name: 'Claude', responseType: 'network' }),
      new MockProvider({ name: 'Gemini', responseType: 'timeout' }),
    ],
    null  // Expect failure
  ));

  // ==========================================
  // SUMMARY
  // ==========================================

  console.log('\n' + '█'.repeat(60));
  console.log('TEST SUMMARY');
  console.log('█'.repeat(60));

  const passed = results.filter(r => r).length;
  const total = results.length;

  console.log(`\nPassed: ${passed}/${total}`);

  if (passed === total) {
    console.log('\n🎉 ALL TESTS PASSED');
    console.log('\nFallback system is working correctly:');
    console.log('✓ Providers fall back on failures');
    console.log('✓ System stops on first success');
    console.log('✓ Returns 503 only when all fail');
    console.log('✓ Handles billing failures correctly');
    console.log('✓ Handles model unavailable correctly');
    console.log('✓ Handles network errors correctly');
    console.log('✓ Handles timeouts correctly');
  } else {
    console.log('\n❌ SOME TESTS FAILED');
    process.exit(1);
  }
}

// ==========================================
// TEST ERROR CLASSIFIER
// ==========================================

async function testErrorClassifier() {
  console.log('\n' + '█'.repeat(60));
  console.log('ERROR CLASSIFIER TEST');
  console.log('█'.repeat(60));

  const testCases = [
    {
      name: 'Billing error (insufficient balance)',
      error: new Error('Insufficient balance'),
      error_status: 402,
      expect: { category: 'billing', shouldFallback: true },
    },
    {
      name: 'Billing error (no credits)',
      error: new Error('No credits available'),
      error_status: 402,
      expect: { category: 'billing', shouldFallback: true },
    },
    {
      name: 'Model not found',
      error: new Error('Model not found'),
      error_status: 404,
      expect: { category: 'model_unavailable', shouldFallback: true },
    },
    {
      name: 'Rate limiting',
      error: new Error('Rate limited'),
      error_status: 429,
      expect: { category: 'rate_limit', shouldFallback: true },
    },
    {
      name: 'Timeout',
      error: new Error('Request timeout'),
      error_status: 408,
      expect: { category: 'timeout', shouldFallback: true },
    },
    {
      name: 'Network error',
      error: new Error('ECONNREFUSED'),
      error_status: undefined,
      expect: { category: 'network', shouldFallback: true },
    },
    {
      name: 'Server error (500)',
      error: new Error('Internal server error'),
      error_status: 500,
      expect: { category: 'server_error', shouldFallback: true },
    },
  ];

  let passed = 0;

  for (const tc of testCases) {
    tc.error.status = tc.error_status;
    const classification = ProviderErrorClassifier.classify(tc.error);

    const categoryMatch = classification.category === tc.expect.category;
    const fallbackMatch = classification.shouldFallback === tc.expect.shouldFallback;

    if (categoryMatch && fallbackMatch) {
      console.log(`✅ ${tc.name}`);
      console.log(
        `   Category: ${classification.category}, ` +
        `Fallback: ${classification.shouldFallback}`
      );
      passed++;
    } else {
      console.log(`❌ ${tc.name}`);
      console.log(`   Expected: ${JSON.stringify(tc.expect)}`);
      console.log(`   Got: category=${classification.category}, fallback=${classification.shouldFallback}`);
    }
  }

  console.log(`\nClassifier tests: ${passed}/${testCases.length} passed`);

  return passed === testCases.length;
}

// ==========================================
// MAIN
// ==========================================

async function main() {
  const classifierPassed = await testErrorClassifier();
  await runAllTests();

  if (!classifierPassed) {
    process.exit(1);
  }
}

main().catch(console.error);