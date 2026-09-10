/**
 * Updated Provider Adapters
 * 
 * All providers now use consistent error handling via BaseProvider
 * and ProviderErrorClassifier.
 * 
 * Each provider:
 * 1. Makes request with timeout
 * 2. Parses response safely
 * 3. If not OK, extracts error message and throws
 * 4. If OK, validates response has content
 * 5. Returns consistent format
 */

const BaseProvider = require('./BaseProviderEnhanced');

// ==========================================
// GROQ PROVIDER
// ==========================================

class GroqProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = 'openai-compatible';
  }

  async call(messages, model, maxTokens, options = {}) {
    const requestId = options.requestId || 'unknown';
    const timeoutMs = options.timeoutMs || 10000;

    const headers = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    };

    try {
      const response = await this.fetchWithTimeout(
        this.url,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            messages,
            temperature: 0.7,
            max_tokens: maxTokens,
            top_p: 1,
          }),
        },
        timeoutMs,
        requestId
      );

      const text = await response.text();
      const data = this.safeParseJson(text);

      if (!response.ok) {
        const errorMessage = this.extractErrorMessage(data, response.status);
        const error = new Error(errorMessage);
        error.status = response.status;
        throw error;
      }

      const reply = data?.choices?.[0]?.message?.content;
      if (!reply) {
        throw new Error('Empty response from provider');
      }

      return {
        reply: reply.trim(),
        usage: data.usage || null,
        provider: this.name,
        model,
        finishReason: data?.choices?.[0]?.finish_reason || null,
      };

    } catch (error) {
      throw this.normalizeError(error);
    }
  }
}

// ==========================================
// DEEPSEEK PROVIDER
// ==========================================

class DeepSeekProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = 'openai-compatible';
  }

  async call(messages, model, maxTokens, options = {}) {
    const requestId = options.requestId || 'unknown';
    const timeoutMs = options.timeoutMs || 10000;

    const headers = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    };

    try {
      const response = await this.fetchWithTimeout(
        this.url,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            messages,
            temperature: 0.7,
            max_tokens: maxTokens,
          }),
        },
        timeoutMs,
        requestId
      );

      const text = await response.text();
      const data = this.safeParseJson(text);

      if (!response.ok) {
        const errorMessage = this.extractErrorMessage(data, response.status);
        const error = new Error(errorMessage);
        error.status = response.status;
        throw error;
      }

      const reply = data?.choices?.[0]?.message?.content;
      if (!reply) {
        throw new Error('Empty response from provider');
      }

      return {
        reply: reply.trim(),
        usage: data.usage || null,
        provider: this.name,
        model,
        finishReason: data?.choices?.[0]?.finish_reason || null,
      };

    } catch (error) {
      throw this.normalizeError(error);
    }
  }
}

// ==========================================
// GEMINI PROVIDER
// ==========================================

class GeminiProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = 'gemini';
  }

  async call(messages, model, maxTokens, options = {}) {
    const requestId = options.requestId || 'unknown';
    const timeoutMs = options.timeoutMs || 10000;

    const systemMessage = messages.find(m => m.role === 'system');
    const conversation = messages.filter(m => m.role !== 'system');

    const contents = conversation.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));

    const body = {
      contents,
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: maxTokens,
      },
    };

    if (systemMessage) {
      body.systemInstruction = { 
        parts: [{ text: systemMessage.content }] 
      };
    }

    const url = `${this.url}/${model}:generateContent?key=${encodeURIComponent(
      this.apiKey
    )}`;

    try {
      const response = await this.fetchWithTimeout(
        url,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        },
        timeoutMs,
        requestId
      );

      const text = await response.text();
      const data = this.safeParseJson(text);

      if (!response.ok) {
        const errorMessage = this.extractErrorMessage(data, response.status);
        const error = new Error(errorMessage);
        error.status = response.status;
        throw error;
      }

      const reply = data?.candidates?.[0]?.content?.parts
        ?.map(p => p.text || '')
        .join('')
        .trim();

      if (!reply) {
        throw new Error('Empty response from provider');
      }

      return {
        reply,
        usage: data.usageMetadata || null,
        provider: this.name,
        model,
        finishReason: data?.candidates?.[0]?.finishReason || null,
      };

    } catch (error) {
      throw this.normalizeError(error);
    }
  }
}

// ==========================================
// OPENAI PROVIDER
// ==========================================

class OpenAIProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = 'openai-compatible';
  }

  async call(messages, model, maxTokens, options = {}) {
    const requestId = options.requestId || 'unknown';
    const timeoutMs = options.timeoutMs || 10000;

    const headers = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    };

    try {
      const response = await this.fetchWithTimeout(
        this.url,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            messages,
            temperature: 0.7,
            max_tokens: maxTokens,
            top_p: 1,
          }),
        },
        timeoutMs,
        requestId
      );

      const text = await response.text();
      const data = this.safeParseJson(text);

      if (!response.ok) {
        const errorMessage = this.extractErrorMessage(data, response.status);
        const error = new Error(errorMessage);
        error.status = response.status;
        throw error;
      }

      const reply = data?.choices?.[0]?.message?.content;
      if (!reply) {
        throw new Error('Empty response from provider');
      }

      return {
        reply: reply.trim(),
        usage: data.usage || null,
        provider: this.name,
        model,
        finishReason: data?.choices?.[0]?.finish_reason || null,
      };

    } catch (error) {
      throw this.normalizeError(error);
    }
  }
}

// ==========================================
// CLAUDE / ANTHROPIC PROVIDER
// ==========================================

class AnthropicProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = 'anthropic';
  }

  async call(messages, model, maxTokens, options = {}) {
    const requestId = options.requestId || 'unknown';
    const timeoutMs = options.timeoutMs || 10000;

    const systemMessage = messages.find(m => m.role === 'system');
    const conversation = messages.filter(m => m.role !== 'system');

    const headers = {
      'x-api-key': this.apiKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    };

    try {
      const response = await this.fetchWithTimeout(
        this.url,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            system: systemMessage?.content || '',
            messages: conversation.map(m => ({
              role: m.role,
              content: m.content,
            })),
            max_tokens: maxTokens,
            temperature: 0.7,
          }),
        },
        timeoutMs,
        requestId
      );

      const text = await response.text();
      const data = this.safeParseJson(text);

      if (!response.ok) {
        const errorMessage = this.extractErrorMessage(data, response.status);
        const error = new Error(errorMessage);
        error.status = response.status;
        throw error;
      }

      const reply = data?.content?.[0]?.text;
      if (!reply) {
        throw new Error('Empty response from provider');
      }

      return {
        reply: reply.trim(),
        usage: data.usage || null,
        provider: this.name,
        model,
        finishReason: data?.stop_reason || null,
      };

    } catch (error) {
      throw this.normalizeError(error);
    }
  }
}

// ==========================================
// OPENROUTER PROVIDER
// ==========================================

class OpenRouterProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = 'openai-compatible';
    this.isFallbackOnly = true;
  }

  async call(messages, model, maxTokens, options = {}) {
    const requestId = options.requestId || 'unknown';
    const timeoutMs = options.timeoutMs || 10000;

    const headers = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': process.env.CLIENT_URL || 'http://localhost:5173',
      'X-Title': 'AI Security Assistant',
    };

    try {
      const response = await this.fetchWithTimeout(
        this.url,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            messages,
            temperature: 0.7,
            max_tokens: maxTokens,
          }),
        },
        timeoutMs,
        requestId
      );

      const text = await response.text();
      const data = this.safeParseJson(text);

      if (!response.ok) {
        const errorMessage = this.extractErrorMessage(data, response.status);
        const error = new Error(errorMessage);
        error.status = response.status;
        throw error;
      }

      const reply = data?.choices?.[0]?.message?.content;
      if (!reply) {
        throw new Error('Empty response from provider');
      }

      return {
        reply: reply.trim(),
        usage: data.usage || null,
        provider: this.name,
        model,
        finishReason: data?.choices?.[0]?.finish_reason || null,
      };

    } catch (error) {
      throw this.normalizeError(error);
    }
  }
}

// ==========================================
// EXPORTS
// ==========================================

module.exports = {
  GroqProvider,
  DeepSeekProvider,
  GeminiProvider,
  OpenAIProvider,
  AnthropicProvider,
  OpenRouterProvider,
};