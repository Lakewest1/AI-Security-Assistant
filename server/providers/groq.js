const BaseProvider = require("./base");

class GroqProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = "openai-compatible";
  }

  async call(messages, model, maxTokens, options = {}) {
    const headers = {
      "Authorization": `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
    };

    const response = await this.fetchWithTimeout(
      this.url,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          model,
          messages,
          temperature: 0.7,
          max_tokens: maxTokens,
          top_p: 1,
          stream: options.stream || false,
        }),
      },
      options.timeoutMs
    );

    if (options.stream) {
      return response;
    }

    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = null; }

    if (!response.ok) {
      const error = new Error(data?.error?.message || `HTTP ${response.status}`);
      error.status = response.status;
      throw this.normalizeError(error);
    }

    const reply = data?.choices?.[0]?.message?.content;
    if (!reply) throw this.normalizeError(new Error("Empty response"));

    return {
      reply,
      usage: data.usage || null,
      provider: this.name,
      model,
      finishReason: data?.choices?.[0]?.finish_reason || null,
    };
  }
}

module.exports = GroqProvider;