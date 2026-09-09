const BaseProvider = require("./base");

class AnthropicProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = "anthropic";
  }

  async call(messages, model, maxTokens, options = {}) {
    const systemMessage = messages.find(m => m.role === "system");
    const conversation = messages.filter(m => m.role !== "system");

    const response = await this.fetchWithTimeout(
      this.url,
      {
        method: "POST",
        headers: {
          "x-api-key": this.apiKey,
          "anthropic-version": "2023-06-01",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model,
          system: systemMessage?.content || "",
          messages: conversation.map(m => ({ role: m.role, content: m.content })),
          max_tokens: maxTokens,
          temperature: 0.7,
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

    const reply = data?.content?.[0]?.text;
    if (!reply) throw this.normalizeError(new Error("Empty response"));

    return {
      reply,
      usage: data.usage || null,
      provider: this.name,
      model,
      finishReason: data?.stop_reason || null,
    };
  }
}

module.exports = AnthropicProvider;