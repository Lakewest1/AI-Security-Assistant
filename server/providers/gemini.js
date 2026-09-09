const BaseProvider = require("./base");

class GeminiProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = "gemini";
  }

  async call(messages, model, maxTokens, options = {}) {
    const systemMessage = messages.find(m => m.role === "system");
    const conversation = messages.filter(m => m.role !== "system");

    const contents = conversation.map(m => ({
      role: m.role === "assistant" ? "model" : "user",
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
      body.systemInstruction = { parts: [{ text: systemMessage.content }] };
    }

    const url = `${this.url}/${model}:generateContent?key=${encodeURIComponent(this.apiKey)}`;

    const response = await this.fetchWithTimeout(
      url,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
      options.timeoutMs
    );

    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = null; }

    if (!response.ok) {
      const error = new Error(data?.error?.message || `HTTP ${response.status}`);
      error.status = response.status;
      throw this.normalizeError(error);
    }

    const reply = data?.candidates?.[0]?.content?.parts
      ?.map(p => p.text || "")
      .join("")
      .trim();

    if (!reply) throw this.normalizeError(new Error("Empty response"));

    return {
      reply,
      usage: data.usageMetadata || null,
      provider: this.name,
      model,
      finishReason: data?.candidates?.[0]?.finishReason || null,
    };
  }
}

module.exports = GeminiProvider;