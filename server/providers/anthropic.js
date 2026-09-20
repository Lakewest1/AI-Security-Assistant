const BaseProvider = require("./base");

class AnthropicProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = "anthropic";
  }

  async call(messages, model, maxTokens, options = {}) {
    const systemMessage = messages.find(
      (message) => message.role === "system"
    );
    const conversation = messages.filter(
      (message) => message.role !== "system"
    );

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
          messages: conversation.map((message) => ({
            role: message.role,
            content: message.content,
          })),
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

    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }

    if (!response.ok) {
      const error = new Error(
        data?.error?.message || `HTTP ${response.status}`
      );
      error.status = response.status;
      throw this.normalizeError(error);
    }

    const content = Array.isArray(data?.content)
      ? data.content
      : [];

    const reply = content
      .filter((block) => block.type === "text")
      .map((block) => block.text || "")
      .join("")
      .trim();

    if (!reply && content.length === 0) {
      throw this.normalizeError(
        new Error("Empty response")
      );
    }

    return {
      reply,
      content,
      usage: data?.usage || null,
      provider: this.name,
      model,
      finishReason: data?.stop_reason || null,
      stopReason: data?.stop_reason || null,
    };
  }

  async callWithTools({
    messages,
    tools,
    systemPrompt,
    model,
    maxTokens,
    timeoutMs,
  }) {
    const body = {
      model,
      messages,
      max_tokens: maxTokens,
      temperature: 0.7,
    };

    if (systemPrompt) {
      body.system = systemPrompt;
    }

    if (Array.isArray(tools) && tools.length > 0) {
      body.tools = tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        input_schema:
          tool.input_schema ||
          tool.inputSchema || {
            type: "object",
            properties: {},
            additionalProperties: false,
          },
      }));
    }

    const response = await this.fetchWithTimeout(
      this.url,
      {
        method: "POST",
        headers: {
          "x-api-key": this.apiKey,
          "anthropic-version": "2023-06-01",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
      timeoutMs
    );

    const text = await response.text();
    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }

    if (!response.ok) {
      const error = new Error(
        data?.error?.message || `HTTP ${response.status}`
      );
      error.status = response.status;
      throw this.normalizeError(error);
    }

    const content = Array.isArray(data?.content)
      ? data.content
      : [];

    const reply = content
      .filter((block) => block.type === "text")
      .map((block) => block.text || "")
      .join("")
      .trim();

    return {
      reply,
      content,
      usage: data?.usage || null,
      provider: this.name,
      model,
      finishReason: data?.stop_reason || null,
      stopReason: data?.stop_reason || null,
    };
  }
}

module.exports = AnthropicProvider;
