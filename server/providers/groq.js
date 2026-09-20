const BaseProvider = require("./base");

class GroqProvider extends BaseProvider {
  constructor(config) {
    super(config);
    this.type = "openai-compatible";
  }

  async call(messages, model, maxTokens, options = {}) {
    const headers = {
      Authorization: `Bearer ${this.apiKey}`,
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

    const reply = data?.choices?.[0]?.message?.content;

    if (!reply) {
      throw this.normalizeError(
        new Error("Empty response")
      );
    }

    return {
      reply,
      usage: data.usage || null,
      provider: this.name,
      model,
      finishReason:
        data?.choices?.[0]?.finish_reason || null,
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
      temperature: 0.7,
      max_tokens: maxTokens,
      top_p: 1,
    };

    if (Array.isArray(tools) && tools.length > 0) {
      body.tools = tools.map((tool) => ({
        type: "function",
        function: {
          name: tool.name,
          description: tool.description,
          parameters:
            tool.input_schema ||
            tool.inputSchema || {
              type: "object",
              properties: {},
              additionalProperties: false,
            },
        },
      }));

      body.tool_choice = "auto";
    }

    const response = await this.fetchWithTimeout(
      this.url,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
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

    const choice = data?.choices?.[0];
    const message = choice?.message || {};
    const textContent =
      typeof message.content === "string"
        ? message.content
        : "";
    const toolCalls = Array.isArray(message.tool_calls)
      ? message.tool_calls
      : [];

    const content = [];

    if (textContent) {
      content.push({
        type: "text",
        text: textContent,
      });
    }

    for (const toolCall of toolCalls) {
      const name = toolCall?.function?.name;

      let args = {};
      try {
        const raw = toolCall?.function?.arguments;
        args =
          typeof raw === "string"
            ? JSON.parse(raw || "{}")
            : raw || {};
      } catch {
        args = {};
      }

      content.push({
        type: "tool_use",
        id: toolCall?.id,
        name,
        input: args,
      });
    }

    const finishReason =
      choice?.finish_reason || "stop";

    const stopReason =
      finishReason === "tool_calls"
        ? "tool_use"
        : finishReason === "stop"
          ? "end_turn"
          : finishReason;

    return {
      reply: textContent,
      content,
      usage: data?.usage || null,
      provider: this.name,
      model,
      finishReason,
      stopReason,
    };
  }
}

module.exports = GroqProvider;
