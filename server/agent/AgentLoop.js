/**
 * AgentLoop
 *
 * Provider-neutral execution controller for tool-using agent requests.
 * The LLM proposes tool calls; the server owns validation, authorization,
 * execution, evidence storage, loop limits, and completion semantics.
 */

const crypto = require("crypto");
const { buildInvestigationFromEvidence } = require("./Investigation");

const DEFAULT_MAX_ITERATIONS = Number(process.env.AGENT_MAX_ITERATIONS) || 8;
const DEFAULT_AGENT_TIMEOUT_MS = Number(process.env.AGENT_TIMEOUT_MS) || 45000;
const DEFAULT_TOOL_TIMEOUT_MS = Number(process.env.TOOL_TIMEOUT_MS) || 10000;
const DEFAULT_MAX_TOOL_CALLS = Number(process.env.AGENT_MAX_TOOL_CALLS) || 12;
const DEFAULT_MAX_SAME_TOOL_CALLS =
  Number(process.env.AGENT_MAX_SAME_TOOL_CALLS) || 3;
const DEFAULT_MAX_TOOL_RESULT_CHARS =
  Number(process.env.MAX_TOOL_RESULT_CHARS) || 12000;

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

function fingerprintToolCall(toolName, args) {
  const hash = crypto.createHash("sha256");
  hash.update(String(toolName));
  hash.update("|");
  hash.update(stableStringify(args || {}));
  return hash.digest("hex");
}

function normalizeToolCall(block) {
  if (!block) return null;
  if (block.type === "tool_use") {
    return { type: "tool_call", id: block.id, name: block.name, arguments: block.input || {} };
  }
  if (block.type === "tool_call") {
    return { type: "tool_call", id: block.id, name: block.name, arguments: block.arguments || block.input || {} };
  }
  return null;
}

function toAnthropicMessages(conversation) {
  return conversation.map((message) => {
    if (message.role === "assistant" || message.role === "user") {
      return {
        role: message.role,
        content: Array.isArray(message.content)
          ? message.content
          : [{ type: "text", text: String(message.content || "") }],
      };
    }
    return { role: message.role, content: message.content };
  });
}

function toOpenAIMessages(conversation, systemPrompt) {
  const output = [];
  if (systemPrompt) output.push({ role: "system", content: systemPrompt });

  for (const message of conversation) {
    if (message.role === "assistant") {
      const blocks = Array.isArray(message.content)
        ? message.content
        : [{ type: "text", text: String(message.content || "") }];
      const text = blocks.filter((b) => b?.type === "text").map((b) => b.text || "").join("");
      const calls = blocks.map(normalizeToolCall).filter(Boolean);
      if (calls.length) {
        output.push({
          role: "assistant",
          content: text || null,
          tool_calls: calls.map((call) => ({
            id: call.id,
            type: "function",
            function: { name: call.name, arguments: JSON.stringify(call.arguments || {}) },
          })),
        });
      } else {
        output.push({ role: "assistant", content: text });
      }
      continue;
    }

    if (message.role === "user") {
      const blocks = Array.isArray(message.content)
        ? message.content
        : [{ type: "text", text: String(message.content || "") }];
      const toolResults = blocks.filter((b) => b?.type === "tool_result");
      const texts = blocks.filter((b) => b?.type === "text").map((b) => b.text || "").join("");
      for (const result of toolResults) {
        output.push({
          role: "tool",
          tool_call_id: result.tool_use_id,
          content: typeof result.content === "string" ? result.content : JSON.stringify(result.content),
        });
      }
      if (texts) output.push({ role: "user", content: texts });
      else if (!toolResults.length) output.push({ role: "user", content: "" });
      continue;
    }

    output.push({ role: message.role, content: message.content });
  }
  return output;
}

function genericInvestigationResponse(text) {
  if (!text || typeof text !== "string") return true;
  const value = text.trim();
  if (!value) return true;
  return [
    /please provide (the )?(ip|address)\b/i,
    /please provide.*\b(domain|url|hash)\b/i,
    /i[’']?m ready to help/i,
    /i[’']?m ready to investigate/i,
    /please provide more information/i,
    /let me know what you'?d like investigated/i,
  ].some((pattern) => pattern.test(value));
}

class AgentLoop {
  constructor({
    toolRegistry,
    toolPolicy,
    toolValidator,
    auditLogger,
    maxIterations = DEFAULT_MAX_ITERATIONS,
    agentTimeoutMs = DEFAULT_AGENT_TIMEOUT_MS,
    toolTimeoutMs = DEFAULT_TOOL_TIMEOUT_MS,
    maxToolCalls = DEFAULT_MAX_TOOL_CALLS,
    maxSameToolCalls = DEFAULT_MAX_SAME_TOOL_CALLS,
    maxToolResultChars = DEFAULT_MAX_TOOL_RESULT_CHARS,
  }) {
    this.toolRegistry = toolRegistry;
    this.toolPolicy = toolPolicy;
    this.toolValidator = toolValidator;
    this.auditLogger = auditLogger;
    this.maxIterations = maxIterations;
    this.agentTimeoutMs = agentTimeoutMs;
    this.toolTimeoutMs = toolTimeoutMs;
    this.maxToolCalls = maxToolCalls;
    this.maxSameToolCalls = maxSameToolCalls;
    this.maxToolResultChars = maxToolResultChars;
  }

  _emit(event, payload) {
    if (this.auditLogger && typeof this.auditLogger._emit === "function") this.auditLogger._emit(event, payload);
  }

  _log(method, payload, fallbackEvent) {
    if (this.auditLogger && typeof this.auditLogger[method] === "function") this.auditLogger[method](payload);
    else if (fallbackEvent) this._emit(fallbackEvent, payload);
  }

  _requiredToolsComplete(state) {
    return state.requiredTools.length === 0 || state.requiredTools.every((name) => (state.attemptedRequiredTools || []).includes(name));
  }

  _serialize(value) {
    let serialized;
    try {
      serialized = value && typeof value._serialized === "string" ? value._serialized : JSON.stringify(value);
    } catch {
      serialized = JSON.stringify({ ok: false, error: { code: "UNSERIALIZABLE_TOOL_RESULT", retryable: false, message: "Tool returned an unserializable result" } });
    }
    if (typeof serialized !== "string") serialized = "null";
    if (serialized.length > this.maxToolResultChars) {
      return JSON.stringify({ ok: false, error: { code: "TOOL_RESULT_TOO_LARGE", retryable: false, message: `Tool result exceeded ${this.maxToolResultChars} characters` } });
    }
    return serialized;
  }

  _structuredToolError(error) {
    const status = Number(error?.status);
    const code = error?.category === "tool_timeout"
      ? "TIMEOUT"
      : status === 429
        ? "RATE_LIMITED"
        : status === 401 || status === 403
          ? "AUTHORIZATION_FAILED"
          : status >= 500
            ? "UPSTREAM_ERROR"
            : "TOOL_EXECUTION_FAILED";
    return {
      code,
      retryable: code === "TIMEOUT" || code === "RATE_LIMITED" || code === "UPSTREAM_ERROR",
      message: error?.message || "Tool execution failed",
    };
  }

  _providerStatusCode(status) {
    const value = String(status || "").toLowerCase();
    if (value === "timeout") return "TIMEOUT";
    if (value === "rate_limited") return "RATE_LIMITED";
    if (["unauthorized", "forbidden", "authorization_failed"].includes(value)) return "AUTHORIZATION_FAILED";
    if (["unavailable", "network", "network_error"].includes(value)) return "UPSTREAM_ERROR";
    if (value === "not_found") return "NOT_FOUND";
    return "TOOL_EXECUTION_FAILED";
  }

  _existingEvidence(state, fingerprint) {
    return state.rawToolEvidence.find((item) => item.fingerprint === fingerprint && item.ok === true) || null;
  }

  _recordAttemptedFailure(state, toolName, toolCallId, input, code, message) {
    const now = new Date().toISOString();
    const evidence = {
      ok: false,
      toolName,
      callId: toolCallId,
      input: JSON.parse(JSON.stringify(input || {})),
      output: null,
      error: { code, retryable: false, message },
      startedAt: now,
      completedAt: now,
      durationMs: 0,
      controllerExecuted: true,
    };
    this._recordEvidence(state, evidence);
    if (state.requiredTools.includes(toolName) && !state.attemptedRequiredTools.includes(toolName)) {
      state.attemptedRequiredTools.push(toolName);
    }
    return evidence;
  }

  _recordEvidence(state, evidence) {
    state.rawToolEvidence.push(evidence);
    state.toolResults.push(evidence);

    const target =
      state.requiredToolArguments?.virustotal_ip_lookup?.ip ||
      state.requiredToolArguments?.abuseipdb_ip_lookup?.ip ||
      evidence?.input?.ip ||
      null;

    state.investigation = buildInvestigationFromEvidence({
      target,
      targetType: "ip",
      rawToolEvidence: state.rawToolEvidence,
      startedAt: new Date(state.startedAt || Date.now()).toISOString(),
      completed: false,
    });

    return evidence;
  }

  async _executeTool({ state, toolName, input, toolCallId, requestId, userContext, iteration, controllerExecuted = false }) {
    this._emit("agent_tool_requested", { requestId, iteration, toolName, input, controllerExecuted });

    const tool = this.toolRegistry.get(toolName);
    if (!tool) {
      this._emit("agent_tool_denied", { requestId, toolName, reason: "tool_not_registered" });
      const failure = this._failedToolResult(toolName, toolCallId, input, "UNKNOWN_TOOL", "Tool is not registered", false);
      this._recordAttemptedFailure(state, toolName, toolCallId, input, "UNKNOWN_TOOL", "Tool is not registered");
      return failure;
    }

    const validation = this.toolValidator.validate(tool, input);
    this._emit("tool_validation", { requestId, toolName, valid: validation.valid, reason: validation.reason || null });
    if (!validation.valid) {
      this._emit("agent_tool_denied", { requestId, toolName, reason: "invalid_arguments", validation: validation.reason });
      const failure = this._failedToolResult(toolName, toolCallId, input, "INVALID_TOOL_ARGUMENTS", validation.reason, false);
      this._recordAttemptedFailure(state, toolName, toolCallId, input, "INVALID_TOOL_ARGUMENTS", validation.reason);
      return failure;
    }

    const decision = this.toolPolicy.check({ tool, userContext, input });
    this._emit("policy_decision", { requestId, toolName, allowed: decision.allowed, reason: decision.reason });
    if (!decision.allowed) {
      this._emit("agent_tool_denied", { requestId, toolName, reason: decision.reason });
      const failure = this._failedToolResult(toolName, toolCallId, input, "TOOL_DENIED", decision.reason, false);
      this._recordAttemptedFailure(state, toolName, toolCallId, input, "TOOL_DENIED", decision.reason);
      return failure;
    }

    if (controllerExecuted && tool.riskLevel !== "read") {
      this._emit("agent_tool_denied", { requestId, toolName, reason: "controller_execution_requires_read_only_tool" });
      const message = "Controller execution is restricted to read-only tools";
      const failure = this._failedToolResult(toolName, toolCallId, input, "CONTROLLER_EXECUTION_NOT_PERMITTED", message, false);
      this._recordAttemptedFailure(state, toolName, toolCallId, input, "CONTROLLER_EXECUTION_NOT_PERMITTED", message);
      return failure;
    }

    const fingerprint = fingerprintToolCall(toolName, input);
    const existing = this._existingEvidence(state, fingerprint);
    if (existing) {
      this._emit("agent_tool_duplicate", { requestId, toolName, reused: true, originalCallId: existing.callId });
      return {
        ok: true,
        reused: true,
        evidence: existing,
        toolResult: {
          type: "tool_result",
          tool_use_id: toolCallId,
          is_error: false,
          content: this._serialize(existing.output),
        },
      };
    }

    const sameCount = (state.sameToolCounts.get(toolName) || 0) + 1;
    if (sameCount > this.maxSameToolCalls) {
      this._emit("agent_tool_denied", { requestId, toolName, reason: "max_same_tool_calls", limit: this.maxSameToolCalls });
      return this._failedToolResult(toolName, toolCallId, input, "MAX_SAME_TOOL_CALLS", `Maximum repeated calls (${this.maxSameToolCalls}) reached`, false);
    }
    if (state.toolCallCount >= this.maxToolCalls) {
      state.terminationReason = "max_tool_calls";
      this._emit("agent_terminated", { requestId, reason: "max_tool_calls", limit: this.maxToolCalls });
      return this._failedToolResult(toolName, toolCallId, input, "MAX_TOOL_CALLS", `Maximum total tool calls (${this.maxToolCalls}) reached`, false);
    }

    state.toolCallCount += 1;
    state.sameToolCounts.set(toolName, sameCount);

    const startedAt = new Date().toISOString();
    const startedMs = Date.now();
    this._emit("agent_tool_started", { requestId, toolName, toolCallId, controllerExecuted });

    let output = null;
    let error = null;
    let timeoutHandle = null;
    try {
      const remaining = Math.max(1, state.deadline - Date.now());
      const timeoutMs = Math.min(this.toolTimeoutMs, remaining);
      output = await Promise.race([
        tool.execute(input, { requestId, userContext }),
        new Promise((_, reject) => {
          timeoutHandle = setTimeout(() => reject(Object.assign(new Error(`Tool timeout after ${timeoutMs}ms`), { category: "tool_timeout" })), timeoutMs);
        }),
      ]);
    } catch (err) {
      error = this._structuredToolError(err);
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }

    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startedMs;
    const providerStatus = typeof output?.status === "string" ? output.status.toLowerCase() : "";
    const outputIndicatesSuccess =
      !error &&
      output &&
      output.ok !== false &&
      output.success !== false &&
      (!providerStatus || providerStatus === "success" || providerStatus === "partial");
    const success = Boolean(outputIndicatesSuccess);
    const evidence = {
      ok: Boolean(success),
      toolName,
      callId: toolCallId,
      input: JSON.parse(JSON.stringify(input || {})),
      output: success ? output : null,
      error: success ? null : (error || {
        code: this._providerStatusCode(output?.status),
        retryable: ["TIMEOUT", "RATE_LIMITED", "UPSTREAM_ERROR"].includes(this._providerStatusCode(output?.status)),
        message: output?.message || output?.error?.message || output?.error || `Tool returned status: ${output?.status || "error"}`,
      }),
      startedAt,
      completedAt,
      durationMs,
      fingerprint,
      controllerExecuted,
    };
    this._recordEvidence(state, evidence);

    if (state.requiredTools.includes(toolName) && !Array.isArray(state.attemptedRequiredTools)) state.attemptedRequiredTools = [];
    if (state.requiredTools.includes(toolName) && !state.attemptedRequiredTools.includes(toolName)) {
      state.attemptedRequiredTools.push(toolName);
    }

    if (success) {
      state.executedToolFingerprints.add(fingerprint);
      state.toolsUsed.push(toolName);
      state.executedToolCalls.push({ toolName, toolCallId: toolCallId, arguments: input, controllerExecuted });
      this._emit("tool_completed", { requestId, toolName, toolCallId, durationMs, success: true });
      this._emit("agent_tool_succeeded", { requestId, toolName, toolCallId, durationMs, controllerExecuted });
      if (state.requiredTools.includes(toolName) && !state.completedRequiredTools.includes(toolName)) {
        state.completedRequiredTools.push(toolName);
        this._emit("agent_tool_requirement_satisfied", { requestId, tool: toolName });
      }
    } else {
      this._emit("tool_completed", { requestId, toolName, toolCallId, durationMs, success: false, errorCategory: evidence.error?.code || "TOOL_EXECUTION_FAILED" });
      this._emit("agent_tool_failed", { requestId, toolName, toolCallId, durationMs, errorCategory: evidence.error?.code || "TOOL_EXECUTION_FAILED", errorMessage: evidence.error?.message });
    }

    return {
      ok: Boolean(success),
      evidence,
      toolResult: {
        type: "tool_result",
        tool_use_id: toolCallId,
        is_error: !success,
        content: this._serialize(success ? output : { ok: false, tool: toolName, error: evidence.error }),
      },
    };
  }

  _failedToolResult(toolName, callId, input, code, message, retryable) {
    const payload = { ok: false, tool: toolName, input, error: { code, message, retryable } };
    return {
      ok: false,
      evidence: { ok: false, toolName, callId, input, output: null, error: payload.error, startedAt: new Date().toISOString(), completedAt: new Date().toISOString() },
      toolResult: { type: "tool_result", tool_use_id: callId, is_error: true, content: JSON.stringify(payload) },
    };
  }

  async _controllerExecuteRequiredTools({ state, requestId, userContext }) {
    const pending = state.requiredTools
      .filter((toolName) => !(state.attemptedRequiredTools || []).includes(toolName))
      .map((toolName) => {
        const input = state.requiredToolArguments[toolName];
        if (!input) {
          throw Object.assign(
            new Error(`No deterministic arguments available for ${toolName}`),
            { status: 400, category: "required_tool_arguments_missing" }
          );
        }
        return { toolName, input, callId: `controller_${crypto.randomUUID()}` };
      });

    // Required IP intelligence providers are independent sources. When the
    // model omits one or both tools, the deterministic controller executes the
    // missing providers concurrently rather than turning one provider into a
    // serial failover for the other.
    const settled = await Promise.allSettled(
      pending.map(({ toolName, input, callId }) =>
        this._executeTool({
          state,
          toolName,
          input,
          toolCallId: callId,
          requestId,
          userContext,
          iteration: state.iteration,
          controllerExecuted: true,
        }).then((execution) => ({ toolName, input, callId, execution }))
      )
    );

    const executions = settled.map((result, index) => {
      const item = pending[index];
      if (result.status === "fulfilled") return result.value;

      const message = result.reason?.message || "Deterministic required-tool execution failed";
      const failure = this._failedToolResult(
        item.toolName,
        item.callId,
        item.input,
        result.reason?.category || "TOOL_EXECUTION_FAILED",
        message,
        false
      );
      this._recordEvidence(state, {
        ...failure.evidence,
        controllerExecuted: true,
      });
      if (!state.attemptedRequiredTools.includes(item.toolName)) {
        state.attemptedRequiredTools.push(item.toolName);
      }
      return { ...item, execution: failure };
    });

    for (const { toolName, input, callId, execution } of executions) {
      if (!execution.ok) {
        this._emit("agent_required_tool_failed", {
          requestId,
          tool: toolName,
          errorCategory: execution.evidence?.error?.code || "TOOL_EXECUTION_FAILED",
        });
      }

      // Preserve the same assistant-tool-call/tool-result shape the provider
      // would have produced so the next synthesis call sees both sources.
      state.conversation.push({
        role: "assistant",
        content: [{ type: "tool_use", id: callId, name: toolName, input }],
      });
      state.conversation.push({ role: "user", content: [execution.toolResult] });
    }
  }

  async _requestFinalSynthesis({ state, provider, providerOptions, systemPrompt, requestId }) {
    const providerFormat = provider.type === "anthropic" ? "anthropic" : "openai";
    const synthesisInstruction = {
      role: "user",
      content: [{
        type: "text",
        text:
          "FINAL SYNTHESIS REQUIRED. The controller has already executed the required read-only investigation tool. " +
          "Use the supplied tool result as the authoritative evidence. Do not ask for the target again. " +
          "Do not invent facts, threat actors, malware, C2, botnet, phishing, compromise, or attack activity. " +
          "Produce the security assessment now, including Observed, Assessment, Confidence, Limitations, " +
          "Recommended Investigation, Mitigation, and Bottom Line.",
      }],
    };
    state.conversation.push(synthesisInstruction);

    const remainingMs = state.deadline - Date.now();
    if (remainingMs <= 0) throw Object.assign(new Error("Agent deadline exceeded during final synthesis"), { status: 504, category: "agent_timeout" });

    this._emit("agent_final_synthesis", { requestId, provider: provider.name, model: providerOptions.model, iteration: state.iteration + 1 });

    const messages = providerFormat === "anthropic"
      ? toAnthropicMessages(state.conversation)
      : toOpenAIMessages(state.conversation, systemPrompt);

    return provider.callWithTools({
      messages,
      tools: [],
      systemPrompt: providerFormat === "anthropic" ? systemPrompt : undefined,
      model: providerOptions.model,
      maxTokens: providerOptions.maxTokens,
      timeoutMs: remainingMs,
    });
  }

  async run({ sharedState, systemPrompt, agentProvider, providerOptions, requestId, userContext = {} }) {
    if (!agentProvider || typeof agentProvider.callWithTools !== "function") throw Object.assign(new Error("AgentLoop: invalid provider"), { category: "invalid_agent_provider" });
    if (!sharedState || !Array.isArray(sharedState.conversation)) throw new Error("AgentLoop: sharedState.conversation is required");

    const toolDefinitions = this.toolRegistry.getDefinitions();
    const state = sharedState;
    const startedAt = state.startedAt || Date.now();
    state.deadline = state.deadline || startedAt + this.agentTimeoutMs;
    let lastProviderResult = null;

    // Mandatory evidence collection is controller-owned. Required security
    // intelligence providers are executed before the first LLM request, so
    // model tool-calling behavior cannot prevent collection of required
    // evidence or consume extra provider iterations.
    if (state.requiredTools.length > 0) {
      await this._controllerExecuteRequiredTools({
        state,
        requestId,
        userContext,
      });
    }

    // Required security tools have already been collected by the controller.
    // Do not advertise them back to the model as optional tool choices; this
    // prevents redundant LLM tool calls and keeps mandatory collection out of
    // the model's control plane. Optional tools remain available normally.
    const modelToolDefinitions = toolDefinitions.filter(
      (tool) => !state.requiredTools.includes(tool.name)
    );

    while (state.iteration < this.maxIterations) {
      if (Date.now() >= state.deadline) throw Object.assign(new Error("Agent timeout reached"), { status: 504, category: "agent_timeout" });

      state.iteration += 1;
      this._emit("agent_iteration", { requestId, iteration: state.iteration, toolCount: modelToolDefinitions.length, provider: agentProvider.name });

      const providerFormat = agentProvider.type === "anthropic" ? "anthropic" : "openai";
      const providerMessages = providerFormat === "anthropic"
        ? toAnthropicMessages(state.conversation)
        : toOpenAIMessages(state.conversation, systemPrompt);
      const remainingMs = state.deadline - Date.now();
      if (remainingMs <= 0) throw Object.assign(new Error("Agent deadline exceeded"), { status: 504, category: "agent_timeout" });

      this._emit("agent_provider_request", { requestId, provider: agentProvider.name, model: providerOptions.model, iteration: state.iteration, tools: modelToolDefinitions.map((t) => t.name) });

      // Provider failure is deliberately NOT logged here. AgentOrchestrator is the
      // sole owner of agent_provider_failed so a single failure produces one event.
      lastProviderResult = await agentProvider.callWithTools({
        messages: providerMessages,
        tools: modelToolDefinitions,
        systemPrompt: providerFormat === "anthropic" ? systemPrompt : undefined,
        model: providerOptions.model,
        maxTokens: providerOptions.maxTokens,
        timeoutMs: remainingMs,
      });

      const contentBlocks = Array.isArray(lastProviderResult.content) ? lastProviderResult.content : [];
      const calls = contentBlocks.map(normalizeToolCall).filter(Boolean);

      if (calls.length) {
        state.lastAssistantToolCalls = calls.map((call) => ({ role: "assistant", content: [{ type: "tool_use", id: call.id, name: call.name, input: call.arguments }] }));
        state.conversation.push({ role: "assistant", content: contentBlocks });
        const executions = await Promise.all(
          calls.map((call) => this._executeTool({
            state,
            toolName: call.name,
            input: call.arguments,
            toolCallId: call.id,
            requestId,
            userContext,
            iteration: state.iteration,
            controllerExecuted: false,
          }))
        );
        const toolResults = executions.map((execution) => execution.toolResult);
        state.conversation.push({ role: "user", content: toolResults });
        continue;
      }

      const reply = lastProviderResult.reply || contentBlocks.filter((b) => b?.type === "text").map((b) => b.text || "").join("\n").trim();

      if (!this._requiredToolsComplete(state)) {
        // This is a controller invariant failure, not an LLM prompting problem.
        // Attempt only tools that have genuinely not yet been attempted; never
        // spend another model iteration asking the LLM to satisfy a mandatory
        // evidence-collection requirement.
        state.toolExpectedButNotCalled = true;
        this._emit("agent_tool_expected", {
          requestId,
          tools: state.requiredTools,
          reason: "controller_required_tool_incomplete",
        });
        await this._controllerExecuteRequiredTools({ state, requestId, userContext });

        if (!this._requiredToolsComplete(state)) {
          throw Object.assign(
            new Error("Required security tools could not all be attempted"),
            { status: 502, category: "required_tools_incomplete" }
          );
        }
        continue;
      }

      // Required tools are complete. A generic final response is not accepted.
      if (genericInvestigationResponse(reply) && state.requiredTools.length > 0) {
        this._emit("agent_final_synthesis", { requestId, provider: agentProvider.name, reason: "generic_response_rejected" });
        const synthesis = await this._requestFinalSynthesis({ state, provider: agentProvider, providerOptions, systemPrompt, requestId });
        const synthesisBlocks = Array.isArray(synthesis.content) ? synthesis.content : [];
        const synthesisReply = synthesis.reply || synthesisBlocks.filter((b) => b?.type === "text").map((b) => b.text || "").join("\n").trim();
        state.conversation.push({ role: "assistant", content: synthesisBlocks.length ? synthesisBlocks : [{ type: "text", text: synthesisReply }] });
        return {
          reply: synthesisReply,
          content: synthesisBlocks,
          provider: synthesis.provider || lastProviderResult.provider,
          model: synthesis.model || lastProviderResult.model,
          iterations: state.iteration,
          toolsUsed: [...state.toolsUsed],
          stopReason: synthesis.stopReason || "end_turn",
          requiredToolsComplete: true,
          completedRequiredTools: [...state.completedRequiredTools],
          attemptedRequiredTools: [...state.attemptedRequiredTools],
          missingRequiredTools: state.requiredTools.filter((tool) => !state.attemptedRequiredTools.includes(tool)),
          finalResponseInvalid: genericInvestigationResponse(synthesisReply),
          rawToolEvidence: state.rawToolEvidence,
          toolResults: state.toolResults,
        };
      }

      state.toolExpectedButNotCalled = false;
      state.terminationReason = lastProviderResult.stopReason || "end_turn";
      state.conversation.push({ role: "assistant", content: contentBlocks.length ? contentBlocks : [{ type: "text", text: reply }] });
      return {
        reply,
        content: contentBlocks,
        provider: lastProviderResult.provider,
        model: lastProviderResult.model,
        iterations: state.iteration,
        toolsUsed: [...state.toolsUsed],
        stopReason: lastProviderResult.stopReason || "end_turn",
        requiredToolsComplete: true,
        completedRequiredTools: [...state.completedRequiredTools],
        attemptedRequiredTools: [...state.attemptedRequiredTools],
        missingRequiredTools: state.requiredTools.filter((tool) => !state.attemptedRequiredTools.includes(tool)),
        rawToolEvidence: state.rawToolEvidence,
        toolResults: state.toolResults,
      };
    }

    state.terminationReason = "max_iterations";
    this._emit("agent_terminated", { requestId, reason: "max_iterations", toolsUsed: state.toolsUsed });
    throw Object.assign(new Error(`Agent reached the maximum of ${this.maxIterations} iterations`), { status: 504, category: "agent_iteration_limit" });
  }
}

AgentLoop.fingerprintToolCall = fingerprintToolCall;
AgentLoop.toAnthropicMessages = toAnthropicMessages;
AgentLoop.toOpenAIMessages = toOpenAIMessages;
AgentLoop.isGenericInvestigationResponse = genericInvestigationResponse;

module.exports = AgentLoop;
