/**
 * AgentOrchestrator
 *
 * Owns provider failover for agent requests. One provider-neutral state is
 * created per request and is never reset when the active provider changes.
 * General-chat fallback is intentionally outside this class and is never used.
 */

const { resolveRequiredTools } = require("./RequiredToolResolver");
const { buildInvestigationFromEvidence } = require("./Investigation");
function classifyProviderError(error) {
  const category = String(error?.category || "").toLowerCase();
  if (category) return category;

  const status = Number(error?.status);
  if (status === 401) return "authentication";
  if (status === 402) return "billing";
  if (status === 403) return "authorization";
  if (status === 408 || status === 504) return "timeout";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "provider_error";

  const message = String(error?.message || "").toLowerCase();
  if (/credit|billing|insufficient.*(credit|balance)|quota.*billing/.test(message)) return "billing";
  if (/rate.?limit|too many requests|tpm limit|requests per minute|tokens per minute/.test(message)) return "rate_limited";
  if (/timeout|timed out|deadline exceeded|abort/.test(message)) return "timeout";
  if (/network|fetch failed|econnreset|enotfound|socket/.test(message)) return "network";
  if (/invalid.*request|bad request/.test(message)) return "invalid_request";
  if (/unauthorized|authentication|invalid api key/.test(message)) return "authentication";
  if (/forbidden|not allowed|permission/.test(message)) return "authorization";
  if (/unavailable|overloaded|capacity/.test(message)) return "provider_error";
  return "unknown";
}


class AgentOrchestrator {
  constructor({ agentLoop, agentProviders = [], agentProviderOptions = {}, auditLogger, requiredToolResolver = resolveRequiredTools }) {
    this.agentLoop = agentLoop;
    this.agentProviders = agentProviders;
    this.agentProviderOptions = agentProviderOptions;
    this.auditLogger = auditLogger;
    this.requiredToolResolver = requiredToolResolver;
  }

  isConfigured() {
    return Array.isArray(this.agentProviders) && this.agentProviders.some((p) => p && typeof p.callWithTools === "function");
  }

  _emit(event, payload) {
    if (this.auditLogger && typeof this.auditLogger._emit === "function") this.auditLogger._emit(event, payload);
  }

  _modelFor(provider) {
    if (provider.name === "Claude" && this.agentProviderOptions.model) return this.agentProviderOptions.model;
    return provider.models?.balanced || provider.models?.fast || null;
  }

  async run({ messages, systemPrompt, requestId, userContext = {} }) {
    if (!this.isConfigured()) throw Object.assign(new Error("No agent-capable provider configured"), { status: 503, category: "agent_unavailable" });

    const baseConversation = Array.isArray(messages)
      ? messages.filter((m) => m && m.role !== "system").map((m) => ({ ...m }))
      : [];
    const requirement = this.requiredToolResolver(baseConversation);
    const now = Date.now();

    const sharedState = {
      conversation: baseConversation,
      messages: baseConversation,
      providerAttempts: [],
      toolsUsed: [],
      toolResults: [],
      rawToolEvidence: [],
      executedToolCalls: [],
      iteration: 0,
      toolCallCount: 0,
      requiredTools: requirement.requiredTools || [],
      requiredToolArguments: requirement.requiredToolArguments || {},
      completedRequiredTools: [],
      attemptedRequiredTools: [],
      missingRequiredTools: [],
      investigation: null,
      toolExpectedButNotCalled: false,
      startedAt: now,
      deadline: now + this.agentLoop.agentTimeoutMs,
      terminationReason: null,
      executedToolFingerprints: new Set(),
      sameToolCounts: new Map(),
      providerToolState: {},
      lastAssistantToolCalls: [],
      requiredToolRetryUsed: false,
    };

    // Create the canonical investigation at orchestration start. Tool results
    // enrich this same object; they do not create competing investigation
    // representations.
    sharedState.investigation = buildInvestigationFromEvidence({
      target: requirement.targets?.[0]?.value || null,
      targetType: requirement.targets?.[0]?.type === "ipv4" ? "ip" : (requirement.targets?.[0]?.type || "ip"),
      rawToolEvidence: [],
      startedAt: new Date(sharedState.startedAt).toISOString(),
      completed: false,
    });

    this._emit("agent_started", { requestId, requiredTools: sharedState.requiredTools, targets: requirement.targets || [] });
    for (const tool of sharedState.requiredTools) this._emit("agent_tool_expected", { requestId, tool });

    let lastError = null;

    for (let index = 0; index < this.agentProviders.length; index += 1) {
      const provider = this.agentProviders[index];
      if (!provider || typeof provider.callWithTools !== "function") continue;
      const model = this._modelFor(provider);
      if (!model) continue;

      const previous = sharedState.providerAttempts.at(-1)?.provider || null;
      if (previous && previous !== provider.name) this._emit("agent_provider_switch", { requestId, from: previous, to: provider.name });

      const attempt = { provider: provider.name, model, providerAttempt: index + 1, startedAt: Date.now(), ok: false };
      sharedState.providerAttempts.push(attempt);
      this._emit("agent_provider_attempt", { requestId, provider: provider.name, model, providerAttempt: attempt.providerAttempt });

      try {
        const result = await this.agentLoop.run({
          sharedState,
          systemPrompt,
          agentProvider: provider,
          providerOptions: { model, maxTokens: this.agentProviderOptions.maxTokens },
          requestId,
          userContext,
        });

        if (sharedState.requiredTools.length && !sharedState.requiredTools.every((t) => sharedState.attemptedRequiredTools.includes(t))) {
          throw Object.assign(new Error("Agent returned without completing required tools"), { status: 502, category: "required_tools_incomplete" });
        }

        attempt.ok = true;
        attempt.durationMs = Date.now() - attempt.startedAt;
        sharedState.investigation = buildInvestigationFromEvidence({
          target: requirement.targets?.[0]?.value || null,
          targetType: requirement.targets?.[0]?.type === "ipv4" ? "ip" : (requirement.targets?.[0]?.type || "ip"),
          rawToolEvidence: sharedState.rawToolEvidence,
          expectedTools: sharedState.requiredTools,
          startedAt: new Date(sharedState.startedAt).toISOString(),
          completed: true,
        });
        sharedState.terminationReason = "completed";
        this._emit("agent_provider_succeeded", { requestId, provider: provider.name, durationMs: attempt.durationMs });
        this._emit("agent_finished", {
          requestId,
          provider: result.provider,
          model: result.model,
          iterations: result.iterations,
          toolsUsed: sharedState.toolsUsed,
          requiredTools: sharedState.requiredTools,
          completedRequiredTools: sharedState.completedRequiredTools,
          stopReason: result.stopReason,
        });

        return {
          ...result,
          rawToolEvidence: sharedState.rawToolEvidence,
          toolResults: sharedState.toolResults,
          completedRequiredTools: [...sharedState.completedRequiredTools],
          attemptedRequiredTools: [...sharedState.attemptedRequiredTools],
          missingRequiredTools: sharedState.requiredTools.filter((tool) => !sharedState.attemptedRequiredTools.includes(tool)),
          investigation: sharedState.investigation,
          executedToolCalls: [...sharedState.executedToolCalls],
          providerAttempts: sharedState.providerAttempts.map((a) => ({ ...a })),
          metadata: {
            agent: true,
            toolMode: true,
            provider: result.provider,
            model: result.model,
            iterations: result.iterations,
            toolsUsed: [...sharedState.toolsUsed],
            requiredTools: [...sharedState.requiredTools],
            completedRequiredTools: [...sharedState.completedRequiredTools],
            stopReason: result.stopReason || "end_turn",
            toolExpectedButNotCalled: sharedState.toolExpectedButNotCalled,
          },
        };
      } catch (error) {
        attempt.ok = false;
        attempt.durationMs = Date.now() - attempt.startedAt;
        attempt.category = classifyProviderError(error);
        attempt.errorMessage = error.message;
        lastError = error;
        // Exactly one provider-failure event: orchestration boundary only.
        this._emit("agent_provider_failed", {
          requestId,
          provider: provider.name,
          model,
          providerAttempt: attempt.providerAttempt,
          category: classifyProviderError(error),
          errorMessage: error.message,
        });
      }
    }

    // AI-provider exhaustion is independent from security-intelligence
    // collection. If every mandatory security tool was attempted, preserve
    // the investigation and return a deterministic degraded result instead
    // of converting usable evidence into an "agent failed" response.
    if (
      sharedState.requiredTools.length > 0 &&
      sharedState.requiredTools.every((tool) =>
        sharedState.attemptedRequiredTools.includes(tool)
      )
    ) {
      sharedState.investigation = buildInvestigationFromEvidence({
        target: requirement.targets?.[0]?.value || null,
        targetType: requirement.targets?.[0]?.type === "ipv4" ? "ip" : (requirement.targets?.[0]?.type || "ip"),
        rawToolEvidence: sharedState.rawToolEvidence,
        expectedTools: sharedState.requiredTools,
        startedAt: new Date(sharedState.startedAt).toISOString(),
        completed: true,
      });
      sharedState.terminationReason = "completed_with_ai_provider_failure";

      this._emit("agent_completed_degraded", {
        requestId,
        reason: "ai_provider_exhausted_after_required_evidence",
        aiProviderFailures: sharedState.providerAttempts.map((attempt) => ({
          provider: attempt.provider,
          model: attempt.model,
          category: attempt.category || "unknown",
        })),
        requiredTools: sharedState.requiredTools,
        attemptedRequiredTools: sharedState.attemptedRequiredTools,
      });

      return {
        reply: null,
        content: [],
        provider: null,
        model: null,
        iterations: sharedState.iteration,
        toolsUsed: [...sharedState.toolsUsed],
        stopReason: "ai_provider_exhausted",
        rawToolEvidence: sharedState.rawToolEvidence,
        toolResults: sharedState.toolResults,
        completedRequiredTools: [...sharedState.completedRequiredTools],
        attemptedRequiredTools: [...sharedState.attemptedRequiredTools],
        missingRequiredTools: sharedState.requiredTools.filter((tool) => !sharedState.attemptedRequiredTools.includes(tool)),
        investigation: sharedState.investigation,
        executedToolCalls: [...sharedState.executedToolCalls],
        providerAttempts: sharedState.providerAttempts.map((a) => ({ ...a })),
        metadata: {
          agent: true,
          toolMode: true,
          provider: null,
          model: null,
          iterations: sharedState.iteration,
          toolsUsed: [...sharedState.toolsUsed],
          requiredTools: [...sharedState.requiredTools],
          completedRequiredTools: [...sharedState.completedRequiredTools],
          attemptedRequiredTools: [...sharedState.attemptedRequiredTools],
          stopReason: "ai_provider_exhausted",
          aiAnalysis: "unavailable",
          toolExpectedButNotCalled: sharedState.toolExpectedButNotCalled,
          providerFailures: sharedState.providerAttempts.map((attempt) => ({
            provider: attempt.provider,
            model: attempt.model,
            category: attempt.category || "unknown",
          })),
        },
      };
    }

    sharedState.terminationReason = "all_providers_failed";
    this._emit("agent_terminated", { requestId, reason: "all_providers_failed", toolsUsed: sharedState.toolsUsed, requiredTools: sharedState.requiredTools, completedRequiredTools: sharedState.completedRequiredTools });

    throw Object.assign(new Error("All agent providers failed"), {
      status: 503,
      category: "agent_providers_exhausted",
      attempts: sharedState.providerAttempts,
      lastError: lastError?.message || null,
      toolExpectedButNotCalled: sharedState.toolExpectedButNotCalled,
      toolsUsed: [...sharedState.toolsUsed],
      rawToolEvidence: sharedState.rawToolEvidence,
      toolResults: sharedState.toolResults,
      completedRequiredTools: [...sharedState.completedRequiredTools],
      attemptedRequiredTools: [...sharedState.attemptedRequiredTools],
      investigation: sharedState.investigation,
    });
  }
}

module.exports = AgentOrchestrator;
