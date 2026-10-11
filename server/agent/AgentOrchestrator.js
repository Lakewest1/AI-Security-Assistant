/**
 * AgentOrchestrator
 *
 * Owns provider failover for agent requests. One provider-neutral state is
 * created per request and is never reset when the active provider changes.
 * General-chat fallback is intentionally outside this class and is never used.
 */

const { resolveRequiredTools } = require("./RequiredToolResolver");
const { buildInvestigationFromEvidence } = require("./Investigation");
const { DomainInvestigation } = require("./DomainInvestigation");
const { buildSecurityReasoning } = require("./SecurityReasoning");
const SecurityReportGenerator = require("../reports/SecurityReportGenerator");
const crypto = require("crypto");
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
  constructor({ agentLoop, agentProviders = [], agentProviderOptions = {}, auditLogger, requiredToolResolver = resolveRequiredTools, domainInvestigation = null, reportGenerator = null }) {
    this.agentLoop = agentLoop;
    this.agentProviders = agentProviders;
    this.agentProviderOptions = agentProviderOptions;
    this.auditLogger = auditLogger;
    this.requiredToolResolver = requiredToolResolver;
    this.domainInvestigation = domainInvestigation || new DomainInvestigation({ auditLogger });
    this.reportGenerator = reportGenerator || new SecurityReportGenerator();
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
    const currentTarget = requirement.targets?.[0] || null;
    const scopedSystemPrompt = currentTarget
      ? `${systemPrompt || ""}\n\nCURRENT INVESTIGATION SCOPE (authoritative):\nTarget type: ${currentTarget.type}\nTarget: ${currentTarget.value}\nUse only provider evidence collected for this request and this target. Earlier conversation may contain previous targets or findings; do not reuse them as evidence for the current investigation.`
      : systemPrompt;

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
      investigationType: requirement.investigationType || requirement.targets?.[0]?.type || null,
      target: requirement.targets?.[0] || null,
      investigationId: crypto.randomUUID(),
      requiredCapabilities: requirement.requiredCapabilities || [],
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
      investigationId: sharedState.investigationId,
      rawToolEvidence: [],
      startedAt: new Date(sharedState.startedAt).toISOString(),
      completed: false,
    });

    this._emit("investigation_initialized", {
      requestId,
      investigationId: sharedState.investigationId,
      normalizedTarget: sharedState.investigation.target,
      targetType: sharedState.investigation.targetType,
    });

    this._emit("investigation_started", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType });
    this._emit("agent_started", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, requiredTools: sharedState.requiredTools, targets: requirement.targets || [], investigationType: sharedState.investigationType, requiredCapabilities: sharedState.requiredCapabilities });
    if (sharedState.target) this._emit("agent_target_normalized", { requestId, target: sharedState.target, investigationType: sharedState.investigationType });
    this._emit("agent_tools_selected", { requestId, tools: sharedState.requiredTools, investigationType: sharedState.investigationType });
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
      this._emit("agent_provider_attempt", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, provider: provider.name, model, providerAttempt: attempt.providerAttempt });

      try {
        this._emit("llm_reasoning_started", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, provider: provider.name, model });
        const result = await this.agentLoop.run({
          sharedState,
          systemPrompt: scopedSystemPrompt,
          agentProvider: provider,
          providerOptions: { model, maxTokens: this.agentProviderOptions.maxTokens },
          requestId,
          userContext,
        });

        attempt.ok = true;
        attempt.durationMs = Date.now() - attempt.startedAt;
        this._emit("llm_reasoning_completed", { requestId, investigationId: sharedState.investigationId, target: requirement.targets?.[0]?.value || null, targetType: sharedState.investigationType, provider: provider.name, model, durationMs: attempt.durationMs });
        sharedState.investigation = buildInvestigationFromEvidence({
          target: requirement.targets?.[0]?.value || null,
          targetType: requirement.targets?.[0]?.type === "ipv4" ? "ip" : (requirement.targets?.[0]?.type || "ip"),
          investigationId: sharedState.investigationId,
          rawToolEvidence: sharedState.rawToolEvidence,
          expectedTools: sharedState.requiredTools,
          startedAt: new Date(sharedState.startedAt).toISOString(),
          completed: true,
        });
        this._emit("provider_execution_complete", {
          requestId,
          investigationId: sharedState.investigationId,
          normalizedTarget: sharedState.investigation.target,
          attemptedRequiredTools: [...sharedState.attemptedRequiredTools],
          completedRequiredTools: [...sharedState.completedRequiredTools],
          missingRequiredTools: sharedState.requiredTools.filter((tool) => !sharedState.attemptedRequiredTools.includes(tool)),
        });
        this._emit("evidence_normalized", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, evidenceCount: sharedState.investigation.sources.length });
        this._emit("coverage_calculated", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, coverage: sharedState.investigation.coverage });
        this._emit("correlation_calculated", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, correlationCount: sharedState.investigation.correlations.length });
        this._emit("risk_calculated", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, externalThreat: sharedState.investigation.risk.externalThreat, environmentalRisk: sharedState.investigation.risk.environmentalRisk, score: sharedState.investigation.risk.score, confidence: sharedState.investigation.confidence.level });
        if (sharedState.investigationType === "domain") {
          const domainData = this.domainInvestigation.normalize({
            domain: requirement.targets?.[0]?.value,
            rawToolEvidence: sharedState.rawToolEvidence,
            baseInvestigation: sharedState.investigation,
          });
          sharedState.investigation = { ...sharedState.investigation, ...domainData, targetType: "domain", target: requirement.targets?.[0]?.value || null };
          sharedState.reasoning = buildSecurityReasoning({ investigation: sharedState.investigation, rawToolEvidence: sharedState.rawToolEvidence });
          // Reports are generated by the existing /api/security-report PDF
          // route. Avoid invoking a domain-report method that is not part of
          // that generator's public interface.
        }
        sharedState.terminationReason = "completed";
        this._emit("agent_provider_succeeded", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, provider: provider.name, durationMs: attempt.durationMs });
        this._emit("agent_finished", {
          requestId,
          investigationId: sharedState.investigationId,
          target: sharedState.investigation.target,
          targetType: sharedState.investigation.targetType,
          provider: result.provider,
          model: result.model,
          iterations: result.iterations,
          toolsUsed: sharedState.toolsUsed,
          requiredTools: sharedState.requiredTools,
          completedRequiredTools: sharedState.completedRequiredTools,
          stopReason: result.stopReason,
        });
        this._emit("investigation_completed", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, status: sharedState.investigation.status, coverage: sharedState.investigation.coverage });

        return {
          ...result,
          rawToolEvidence: sharedState.rawToolEvidence,
          toolResults: sharedState.toolResults,
          completedRequiredTools: [...sharedState.completedRequiredTools],
          attemptedRequiredTools: [...sharedState.attemptedRequiredTools],
          missingRequiredTools: sharedState.requiredTools.filter((tool) => !sharedState.attemptedRequiredTools.includes(tool)),
          investigation: sharedState.investigation,
          reasoningStatus: result.reasoningStatus || "completed",
          reasoning: sharedState.reasoning || null,
          report: sharedState.report || null,
          executedToolCalls: [...sharedState.executedToolCalls],
          providerAttempts: sharedState.providerAttempts.map((a) => ({ ...a })),
          metadata: {
            agent: true,
            toolMode: true,
            provider: result.provider,
            model: result.model,
            iterations: result.iterations,
            toolsUsed: [...sharedState.toolsUsed],
            coverage: sharedState.investigation.coverage || null,
            providerStatus: sharedState.investigation.sources || [],
            reasoningStatus: result.reasoningStatus || "completed",
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
        lastError = error;
        // Exactly one provider-failure event: orchestration boundary only.
        this._emit("agent_provider_failed", {
          requestId,
          investigationId: sharedState.investigationId,
          target: sharedState.investigation.target,
          targetType: sharedState.investigation.targetType,
          provider: provider.name,
          model,
          providerAttempt: attempt.providerAttempt,
          category: classifyProviderError(error),
        });
        this._emit("llm_reasoning_failed", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, provider: provider.name, model, category: attempt.category });
      }
    }

    // AI-provider exhaustion is independent from security-intelligence
    // collection. If every mandatory security tool was attempted, preserve
    // the investigation and return a deterministic degraded result instead
    // of converting usable evidence into an "agent failed" response.
    if (sharedState.rawToolEvidence.length > 0) {
      sharedState.investigation = buildInvestigationFromEvidence({
        target: requirement.targets?.[0]?.value || null,
        targetType: requirement.targets?.[0]?.type === "ipv4" ? "ip" : (requirement.targets?.[0]?.type || "ip"),
        investigationId: sharedState.investigationId,
        rawToolEvidence: sharedState.rawToolEvidence,
        expectedTools: sharedState.requiredTools,
        startedAt: new Date(sharedState.startedAt).toISOString(),
        completed: true,
      });
      sharedState.terminationReason = "completed_with_ai_provider_failure";

      this._emit("agent_completed_degraded", {
        requestId,
        investigationId: sharedState.investigationId,
        normalizedTarget: sharedState.investigation.target,
        reason: "ai_provider_exhausted_after_evidence_collection",
        aiProviderFailures: sharedState.providerAttempts.map((attempt) => ({
          provider: attempt.provider,
          model: attempt.model,
          category: attempt.category || "unknown",
        })),
        requiredTools: sharedState.requiredTools,
        attemptedRequiredTools: sharedState.attemptedRequiredTools,
      });
      this._emit("investigation_completed", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, status: sharedState.investigation.status, reasoningStatus: "fallback", coverage: sharedState.investigation.coverage });

      return {
        reply: "AI reasoning was unavailable. Deterministic evidence collection completed; review the structured investigation, source statuses, coverage, assessment, and limitations in the response metadata.",
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
        reasoningStatus: "fallback",
        reasoning: sharedState.reasoning || null,
        report: sharedState.report || null,
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
          reasoningStatus: "fallback",
          coverage: sharedState.investigation.coverage || null,
          providerStatus: sharedState.investigation.sources || [],
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
    this._emit("investigation_failed", { requestId, investigationId: sharedState.investigationId, target: sharedState.investigation.target, targetType: sharedState.investigation.targetType, reason: "no_evidence_and_all_llm_providers_failed" });
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
