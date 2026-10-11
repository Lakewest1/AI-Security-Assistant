"use strict";

const { checkResearchPrivacy } = require("./researchPrivacy");
const { normalizeSearchResult, McpWorkflowError } = require("./tavilyMcpClient");

const ALLOWED_OPTION_KEYS = new Set(["maxResults", "containsPersonalData", "containsConfidentialData"]);
const MAX_QUESTION_BYTES = 2048;
const MAX_QUESTION_CHARS = 1000;

function validateResearchOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)
    || Object.getPrototypeOf(options) !== Object.prototype && Object.getPrototypeOf(options) !== null) {
    return { ok: false, code: "INVALID_RESEARCH_OPTIONS", message: "Research options are invalid." };
  }
  if (Object.keys(options).some((key) => !ALLOWED_OPTION_KEYS.has(key))) {
    return { ok: false, code: "INVALID_RESEARCH_OPTIONS", message: "Research options contain unsupported fields." };
  }
  for (const key of ["containsPersonalData", "containsConfidentialData"]) {
    if (Object.hasOwn(options, key) && typeof options[key] !== "boolean") {
      return { ok: false, code: "INVALID_RESEARCH_OPTIONS", message: "Research privacy declarations must be boolean." };
    }
  }
  const maxResults = options.maxResults === undefined ? 3 : options.maxResults;
  if (!Number.isInteger(maxResults) || maxResults < 1 || maxResults > 5) {
    return { ok: false, code: "INVALID_RESEARCH_OPTIONS", message: "maxResults must be an integer from 1 to 5." };
  }
  return { ok: true, value: { maxResults, containsPersonalData: options.containsPersonalData === true, containsConfidentialData: options.containsConfidentialData === true } };
}

function createResearchHandler({ manager }) {
  if (!manager || typeof manager.search !== "function") throw new TypeError("A research manager is required");
  return async function handleResearch({ question, options = {}, signal } = {}) {
    if (typeof question !== "string" || Buffer.byteLength(question, "utf8") > MAX_QUESTION_BYTES || question.length > MAX_QUESTION_CHARS) {
      return { status: "error", httpStatus: 413, executionStatus: "not_started", error: { code: "RESEARCH_QUESTION_TOO_LARGE", message: "Research question exceeds the maximum size." } };
    }
    const privacy = checkResearchPrivacy(question, options);
    if (!privacy.allowed) {
      return { status: "error", httpStatus: 400, executionStatus: "not_started", error: { code: "RESEARCH_PRIVACY_REJECTED", message: "This request may contain confidential or personal information and was not sent for research." } };
    }

    let raw;
    try {
      raw = await manager.search(question, { maxResults: options.maxResults, signal });
    } catch (error) {
      const categories = {
        PROVIDER_DISABLED: ["unavailable", 503, "RESEARCH_PROVIDER_DISABLED", "Research provider access is disabled."],
        PROVIDER_UNAVAILABLE: ["unavailable", 503, "RESEARCH_PROVIDER_UNAVAILABLE", "Research provider is unavailable."],
        REQUEST_TIMEOUT: ["timeout", 504, "RESEARCH_TIMEOUT", "Research timed out."],
        TOOL_SCHEMA_MISMATCH: ["unavailable", 503, "RESEARCH_TOOL_INCOMPATIBLE", "Research provider configuration is incompatible."],
        RESPONSE_TOO_LARGE: ["error", 502, "RESEARCH_RESPONSE_TOO_LARGE", "Research provider response exceeded the allowed size."],
        INVALID_PROVIDER_RESPONSE: ["error", 502, "INVALID_RESEARCH_RESPONSE", "Research provider returned an invalid response."],
        CONCURRENCY_LIMIT: ["unavailable", 503, "RESEARCH_BUSY", "Research is temporarily busy."],
      };
      const [status, httpStatus, code, message] = categories[error?.code] || categories.PROVIDER_UNAVAILABLE;
      return { status, httpStatus, executionStatus: error?.code === "PROVIDER_DISABLED" ? "not_started" : "failed", error: { code, message } };
    }

    let normalized;
    try {
      normalized = normalizeSearchResult(raw);
    } catch (error) {
      const invalid = error instanceof McpWorkflowError && error.code === "RESPONSE_TOO_LARGE"
        ? { status: "error", httpStatus: 502, executionStatus: "completed", error: { code: "RESEARCH_RESPONSE_TOO_LARGE", message: "Research provider response exceeded the allowed size." } }
        : { status: "error", httpStatus: 502, executionStatus: "completed", error: { code: "INVALID_RESEARCH_RESPONSE", message: "Research provider returned an invalid response." } };
      return invalid;
    }
    if (normalized.status === "empty") {
      return { ...normalized, httpStatus: 200, executionStatus: "completed" };
    }
    return { ...normalized, httpStatus: 200, executionStatus: "completed" };
  };
}

module.exports = { createResearchHandler, validateResearchOptions, MAX_QUESTION_BYTES, MAX_QUESTION_CHARS };
