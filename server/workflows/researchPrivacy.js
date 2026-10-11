"use strict";

// Research is for general questions answerable from public sources. This list
// reduces accidental disclosure; it cannot establish that a prompt is public
// or non-sensitive. Ambiguous target-oriented requests are rejected as well.
const SENSITIVE_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i,
  /\bBearer\s+\S{6,}/i,
  /\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|secret|credential)\s*[:=]\s*\S+/i,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\b[A-Z0-9._%+-]+\s*(?:@|\[at\]|\(at\))\s*[A-Z0-9.-]+\s*(?:\.|\[dot\]|\(dot\))\s*[A-Z]{2,}\b/i,
  /\b\d{3}-\d{2}-\d{4}\b/,
  // Common North American and international phone-number forms.
  /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/,
  /https?:\/\/|\bwww\.|\bhxxps?:|(?:\[\.\]|\(\.\)|\s+dot\s+)/i,
  // Bare DNS names and defanged hostnames, even without a URL scheme.
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,62})\s*(?:\.|\[\.\]|\(\.\)|\s+dot\s+))+[a-z]{2,63}\b/i,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  // IPv6-like literals, including compressed and bracketed forms.
  /(?<![\w])[\[]?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}[\]]?(?![\w])/i,
  /\b(?:confidential|proprietary|internal use only|personal data|personally identifiable|customer record|patient record|employee record|private correspondence|security incident|incident response|security investigation|breach|malware|phishing|ransomware|indicator of compromise|\bioc\b)\b/i,
  // A request to inspect a target can be sensitive even if its identifier is
  // omitted, paraphrased, or not recognizable as a URL/IP.
  /\b(?:investigate|trace|identify|locate|check|assess|look\s+up|search\s+for)\b.{0,80}\b(?:target|host|domain|address|account|person|employee|customer|patient|incident|reputation|suspicious|malicious)\b/i,
  /\b(?:target|host|domain|address|account|person|employee|customer|patient|incident|reputation|suspicious|malicious)\b.{0,80}\b(?:investigate|trace|identify|locate|check|assess|look\s+up|search\s+for)\b/i,
  /\b(?:this|that|the|my|our|your)\s+(?:target|host|domain|address|account|person|employee|customer|patient|incident|case|record)\b/i,
];

function checkResearchPrivacy(question, options = {}) {
  if (typeof question !== "string" || question.length === 0) return { allowed: false, reason: "ambiguous" };
  if (options.containsPersonalData === true || options.containsConfidentialData === true) {
    return { allowed: false, reason: "user_marked_sensitive" };
  }
  if (SENSITIVE_PATTERNS.some((pattern) => pattern.test(question))) {
    return { allowed: false, reason: "sensitive_pattern" };
  }
  return { allowed: true, reason: null };
}

module.exports = { checkResearchPrivacy };
