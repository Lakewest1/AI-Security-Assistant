const assert = require("assert");
const {
  applySecurityAssessment,
  parseStructuredReply,
  validateStructuredReply,
  normalizeStructuredSecurityAssessment,
  renderStructuredReply,
} = require("../agent/SecurityAssessment");

/* -------------------------------------------------------------------------
   Structured path tests
   ------------------------------------------------------------------------- */

function wrap(json) {
  return "```json\n" + JSON.stringify(json) + "\n```";
}

function baseStructured(overrides = {}) {
  return {
    title: "IP Investigation",
    target: "129.205.124.229",
    observed: [
      { field: "IP address", value: "129.205.124.229", source: "VirusTotal" },
      { field: "Country", value: "Nigeria", source: "VirusTotal" },
      { field: "ASN / Owner", value: "37148 – Globacom Limited", source: "VirusTotal" },
      { field: "Network", value: "129.205.96.0/19", source: "VirusTotal" },
      { field: "Reputation", value: "-1", source: "VirusTotal" },
      { field: "Malicious detections", value: "1", source: "VirusTotal" },
      { field: "Suspicious detections", value: "1", source: "VirusTotal" },
      { field: "Harmless detections", value: "53", source: "VirusTotal" },
      { field: "Undetected", value: "34", source: "VirusTotal" },
      { field: "Last analysis", value: "2026-09-05 12:46 UTC", source: "VirusTotal" },
    ],
    assessment: "The IP is confirmed malicious.",
    confidence: "high",
    limitations: "",
    recommendedInvestigation: [
      "Block it.",
      "Isolate that host.",
      "Add it to the deny list.",
    ],
    mitigation: "Apply a temporary block and consider a permanent block.",
    bottomLine: "Treat any inbound or outbound traffic to this address as suspicious.",
    ...overrides,
  };
}

test("structured: 129.205.124.229 produces calibrated output", () => {
  const reply = wrap(baseStructured());
  const out = applySecurityAssessment(reply, {
    toolsUsed: ["virustotal_ip_lookup"],
  });

  // Observed CIDR preserved exactly
  assert.ok(out.includes("129.205.96.0/19"), "observed /19 must be preserved");
  // Calibrated assessment
  assert.ok(/weak and mixed signal/i.test(out), "should call it weak and mixed");
  // No unsupported threat-role claims
  assert.ok(!/\bC2\b/.test(out), "must not claim C2");
  assert.ok(!/botnet/i.test(out), "must not claim botnet");
  assert.ok(!/phishing/i.test(out), "must not claim phishing");
  // No unconditional blocking
  assert.ok(!/\bBlock it\b/.test(out), "must not contain 'Block it'");
  assert.ok(!/\bIsolate that host\b/i.test(out), "must not contain 'Isolate that host'");
  // No "treat as suspicious" broad language
  assert.ok(
    !/treat any.*traffic.*as suspicious/i.test(out),
    "must not tell user to treat all traffic as suspicious"
  );
  // Confidence not high for VT-only evidence
  assert.ok(!/### Confidence\s*\nHigh/.test(out), "VT-only cannot be high confidence");
  // Limitations present
  assert.ok(/### Limitations/.test(out), "limitations must be present");
  // Timestamp preserved
  assert.ok(out.includes("2026-09-05 12:46 UTC"), "analysis timestamp must be present");
  // Only specific IP blocking
  assert.ok(
    !/block the broader network|network-wide block|block the \/19/i.test(out),
    "must not recommend broader blocking"
  );
});

test("structured: 185.220.101.34 produces elevated concern but no role claim", () => {
  const reply = wrap(
    baseStructured({
      target: "185.220.101.34",
      observed: [
        { field: "IP address", value: "185.220.101.34", source: "VirusTotal" },
        { field: "Network", value: "185.220.101.0/24", source: "VirusTotal" },
        { field: "Reputation", value: "-14", source: "VirusTotal" },
        { field: "Malicious detections", value: "15", source: "VirusTotal" },
        { field: "Suspicious detections", value: "3", source: "VirusTotal" },
        { field: "Harmless detections", value: "42", source: "VirusTotal" },
        { field: "Undetected", value: "29", source: "VirusTotal" },
        { field: "Last analysis", value: "2026-09-01 08:30 UTC", source: "VirusTotal" },
      ],
      assessment: "This is a C2 server.",
    })
  );
  const out = applySecurityAssessment(reply, {
    toolsUsed: ["virustotal_ip_lookup"],
  });

  assert.ok(out.includes("185.220.101.0/24"), "observed /24 preserved");
  assert.ok(/elevated signal/i.test(out), "should call it elevated concern");
  assert.ok(!/C2\s+server/i.test(out), "must not claim C2 server");
  assert.ok(!/ransomware/i.test(out), "must not claim ransomware");
  assert.ok(!/hostile/i.test(out), "must not claim hostile");
  assert.ok(
    !/block.*185\.220\.101\.0\/24/i.test(out),
    "must not recommend blocking the /24"
  );
});

test("structured: normalizeStructuredSecurityAssessment never mutates input", () => {
  const original = baseStructured();
  const before = JSON.stringify(original);
  normalizeStructuredSecurityAssessment(original);
  assert.strictEqual(JSON.stringify(original), before, "input must not be mutated");
});

test("structured: invalid JSON falls back to regex sweep", () => {
  const malformed = "```json\n{ not valid json }\n```";
  const out = applySecurityAssessment(malformed, {
    toolsUsed: ["virustotal_ip_lookup"],
  });
  assert.strictEqual(typeof out, "string");
});

/* -------------------------------------------------------------------------
   Semantic failure tests (regex fallback path)
   ------------------------------------------------------------------------- */

function assertRewritten(input, mustNotContain, mustMatch) {
  const out = applySecurityAssessment(input, {
    toolsUsed: ["virustotal_ip_lookup"],
  });
  for (const bad of mustNotContain) {
    assert.ok(
      !new RegExp(bad, "i").test(out),
      `output must not contain /${bad}/i — got:\n${out}`
    );
  }
  if (mustMatch) {
    assert.ok(new RegExp(mustMatch, "i").test(out), `output must match /${mustMatch}/i — got:\n${out}`);
  }
}

test("semantic: 'Treat any inbound or outbound traffic ... as suspicious'", () => {
  assertRewritten(
    "Treat any inbound or outbound traffic to this address as suspicious until you can confirm it's benign.",
    ["treat any.*as suspicious", "until you can confirm it'?s benign"],
    "if this IP appears in your environment"
  );
});

test("semantic: 'Block if suspicious'", () => {
  assertRewritten(
    "Block if suspicious.",
    ["\\bblock if suspicious\\b"],
    "consider blocking the specific IP only if malicious activity"
  );
});

test("semantic: 'Isolate that host'", () => {
  assertRewritten(
    "Isolate that host.",
    ["\\bisolate that host\\b"],
    "incident-response containment"
  );
});

test("semantic: 'Consider a network-wide block'", () => {
  assertRewritten(
    "Consider a network-wide block.",
    ["network-wide block"],
    "blocking only the specific IP"
  );
});

test("semantic: 'This may be a C2 server'", () => {
  assertRewritten(
    "This may be a C2 server.",
    ["\\bC2\\s+server\\b"],
    "specific operational role.*not established|some vendors"
  );
});

test("semantic: 'The IP is confirmed malicious'", () => {
  assertRewritten(
    "The IP is confirmed malicious.",
    ["\\bconfirmed malicious\\b"],
    "reported by"
  );
});

test("semantic: 'Apply a temporary block'", () => {
  assertRewritten(
    "Apply a temporary block now.",
    ["temporary block"],
    "consider blocking the specific IP"
  );
});

test("semantic: 'Block the host, isolate, and investigate'", () => {
  assertRewritten(
    "Block the host, isolate, and investigate.",
    ["\\bblock the host"],
    "incident-response containment"
  );
});

test("semantic: 'Add an indicator of compromise (IOC) for this IP'", () => {
  assertRewritten(
    "Add an indicator of compromise (IOC) for this IP to your SIEM.",
    ["\\badd an indicator of compromise"],
    "consider adding an indicator"
  );
});

test("regex sweep preserves observed CIDR", () => {
  const observed =
    "### Observed Intelligence\n- Network: 129.205.96.0/19 _(VirusTotal)_\n\n### Mitigation\nBlock the 129.205.96.0/19.";
  const out = applySecurityAssessment(observed, {
    toolsUsed: ["virustotal_ip_lookup"],
  });
  assert.ok(out.includes("129.205.96.0/19"), "observed /19 must be preserved");
  assert.ok(
    !/block the 129\.205\.96\.0\/19/i.test(out),
    "mitigation /19 must be rewritten"
  );
});