
function nowIso() {
  return new Date().toISOString();
}

const TOOL_PROVIDERS = {
  virustotal_ip_lookup: "virustotal",
  abuseipdb_ip_lookup: "abuseipdb",
  urlscan_lookup: "urlscan",
  shodan_ip_lookup: "shodan",
  ipinfo_ip_lookup: "ipinfo",
  censys_ip_lookup: "censys",
  securitytrails_lookup: "securitytrails",
  mozilla_observatory_scan: "mozilla_observatory",
  viewdns_lookup: "viewdns",
  hibp_lookup: "hibp",
};

const PROVIDER_LABELS = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlscan: "URLScan",
  shodan: "Shodan",
  ipinfo: "IPinfo",
  censys: "Censys",
  securitytrails: "SecurityTrails",
  mozilla_observatory: "Mozilla Observatory",
  viewdns: "ViewDNS",
  hibp: "Have I Been Pwned",
};

const STATUS_SET = new Set([
  "success",
  "partial",
  "not_configured",
  "unauthorized",
  "rate_limited",
  "timeout",
  "unavailable",
  "not_found",
  "empty",
  "error",
  "skipped",
  "not_required",
]);

const REPUTATION_PROVIDERS = new Set([
  "virustotal",
  "abuseipdb",
]);

const INFRA_PROVIDERS = new Set([
  "shodan",
  "censys",
  "securitytrails",
  "viewdns",
  "urlscan",
]);

/*
 * IMPORTANT:
 *
 * These are the ONLY provider names that this investigation engine
 * is allowed to treat as INTERNAL / ENVIRONMENTAL telemetry.
 *
 * External intelligence providers such as Censys, Shodan, IPinfo,
 * VirusTotal, AbuseIPDB, etc. may contain words such as:
 *
 *   proxy
 *   dns
 *   malware
 *   connection
 *   endpoint
 *   authentication
 *
 * Those words DO NOT mean that we have evidence from the user's
 * own environment.
 *
 * This distinction is critical:
 *
 * External threat intelligence
 *       !=
 * Internal compromise evidence
 */
const INTERNAL_TELEMETRY_PROVIDERS = new Set([
  "edr",
  "xdr",
  "siem",
  "firewall",
  "dns_internal",
  "proxy_internal",
  "auth_internal",
  "identity_internal",
  "cloudtrail",
  "azure_activity",
  "kubernetes_audit",
  "netflow",
  "pcap",
  "endpoint",
  "application_logs",
  "internal_logs",
]);

function createInvestigation({
  target,
  targetType = "ip",
  startedAt = nowIso(),
} = {}) {
  return {
    target: target || null,
    targetType,
    startedAt,
    completedAt: null,

    status: "running",

    sources: [],
    findings: [],
    correlations: [],
    conflicts: [],

    confidence: {
      level: "low",
      rationale: [],
      externalIntelligence: "low",
      environmentalAssessment: "low",
    },

    risk: {
      level: "unknown",
      overallAssessment: "insufficient_evidence",
      rationale: [],
      externalThreat: "unknown",
      environmentalRisk: "unknown",
      evidenceCoverage: "none",
    },

    mitre: [],
    limitations: [],
  };
}

function providerFromTool(toolName) {
  return TOOL_PROVIDERS[toolName] || toolName;
}

function providerLabel(provider) {
  return PROVIDER_LABELS[provider] || provider;
}

function statusFromError(error) {
  const c = String(error?.code || error?.category || "").toUpperCase();

  if (c.includes("TIMEOUT")) {
    return "timeout";
  }

  if (c.includes("RATE_LIMIT")) {
    return "rate_limited";
  }

  if (c.includes("AUTH") || c.includes("FORBIDDEN")) {
    return "unauthorized";
  }

  if (c.includes("NOT_FOUND")) {
    return "not_found";
  }

  if (
    c.includes("UNAVAILABLE") ||
    c.includes("UPSTREAM") ||
    c.includes("NETWORK")
  ) {
    return "unavailable";
  }

  return "error";
}

function sourceStatus(evidence) {
  if (!evidence) {
    return "error";
  }

  if (!evidence.ok) {
    return statusFromError(evidence.error);
  }

  let status = String(
    evidence.output?.status || "success"
  ).toLowerCase();

  if (
    status === "unauthorized" &&
    /not configured|missing|credentials? are not configured|api key is not configured|token is not configured/i.test(
      String(
        evidence.output?.message ||
          evidence.error?.message ||
          ""
      )
    )
  ) {
    status = "not_configured";
  }

  return STATUS_SET.has(status) ? status : "error";
}

function sourceFindings(output) {
  if (!output || typeof output !== "object") {
    return {};
  }

  if (
    output.findings &&
    typeof output.findings === "object"
  ) {
    return output.findings;
  }

  const ignored = new Set([
    "ok",
    "success",
    "provider",
    "status",
    "message",
    "collectedAt",
    "evidence",
    "limitations",
  ]);

  return Object.fromEntries(
    Object.entries(output).filter(
      ([key, value]) =>
        !ignored.has(key) &&
        value !== undefined &&
        value !== null &&
        value !== ""
    )
  );
}

function isMeaningfulValue(value) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return false;
  }

  if (Array.isArray(value)) {
    return value.length > 0;
  }

  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }

  return true;
}

function meaningfulFields(source) {
  const findings = source?.findings || {};

  return Object.entries(findings).filter(
    ([, value]) => isMeaningfulValue(value)
  );
}

function hasMeaningfulInfrastructure(source) {
  if (
    !source ||
    !INFRA_PROVIDERS.has(source.provider) ||
    !["success", "partial"].includes(source.status)
  ) {
    return false;
  }

  const findings = source.findings || {};

  if (source.provider === "viewdns") {
    return (
      Number(findings.reverseIpDomainCount) > 0 ||
      Number(findings.whoisResultCount) > 0 ||
      isMeaningfulValue(findings.reverseIpDomains) ||
      isMeaningfulValue(findings.reverseWhoisMatches) ||
      isMeaningfulValue(findings.whoisRecords) ||
      isMeaningfulValue(findings.owner)
    );
  }

  if (source.provider === "shodan") {
    return (
      isMeaningfulValue(findings.ports) ||
      isMeaningfulValue(findings.services) ||
      isMeaningfulValue(findings.hostnames) ||
      isMeaningfulValue(findings.organization) ||
      isMeaningfulValue(findings.asn) ||
      isMeaningfulValue(findings.country)
    );
  }

  if (source.provider === "ipinfo") {
    return (
      isMeaningfulValue(findings.hostname) ||
      isMeaningfulValue(findings.organization) ||
      isMeaningfulValue(findings.asn) ||
      isMeaningfulValue(findings.privacy)
    );
  }

  if (source.provider === "censys") {
    return (
      isMeaningfulValue(findings.services) ||
      isMeaningfulValue(findings.autonomousSystem) ||
      isMeaningfulValue(findings.location) ||
      isMeaningfulValue(findings.lastUpdated)
    );
  }

  if (source.provider === "securitytrails") {
    return meaningfulFields(source).length > 0;
  }

  if (source.provider === "urlscan") {
    return meaningfulFields(source).length > 0;
  }

  return meaningfulFields(source).length > 0;
}

function hasMeaningfulEvidence(source) {
  if (
    !source ||
    !["success", "partial"].includes(source.status)
  ) {
    return false;
  }

  if (source.provider === "viewdns") {
    return hasMeaningfulInfrastructure(source);
  }

  if (
    [
      "shodan",
      "censys",
      "securitytrails",
      "urlscan",
    ].includes(source.provider)
  ) {
    return hasMeaningfulInfrastructure(source);
  }

  return meaningfulFields(source).length > 0;
}

function evidenceStrength({
  direct = false,
  corroborated = false,
  contextual = false,
  inconclusive = false,
} = {}) {
  if (inconclusive) {
    return "inconclusive";
  }

  if (corroborated) {
    return "corroborated";
  }

  if (direct) {
    return "direct";
  }

  if (contextual) {
    return "contextual";
  }

  return "inconclusive";
}

function freshnessInfo(source) {
  const findings = source?.findings || {};

  const raw =
    findings.lastReportedAt ||
    findings.lastAnalysisDate ||
    findings.providerObservedAt ||
    findings.lastUpdated ||
    findings.scanDate ||
    null;

  if (!raw) {
    return {
      status: "unknown",
      observedAt: null,
    };
  }

  const date = new Date(
    typeof raw === "number"
      ? raw * 1000
      : raw
  );

  if (Number.isNaN(date.getTime())) {
    return {
      status: "unknown",
      observedAt: String(raw),
    };
  }

  const ageMs = Math.max(
    0,
    Date.now() - date.getTime()
  );

  const ageDays = ageMs / 86400000;

  return {
    status:
      ageDays <= 7
        ? "fresh"
        : ageDays <= 30
        ? "recent"
        : "stale",

    observedAt: date.toISOString(),

    ageDays: Number(
      ageDays.toFixed(1)
    ),
  };
}

function providerQuality(source) {
  const meaningful =
    hasMeaningfulEvidence(source);

  const freshness =
    freshnessInfo(source);

  const directness =
    REPUTATION_PROVIDERS.has(
      source.provider
    )
      ? "reputation"
      : hasMeaningfulInfrastructure(source)
      ? "observational/contextual"
      : "contextual";

  let score = 0;

  if (source.status === "success") {
    score += 0.35;
  } else if (source.status === "partial") {
    score += 0.20;
  }

  if (meaningful) {
    score += 0.25;
  }

  if (freshness.status === "fresh") {
    score += 0.20;
  } else if (freshness.status === "recent") {
    score += 0.12;
  }

  if (
    REPUTATION_PROVIDERS.has(
      source.provider
    )
  ) {
    score += 0.10;
  }

  if (hasMeaningfulInfrastructure(source)) {
    score += 0.10;
  }

  return {
    score: Number(
      Math.min(score, 1).toFixed(2)
    ),
    meaningful,
    freshness,
    directness,
  };
}

function sourceTrace(
  source,
  field,
  value
) {
  return {
    provider: source.provider,
    tool: source.tool,
    field,
    value,
    collectedAt: source.collectedAt,
    providerObservedAt:
      source.quality?.freshness
        ?.observedAt || null,
  };
}

function addFinding(
  inv,
  type,
  description,
  sourceRefs = [],
  severity = "informational",
  evidenceType = "context",
  strength = "contextual",
  extra = {}
) {
  inv.findings.push({
    type,
    description,

    providers: [
      ...new Set(
        sourceRefs.map((ref) =>
          typeof ref === "string"
            ? ref
            : ref.provider
        )
      ),
    ],

    severity,
    evidenceType,
    strength,

    ...extra,

    evidence: sourceRefs.map(
      (ref) =>
        typeof ref === "string"
          ? { provider: ref }
          : ref
    ),
  });
}

function addCorrelation(
  inv,
  type,
  description,
  sourceRefs,
  strength = "corroborated",
  evidenceType = "correlation",
  extra = {}
) {
  inv.correlations.push({
    type,
    description,

    providers: [
      ...new Set(
        sourceRefs.map((ref) =>
          typeof ref === "string"
            ? ref
            : ref.provider
        )
      ),
    ],

    confidence: strength,
    evidenceType,
    strength,

    ...extra,

    evidence: sourceRefs.map(
      (ref) =>
        typeof ref === "string"
          ? { provider: ref }
          : ref
    ),
  });
}

function dedupePush(list, values) {
  for (const value of values || []) {
    if (
      value &&
      !list.includes(value)
    ) {
      list.push(value);
    }
  }
}

/*
 * ---------------------------------------------------------
 * REPUTATION ASSESSMENT
 * ---------------------------------------------------------
 *
 * This evaluates EXTERNAL threat intelligence only.
 *
 * It does NOT mean the user's environment is compromised.
 */
function reputationAssessment(
  inv,
  vt,
  abuse
) {
  const vtM = vt
    ? Number(vt.findings.malicious)
    : NaN;

  const vtS = vt
    ? Number(vt.findings.suspicious)
    : NaN;

  const abuseScore = abuse
    ? Number(
        abuse.findings
          .abuseConfidenceScore
      )
    : NaN;

  const vtElevated =
    (Number.isFinite(vtM) &&
      vtM > 0) ||
    (Number.isFinite(vtS) &&
      vtS > 0);

  const abuseElevated =
    Number.isFinite(abuseScore) &&
    abuseScore > 0;

  if (vtElevated) {
    addFinding(
      inv,
      "reputation_signal",
      `VirusTotal reports ${
        Number.isFinite(vtM)
          ? vtM
          : "an unspecified number of"
      } malicious and ${
        Number.isFinite(vtS)
          ? vtS
          : "an unspecified number of"
      } suspicious detections.`,
      [
        sourceTrace(
          vt,
          "malicious",
          vt.findings.malicious
        ),
        sourceTrace(
          vt,
          "suspicious",
          vt.findings.suspicious
        ),
      ],
      "elevated",
      "reputation",
      evidenceStrength({
        direct: true,
      })
    );
  } else if (
    vt &&
    (
      Number.isFinite(vtM) ||
      Number.isFinite(vtS)
    )
  ) {
    addFinding(
      inv,
      "reputation_observation",
      "VirusTotal reports no malicious or suspicious detections in the supplied result.",
      [
        sourceTrace(
          vt,
          "malicious",
          vt.findings.malicious
        ),
        sourceTrace(
          vt,
          "suspicious",
          vt.findings.suspicious
        ),
      ],
      "informational",
      "reputation",
      evidenceStrength({
        inconclusive: true,
      })
    );
  }

  if (abuseElevated) {
    addFinding(
      inv,
      "abuse_history",
      `AbuseIPDB reports an abuse confidence score of ${abuseScore}${
        Number.isFinite(
          Number(
            abuse.findings
              .totalReports
          )
        )
          ? ` with ${Number(
              abuse.findings
                .totalReports
            )} total reports.`
          : "."
      }`,
      [
        sourceTrace(
          abuse,
          "abuseConfidenceScore",
          abuse.findings
            .abuseConfidenceScore
        ),

        ...(abuse.findings
          .totalReports !==
        undefined
          ? [
              sourceTrace(
                abuse,
                "totalReports",
                abuse.findings
                  .totalReports
              ),
            ]
          : []),
      ],
      "elevated",
      "reputation",
      evidenceStrength({
        direct: true,
      })
    );
  } else if (
    abuse &&
    Number.isFinite(abuseScore)
  ) {
    addFinding(
      inv,
      "reputation_observation",
      `AbuseIPDB reports an abuse confidence score of ${abuseScore}; no elevated abuse-confidence signal was observed in the supplied result.`,
      [
        sourceTrace(
          abuse,
          "abuseConfidenceScore",
          abuseScore
        ),
      ],
      "informational",
      "reputation",
      evidenceStrength({
        inconclusive: true,
      })
    );
  }

  if (
    vtElevated &&
    abuseElevated
  ) {
    addCorrelation(
      inv,
      "reputation_corroboration",
      "Independent reputation providers report elevated threat-related indicators.",
      [
        sourceTrace(
          vt,
          "malicious",
          vt.findings.malicious
        ),
        sourceTrace(
          abuse,
          "abuseConfidenceScore",
          abuse.findings
            .abuseConfidenceScore
        ),
      ],
      "corroborated",
      "reputation"
    );
  }

  return {
    vtElevated,
    abElevated: abuseElevated,
    elevated:
      vtElevated || abuseElevated,
    both:
      vtElevated && abuseElevated,
  };
}

/*
 * ---------------------------------------------------------
 * IDENTITY / INFRASTRUCTURE CORRELATION
 * ---------------------------------------------------------
 *
 * These remain external/contextual findings.
 * They are NOT environmental compromise evidence.
 */
function identityCorrelation(
  inv,
  sources
) {
  const hostnameSources = [];

  for (const source of sources) {
    const hostname =
      source.findings?.hostname ||
      (
        Array.isArray(
          source.findings?.hostnames
        )
          ? source.findings
              .hostnames[0]
          : null
      );

    if (hostname) {
      hostnameSources.push(
        sourceTrace(
          source,
          "hostname",
          hostname
        )
      );
    }
  }

  const normalized = new Map();

  for (const ref of hostnameSources) {
    const hostname = String(
      ref.value
    ).toLowerCase();

    if (!normalized.has(hostname)) {
      normalized.set(
        hostname,
        []
      );
    }

    normalized
      .get(hostname)
      .push(ref);
  }

  for (
    const [hostname, refs] of normalized
  ) {
    if (refs.length >= 2) {
      addCorrelation(
        inv,
        "identity_corroboration",
        `Multiple independent sources associate the target with the hostname ${hostname}.`,
        refs,
        "corroborated",
        "identity"
      );
    }
  }

  const torRefs = [];

  for (const source of sources) {
    for (const [
      field,
      value,
    ] of Object.entries(
      source.findings || {}
    )) {
      if (
        typeof value === "string" &&
        /tor[- ]?exit/i.test(value)
      ) {
        torRefs.push(
          sourceTrace(
            source,
            field,
            value
          )
        );
      }
    }
  }

  if (torRefs.length >= 2) {
    addCorrelation(
      inv,
      "tor_infrastructure_context",
      "Multiple independent sources associate the target with Tor-exit infrastructure. This is infrastructure context and does not by itself establish malicious activity.",
      torRefs,
      "corroborated",
      "infrastructure"
    );
  }

  return {
    hostnameSources,
    torRefs,
  };
}

function infrastructureCorrelation(
  inv,
  sources
) {
  const meaningful =
    sources.filter(
      hasMeaningfulInfrastructure
    );

  for (const source of meaningful) {
    if (source.provider === "shodan") {
      if (
        isMeaningfulValue(
          source.findings.ports
        )
      ) {
        addFinding(
          inv,
          "service_exposure",
          `Shodan observed ${
            Array.isArray(
              source.findings.ports
            )
              ? source.findings.ports
                  .length
              : "one or more"
          } exposed port observations for the target.`,
          [
            sourceTrace(
              source,
              "ports",
              source.findings
                .ports
            ),
          ],
          "informational",
          "exposure",
          evidenceStrength({
            direct: true,
          })
        );
      }

      if (
        isMeaningfulValue(
          source.findings.services
        )
      ) {
        addFinding(
          inv,
          "service_observation",
          "Shodan returned service/banner observations for the target.",
          [
            sourceTrace(
              source,
              "services",
              source.findings
                .services
            ),
          ],
          "informational",
          "network",
          evidenceStrength({
            direct: true,
          })
        );
      }
    }
  }

  if (meaningful.length >= 2) {
    addCorrelation(
      inv,
      "infrastructure_corroboration",
      "Multiple providers returned meaningful infrastructure observations for the target.",
      meaningful.map(
        (source) => ({
          provider:
            source.provider,
          tool: source.tool,
          field:
            "meaningfulFindings",
          value:
            Object.keys(
              source.findings || {}
            ),
          collectedAt:
            source.collectedAt,
        })
      ),
      "corroborated",
      "infrastructure"
    );
  }
}

/*
 * ---------------------------------------------------------
 * CRITICAL SECURITY FIX
 * ---------------------------------------------------------
 *
 * NEVER infer internal/environmental telemetry by looking
 * for generic words inside external-provider finding fields.
 *
 * BAD:
 *
 *   Censys -> proxy
 *   therefore -> environment compromised
 *
 *   Shodan -> dns
 *   therefore -> internal DNS evidence
 *
 *   VirusTotal -> malware
 *   therefore -> malware in user's environment
 *
 * That is incorrect.
 *
 * Instead, environmental evidence must come from an
 * explicitly identified INTERNAL telemetry provider.
 */
function detectEnvironmentalEvidence(
  sources
) {
  const refs = [];

  for (const source of sources || []) {
    const provider = String(
      source?.provider ||
        source?.providerName ||
        ""
    )
      .trim()
      .toLowerCase();

    /*
     * External providers are explicitly rejected here.
     *
     * Only the allow-listed internal providers below
     * can contribute to environmental risk.
     */
    if (
      !INTERNAL_TELEMETRY_PROVIDERS.has(
        provider
      )
    ) {
      continue;
    }

    const status = String(
      source?.status || ""
    ).toLowerCase();

    if (
      !["success", "partial"].includes(
        status
      )
    ) {
      continue;
    }

    for (const [
      field,
      value,
    ] of Object.entries(
      source?.findings || {}
    )) {
      if (
        isMeaningfulValue(value)
      ) {
        refs.push(
          sourceTrace(
            source,
            field,
            value
          )
        );
      }
    }
  }

  return refs;
}

function buildConfidence(
  inv,
  {
    successful,
    failed,
    environmentalRefs,
    reputation,
  }
) {
  const meaningful =
    successful.filter(
      (source) =>
        source.quality?.meaningful
    );

  const independent =
    new Set(
      inv.findings.flatMap(
        (finding) =>
          finding.providers || []
      )
    );

  const conflicts =
    inv.conflicts.length;

  /*
   * External intelligence confidence.
   *
   * Strong reputation signals from multiple
   * independent providers can produce HIGH
   * external confidence.
   */
  const external =
    reputation.both &&
    conflicts === 0
      ? "high"
      : reputation.elevated
      ? conflicts
        ? "moderate"
        : "high"
      : meaningful.length >= 2
      ? "moderate"
      : meaningful.length === 1
      ? "low"
      : "low";

  /*
   * Environmental confidence is deliberately
   * independent from external reputation.
   */
  const environmental =
    environmentalRefs.length
      ? environmentalRefs.length >= 2
        ? "high"
        : "moderate"
      : "low";

  let level = "low";

  /*
   * Example:
   *
   * External threat = HIGH
   * Environmental = LOW
   *
   * Overall confidence = MODERATE
   *
   * because we have strong external evidence,
   * but we do not have enough evidence to say
   * the user's environment was affected.
   */
  if (
    external === "high" &&
    environmental === "low"
  ) {
    level = "moderate";
  } else if (
    external === "high" &&
    environmental !== "low"
  ) {
    level = "high";
  } else if (
    external === "moderate" &&
    meaningful.length >= 2
  ) {
    level = "moderate";
  }

  inv.confidence = {
    level,

    externalIntelligence:
      external,

    environmentalAssessment:
      environmental,

    rationale: [
      `${meaningful.length} source(s) returned meaningful evidence across ${independent.size} provider(s).`,

      "External-intelligence confidence reflects evidence quality, freshness, independence and consistency rather than provider count.",

      environmentalRefs.length
        ? "Direct internal/environmental telemetry was present in the supplied evidence."
        : "No direct internal/environmental telemetry was present in the supplied evidence.",

      ...(conflicts
        ? [
            "One or more same-dimension conflicts remain unresolved.",
          ]
        : []),
    ],
  };
}

function buildInvestigationFromEvidence({
  target,
  targetType = "ip",
  rawToolEvidence = [],
  startedAt,
  completed = true,
  expectedTools = [],
} = {}) {
  const inv =
    createInvestigation({
      target,
      targetType,
      startedAt,
    });

  const evidence =
    Array.isArray(rawToolEvidence)
      ? rawToolEvidence
      : [];

  /*
   * Keep the latest result for each provider.
   */
  const latest = new Map();

  for (const item of evidence) {
    if (item?.toolName) {
      latest.set(
        providerFromTool(
          item.toolName
        ),
        item
      );
    }
  }

  /*
   * Add expected-but-not-attempted
   * providers as skipped.
   */
  for (const tool of expectedTools || []) {
    const provider =
      providerFromTool(tool);

    if (!latest.has(provider)) {
      latest.set(provider, {
        toolName: tool,

        ok: true,

        output: {
          status: "skipped",
          message:
            "Required provider was not attempted.",
        },

        startedAt: null,
        completedAt: null,
      });
    }
  }

  for (const item of latest.values()) {
    const source =
      normalizeSource(item);

    source.quality =
      providerQuality(source);

    inv.sources.push(source);
  }

  const successful =
    inv.sources.filter(
      (source) =>
        ["success", "partial"].includes(
          source.status
        )
    );

  const failed =
    inv.sources.filter(
      (source) =>
        ![
          "success",
          "partial",
          "skipped",
          "not_required",
        ].includes(source.status)
    );

  const vt =
    inv.sources.find(
      (source) =>
        source.provider ===
          "virustotal" &&
        ["success", "partial"].includes(
          source.status
        )
    );

  const abuse =
    inv.sources.find(
      (source) =>
        source.provider ===
          "abuseipdb" &&
        ["success", "partial"].includes(
          source.status
        )
    );

  /*
   * External reputation assessment.
   */
  const reputation =
    reputationAssessment(
      inv,
      vt,
      abuse
    );

  /*
   * External infrastructure correlations.
   */
  infrastructureCorrelation(
    inv,
    inv.sources
  );

  identityCorrelation(
    inv,
    inv.sources
  );

  /*
   * IMPORTANT:
   *
   * This now ONLY returns actual internal telemetry.
   *
   * Censys proxy data, Shodan DNS data, IPinfo
   * hostname data, VirusTotal malware detections,
   * etc. cannot populate this list.
   */
  const environmentalRefs =
    detectEnvironmentalEvidence(
      inv.sources
    );

  const meaningful =
    successful.filter(
      (source) =>
        source.quality?.meaningful
    );

  /*
   * Source availability coverage:
   *
   * none   = nothing succeeded
   * partial = at least one source failed/was unavailable
   * broad   = successful sources and no failed source
   *
   * This is SOURCE AVAILABILITY coverage, not
   * compromise confidence.
   */
  const coverage =
    successful.length === 0
      ? "none"
      : failed.length > 0
      ? "partial"
      : "broad";

  /*
   * External threat is intentionally independent
   * from environmental risk.
   */
  const externalThreat =
    reputation.elevated
      ? "elevated"
      : meaningful.length
      ? "unknown"
      : "unknown";

  /*
   * Environmental risk can ONLY be elevated
   * when internal telemetry actually exists.
   */
  const environmentalRisk =
    environmentalRefs.length
      ? "elevated"
      : "unknown";

  let overallAssessment =
    "insufficient_evidence";

  if (environmentalRefs.length) {
    overallAssessment =
      reputation.elevated
        ? "elevated_concern"
        : "suspicious";
  } else if (reputation.elevated) {
    /*
     * Strong external evidence, but no proof
     * of compromise inside the environment.
     */
    overallAssessment =
      "elevated_concern";
  }

  inv.risk = {
    /*
     * "medium" here means investigation concern,
     * NOT confirmed compromise.
     */
    level: reputation.elevated
      ? "medium"
      : environmentalRefs.length
      ? "medium"
      : "unknown",

    overallAssessment,

    externalThreat,

    environmentalRisk,

    evidenceCoverage: coverage,

    rationale: reputation.elevated
      ? [
          "Multiple independent reputation signals are elevated in the supplied external intelligence.",

          "External reputation is kept separate from environmental impact.",

          ...(environmentalRefs.length
            ? [
                "Direct internal/environmental evidence was also present in the supplied data.",
              ]
            : [
                "No internal/environmental telemetry was provided to establish current malicious activity or compromise.",
              ]),
        ]
      : [
          meaningful
            ? "No elevated external reputation conclusion was established from the available evidence; absence of elevated reputation does not prove benignness."
            : "Relevant external security intelligence was unavailable.",
        ],
  };

  /*
   * Add VirusTotal analysis timestamp
   * to the reputation evidence when available.
   */
  if (
    reputation.both &&
    vt?.findings?.lastAnalysisDate
  ) {
    const reputationFinding =
      inv.findings.find(
        (finding) =>
          finding.type ===
          "reputation_signal"
      );

    if (reputationFinding) {
      reputationFinding.evidence.push(
        sourceTrace(
          vt,
          "lastAnalysisDate",
          vt.findings
            .lastAnalysisDate
        )
      );
    }
  }

  /*
   * Reputation signal difference.
   */
  if (
    vt &&
    abuse &&
    reputation.vtElevated !==
      reputation.abElevated
  ) {
    inv.conflicts.push({
      type:
        "reputation_signal_difference",

      providers: [
        "virustotal",
        "abuseipdb",
      ],

      description:
        "The reputation providers differ in whether their supplied results contain an elevated reputation signal; they use different datasets and scoring methods, so this is treated as a signal difference rather than a direct contradiction.",

      resolution: "unresolved",

      significance: "moderate",

      evidenceType: "reputation",
    });
  }

  /*
   * Provider limitations.
   */
  for (const source of failed) {
    dedupePush(
      inv.limitations,
      [
        `${providerLabel(
          source.provider
        )} was ${source.status} during this investigation.`,
      ]
    );
  }

  /*
   * Skipped providers.
   */
  for (const source of inv.sources.filter(
    (item) =>
      item.status === "skipped"
  )) {
    dedupePush(
      inv.limitations,
      [
        `${providerLabel(
          source.provider
        )} was not attempted; no provider evidence is available from this source.`,
      ]
    );
  }

  /*
   * No internal telemetry.
   */
  if (!environmentalRefs.length) {
    dedupePush(
      inv.limitations,
      [
        "No internal telemetry was provided; environmental impact cannot be determined from external intelligence alone.",

        "No firewall, proxy, DNS, endpoint, identity, packet-capture, or historical activity telemetry was provided.",
      ]
    );
  }

  /*
   * Timestamp limitation.
   */
  if (
    successful.some(
      (source) =>
        source.findings
          ?.lastAnalysisDate ||
        source.findings
          ?.lastReportedAt ||
        source.findings
          ?.lastUpdated
    )
  ) {
    dedupePush(
      inv.limitations,
      [
        "Provider observations have provider-specific timestamps; older reputation or infrastructure data may not reflect the target's current state.",
      ]
    );
  }

  /*
   * Partial source availability.
   */
  if (
    inv.sources.some(
      (source) =>
        source.status !==
          "success" &&
        source.status !==
          "skipped" &&
        source.status !==
          "not_required"
    )
  ) {
    dedupePush(
      inv.limitations,
      [
        "Investigation completed with partial source availability.",
      ]
    );
  }

  /*
   * MITRE limitation.
   */
  if (
    inv.sources.some(
      (source) =>
        ["success", "partial"].includes(
          source.status
        )
    )
  ) {
    dedupePush(
      inv.limitations,
      [
        "No behavioral telemetry was available to support a confident MITRE ATT&CK mapping from reputation, infrastructure, posture, or breach intelligence alone.",
      ]
    );
  }

  /*
   * Final confidence calculation.
   */
  buildConfidence(inv, {
    successful,
    failed,
    environmentalRefs,
    reputation,
  });

  /*
   * Do not create a confident MITRE mapping
   * from reputation/infrastructure data alone.
   */
  inv.mitre = [];

  inv.status = completed
    ? "completed"
    : "collecting";

  inv.completedAt =
    completed
      ? nowIso()
      : null;

  inv.limitations = [
    ...new Set(
      inv.limitations
    ),
  ];

  return inv;
}

function normalizeSource(
  evidence
) {
  const provider =
    providerFromTool(
      evidence?.toolName
    );

  const output =
    evidence?.output || {};

  let status =
    sourceStatus(evidence);

  const source = {
    provider,

    tool:
      evidence?.toolName,

    status,

    collectedAt:
      output.collectedAt ||
      evidence?.completedAt ||
      evidence?.startedAt ||
      nowIso(),

    findings: {},

    confidence: "low",

    limitations: [],

    errors: [],
  };

  if (
    status === "success" ||
    status === "partial" ||
    status === "empty"
  ) {
    source.findings =
      sourceFindings(output);

    /*
     * ViewDNS returning success without
     * meaningful records is normalized to empty.
     */
    if (
      provider === "viewdns" &&
      status === "success" &&
      !hasMeaningfulInfrastructure(
        source
      )
    ) {
      status = "empty";
    }

    source.status = status;

    const qualityHint =
      hasMeaningfulEvidence(
        source
      )
        ? "moderate"
        : "low";

    source.confidence =
      qualityHint;

    if (
      REPUTATION_PROVIDERS.has(
        provider
      )
    ) {
      source.limitations.push(
        "External reputation intelligence does not establish compromise in the user's environment."
      );
    }

    if (provider === "ipinfo") {
      source.limitations.push(
        "Network, ownership and geolocation context do not establish maliciousness."
      );
    }

    if (
      provider ===
      "mozilla_observatory"
    ) {
      source.limitations.push(
        "Web security posture is not threat reputation and does not establish maliciousness."
      );
    }

    if (provider === "hibp") {
      source.limitations.push(
        "Breach exposure indicates historical exposure of an account, not current compromise."
      );
    }

    if (
      INFRA_PROVIDERS.has(
        provider
      )
    ) {
      source.limitations.push(
        "Infrastructure observations do not by themselves establish malicious activity."
      );
    }

    if (status === "empty") {
      source.limitations.push(
        "The provider returned no records; this is absence of evidence, not evidence that the target is benign."
      );
    }
  } else {
    const message =
      output.message ||
      evidence?.error?.message;

    if (message) {
      source.limitations.push(
        String(message).slice(
          0,
          500
        )
      );
    }

    source.errors = [
      {
        category: status,

        message: String(
          message ||
            `Provider returned status: ${status}`
        ).slice(
          0,
          500
        ),
      },
    ];
  }

  if (
    status !== "success" &&
    !source.limitations.length
  ) {
    source.limitations.push(
      `Provider returned status: ${status}.`
    );
  }

  return source;
}

module.exports = {
  createInvestigation,
  buildInvestigationFromEvidence,
  normalizeSource,
  providerFromTool,
  providerLabel,
  hasMeaningfulInfrastructure,
  hasMeaningfulEvidence,
  providerQuality,
};

