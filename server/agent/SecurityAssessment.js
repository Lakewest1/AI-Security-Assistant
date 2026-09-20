/**
 * SecurityAssessment
 *
 * Post-processing layer for agent replies that carry threat-intelligence
 * evidence (currently VirusTotal IP lookups).
 *
 * Architecture (Phase 1.7):
 *
 *     LLM
 *      ↓
 *     structured JSON
 *      ↓
 *     parseStructuredReply()
 *      ↓
 *     validateStructuredReply()          <-- schema AND narrow content checks
 *      ↓
 *     normalizeStructuredSecurityAssessment()   <-- SECURITY BOUNDARY
 *      ↓
 *     renderStructuredReply()
 *      ↓
 *     applyRegexSweep()                          <-- defense-in-depth net
 *      ↓
 *     frontend
 *
 * The deterministic normalization layer is the security boundary.
 * The regex sweep is a fallback for unstructured replies only.
 *
 * Phase 1.7 changes:
 *   - scrubResidualCIDRsFromBlocking() is now context-aware. It preserves
 *     CIDRs that are being referenced as observed facts (preceded by
 *     "the", "than", "in", "at", or a reference verb like "appears",
 *     "represents", "is", "was", "has") and only rewrites CIDRs that are
 *     being suggested as blocking targets. This prevents the earlier
 *     failure where a correct sentence like "Do not block the broader
 *     range solely because the /19 appears in threat-intelligence
 *     results" was rewritten to reference a /32 that does not appear in
 *     the tool result.
 *   - validateStructuredReply() now rejects "confirmed as malicious",
 *     "the IP is not clean", "potentially hostile", "moderate risk",
 *     "high priority", "block or quarantine", "quarantine the
 *     endpoint", and "IOC for this IP". These represent imperative
 *     action instructions or invented severity labels — exactly the
 *     class of output the deterministic layer exists to eliminate.
 *   - hasUnsafeUnstructuredContent() extended with the same phrases so
 *     the server logs an accurate signal when the model ignores the
 *     structured contract.
 *
 * Phase 1.8 changes (evidence-first policy alignment):
 *   - New SEVERITY_LABEL_PATTERNS regex table strips invented incident
 *     severity/priority labels ("low/medium/critical/urgent priority",
 *     "borderline malicious", "hostile IP", "dangerous IP", "clearly
 *     malicious", "definitely malicious", "not clean") that were not
 *     covered by CERTAINTY_PATTERNS. No incident priority may be
 *     assigned unless the tool or the user explicitly supplies one.
 *   - New MONITORING_DURATION_PATTERNS regex table strips invented
 *     fixed monitoring schedules ("monitor for 7 days", "for the next
 *     30 days", etc.) that are not supplied by the tool, the user, or
 *     organizational policy, replacing them with an open-ended,
 *     evidence-driven monitoring statement.
 *   - validateStructuredReply()'s forbidden list expanded to reject
 *     "clearly malicious", "definitely malicious", "hostile IP",
 *     "dangerous IP", "borderline malicious", "not clean" (broadened
 *     beyond "the IP is not clean"), and "low/medium/critical/urgent
 *     priority" — matching the full "NO INCIDENT PRIORITY" and
 *     "NO 'CONFIRMED' LANGUAGE" rule set.
 *   - hasUnsafeUnstructuredContent() extended with the same phrases.
 *   - Both new pattern tables are applied in applyRegexSweep(), in the
 *     same fail-open, no-I/O style as the existing tables.
 *
 * Design constraints:
 *   - Pure functions only. No I/O. No side effects.
 *   - Never mutates the input object.
 *   - Fails open: any error returns the original reply.
 */

const { buildInvestigationFromEvidence } = require("./Investigation");

/* =========================================================================
   SECTION A — Regex pattern tables (defense-in-depth net)
   ========================================================================= */

const CERTAINTY_PATTERNS = [
  {
    pattern:
      /\b(?:confirmed|definitively|proven|established)\s+(?:to be\s+)?(?:malicious|hostile|a\s+threat|compromised|infected)\b/gi,
    replacement:
      "reported by multiple vendors as associated with malicious activity",
  },
  {
    pattern: /\b(?:is|are)\s+(?:a\s+)?(?:malicious|hostile)\s+(?:IP|address|host|server|infrastructure|actor)\b/gi,
    replacement:
      "is currently reported by multiple vendors as associated with malicious activity",
  },
  {
    pattern:
      /\bis\s+(?:currently\s+)?considered\s+(?:a\s+)?(?:threat|malicious|hostile)\b/gi,
    replacement:
      "is currently reported by multiple vendors as associated with suspicious or malicious activity",
  },
  {
    pattern: /\btreat\s+(?:it|this|the\s+(?:IP|address|host))\s+as\s+(?:hostile|malicious|blocked)\b/gi,
    replacement:
      "consider treating it as potentially suspicious pending additional context",
  },
  {
    pattern:
      /\btreat\s+(?:any|all|every)\s+[^.]*?\b(?:traffic|connection|request|activity)[^.]*?\bas\s+suspicious\b[^.]*\.?/gi,
    replacement:
      "If this IP appears in your environment, review the associated traffic and determine whether the communication is expected.",
  },
  {
    pattern: /\b(?:definitely|definitively|certainly|clearly)\s+malicious\b/gi,
    replacement:
      "currently reported by multiple vendors as associated with malicious activity",
  },
  {
    pattern: /\bwill\s+(?:compromise|infect|spread|exfiltrate|attack)\b/gi,
    replacement: "may be associated with activity that could",
  },
  {
    pattern:
      /\b(?:safe\s+to\s+ignore|completely\s+safe|definitely\s+safe|guaranteed\s+safe|100%\s+safe|safe\s+IP|benign\s+IP|clean\s+IP)\b/gi,
    replacement:
      "not currently showing any detections in the available data",
  },
  {
    pattern:
      /(^|[.!?]\s+)((?:It|This|The IP|The address|The indicator|The host)\s+(?:is|are)\s+(?:definitely\s+|certainly\s+|completely\s+|entirely\s+|clearly\s+)?(?:benign|harmless|safe|clean))\b/gi,
    replacement:
      "$1does not show any current detections in the available data",
  },
  {
    pattern:
      /\b(?:largely|mostly|primarily|generally|predominantly)\s+(?:considered\s+)?(?:benign|harmless|safe)\b/gi,
    replacement:
      "showing predominantly harmless detections alongside a small number of positive ones",
  },
  {
    pattern:
      /\b(?:largely|mostly|primarily|generally|predominantly)\s+(?:considered\s+)?(?:a\s+)?(?:threat|malicious|hostile)\b/gi,
    replacement:
      "showing a predominance of malicious detections alongside some harmless ones",
  },
  {
    pattern: /\b(?:just\s+)?(?:below|above)\s+neutral\b/gi,
    replacement:
      "negative within VirusTotal's proprietary scale, which should not be treated as a probability",
  },
  {
    pattern: /\b(?:slightly|mildly|somewhat)\s+(?:negative|positive)\b/gi,
    replacement:
      "mixed within VirusTotal's proprietary scale, which should not be treated as a probability",
  },
  {
    pattern:
      /\branges?\s+(?:roughly\s+)?from\s*[-–—]?\s*100\s*to\s*\+?\s*100\b/gi,
    replacement:
      "is a proprietary value whose exact scale is not documented as a probability",
  },
  {
    pattern:
      /\b(?:a\s+)?(?:value|score)\s+of\s+[-–—]?\d+\s+(?:indicates|means|signals|suggests)\b/gi,
    replacement:
      "The reputation value should be interpreted alongside individual detections rather than as a standalone signal,",
  },
  {
    pattern:
      /\b(?:low|moderate|medium|high)\s*[-–—\s]?\s*to\s*[-–—\s]?\s*(?:low|moderate|medium|high)?\s*[-–—\s]?\s*risk\b/gi,
    replacement:
      "showing mixed evidence that warrants contextual investigation",
  },
  {
    pattern:
      /\b(?:most|majority of|nearly all)\s+(?:scanners|engines|vendors|analysts)\s+(?:consider|report|see|flag|mark)\s+(?:it|the IP|this)\s+(?:as\s+)?(?:benign|harmless|safe|clean)\b/gi,
    replacement:
      "the majority of vendors report no detections, though a small number report malicious or suspicious activity",
  },
  {
    pattern:
      /\bthe\s+majority\s+of\s+(?:engines|scanners|vendors)\s+(?:see|report|show)\s+no\s+threat\b/gi,
    replacement:
      "most vendors report no detections, though a minority do",
  },
  {
    pattern:
      /\bsuggesting\s+it\s+has\s+been\s+observed\s+in\s+(?:at\s+least\s+)?one\s+malicious\s+context\b/gi,
    replacement:
      "indicating at least one vendor currently associates it with malicious activity",
  },
  {
    pattern:
      /\b(?:any\s+)?score\s*(?:<|less than)\s*0\b[^.]*?indicates?[^.]*?\.?/gi,
    replacement:
      "The reputation value should be interpreted alongside individual detections rather than as a standalone signal.",
  },
  {
    pattern:
      /\bpushes?\s+the\s+reputation\s+into\s+the\s+negative\s+range\b/gi,
    replacement:
      "is associated with a negative reputation value within VirusTotal's proprietary scale",
  },
  {
    pattern:
      /\bthe\s+threat\s+is\s+not\s+widespread\b/gi,
    replacement:
      "the negative detections are limited in number, though their significance is uncertain without additional context",
  },
  {
    pattern:
      /\bconfirm\s+it'?s?\s+benign\b/gi,
    replacement:
      "confirm that the traffic is expected and legitimate",
  },
  {
    pattern:
      /\bmove\s+to\s+a\s+higher[- ]severity\s+response\b/gi,
    replacement:
      "consider escalating the investigation if additional corroborating evidence appears",
  },
  {
    pattern:
      /\b(?:confirmed|definitively|proven|established)\s+(?:malicious|hostile|compromised)\s+(?:detection|activity|indicator|signal|result)\b/gi,
    replacement:
      "a vendor-reported malicious detection",
  },
  {
    pattern:
      /\bat\s+least\s+one\s+confirmed\s+(?:malicious|hostile)\s+(?:detection|activity|indicator)\b/gi,
    replacement:
      "one or more vendor-reported malicious detections",
  },
  {
    pattern:
      /\bcommunity[- ]derived\s+reputation\s+is\s+negative,?\s*suggesting\b[^.]*\.?/gi,
    replacement:
      "The reputation value is negative within VirusTotal's proprietary scale; this should be interpreted alongside individual detections, not as a probability of maliciousness.",
  },
  {
    pattern:
      /\bsuggesting\s+that\s+this\s+IP\s+has\s+been\s+flagged\s+for\s+at\s+least\s+one\s+undesirable\s+activity\b/gi,
    replacement:
      "indicating that at least one vendor associates this IP with potentially unwanted or malicious activity",
  },
  {
    pattern:
      /\bhas\s+identified\s+the\s+IP\s+as\s+being\s+involved\s+in\s+malicious\s+activity\b[^.]*\.?/gi,
    replacement:
      "has reported the IP as associated with malicious activity; the specific role is not established by this lookup alone",
  },
  {
    pattern:
      /\btreat\s+it\s+as\s+a\s+high[- ]priority\s+alert\b/gi,
    replacement:
      "review it as potentially significant if the traffic is unexpected in your environment",
  },
  {
    pattern:
      /\btreat\s+(?:any|all|every)[^.]*?\btraffic[^.]*?\bas\s+suspicious\s+until\s+you\s+can\s+confirm[^.]*?\.?/gi,
    replacement:
      "review any such traffic as potentially suspicious only if it is unexpected in your environment; the VirusTotal result alone does not establish maliciousness",
  },
  {
    pattern:
      /\bapply\s+(?:a\s+)?(?:temporary|permanent)\s+block\b/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is confirmed in your environment and policy permits",
  },
  {
    pattern:
      /\badd\s+(?:a\s+)?(?:temporary|permanent)\s+block\b/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is confirmed in your environment and policy permits",
  },
  {
    pattern:
      /\badd\s+an?\s+(?:indicator\s+of\s+compromise|IOC)\s+for\s+this\s+IP\b[^.]*\.?/gi,
    replacement:
      "consider adding an indicator for this IP only after malicious activity is corroborated in your environment",
  },
  {
    pattern:
      /\bconsider\s+a\s+network[- ]wide\s+block\b/gi,
    replacement:
      "consider blocking only the specific IP if malicious activity is confirmed in your environment and policy permits",
  },
  {
    pattern:
      /\bconsider\s+a\s+permanent\s+block\b/gi,
    replacement:
      "consider blocking the specific IP only after malicious activity is corroborated and policy permits",
  },
  {
    pattern:
      /\bmove\s+to\s+a\s+permanent\s+block\b/gi,
    replacement:
      "consider blocking the specific IP only after malicious activity is corroborated and policy permits",
  },
  {
    pattern:
      /\bblock\s+the\s+host,?\s*(?:isolate|quarantine),?\s*and\s+investigate\b/gi,
    replacement:
      "If additional evidence indicates endpoint compromise, follow the organization's incident-response containment procedure.",
  },
  {
    pattern:
      /\bescalate\s+to\s+incident\s+response;?\s*consider\s+a\s+network[- ]wide\s+block\b/gi,
    replacement:
      "If malicious activity is corroborated across multiple hosts, follow your organization's incident response process.",
  },
  {
    pattern:
      /\badd\s+to\s+your\s+(?:deny\s+list|blocklist)\b/gi,
    replacement:
      "consider adding the specific IP to a watchlist pending additional evidence",
  },
  {
    pattern:
      /\bblock\s+if\s+suspicious\b/gi,
    replacement:
      "Consider blocking the specific IP only if malicious activity is corroborated and organizational policy permits.",
  },
  {
    pattern:
      /\bconsider\s+it\s+(?:suspicious|malicious|hostile)\b/gi,
    replacement:
      "consider it potentially suspicious pending additional context",
  },
  {
    pattern:
      /\bas\s+a\s+high[- ]priority\s+alert\b/gi,
    replacement:
      "as potentially significant if the traffic is unexpected in your environment",
  },
  {
    pattern:
      /\bisolate\s+that\s+host\b/gi,
    replacement:
      "If additional evidence indicates endpoint compromise, follow the organization's incident-response containment procedure for that endpoint.",
  },
  {
    pattern: /\b(?:is|are)\s+not\s+(?:clean|safe|benign)\b/gi,
    replacement:
      "has one or more vendor-reported malicious or suspicious detections, which does not by itself establish current maliciousness",
  },
  {
    pattern:
      /\bhas\s+been\s+seen\s+in\s+at\s+least\s+one\s+malicious\s+context\b[^.]*\.?/gi,
    replacement:
      "has been reported by at least one vendor as associated with malicious or suspicious activity; the specific context is not established by this lookup alone",
  },
  {
    pattern:
      /\bsafest\s+posture\s+is\s+to\s+treat\s+(?:it|this|the\s+IP)\s+as\s+(?:suspicious|malicious|hostile)\b/gi,
    replacement:
      "review it in context if it appears in your environment; the available data alone does not establish maliciousness or safety",
  },
  {
    pattern:
      /\btreat\s+(?:it\s+|this\s+|the\s+(?:IP|address|host)\s+)?as\s+suspicious\b/gi,
    replacement:
      "review as potentially suspicious only if it appears in your environment",
  },
  {
    pattern:
      /\bdo\s+not\s+automatically\s+trust\s+traffic\s+from\s+this\s+IP\b/gi,
    replacement:
      "evaluate traffic from this IP in the context of your environment rather than assuming either trust or distrust",
  },
  {
    pattern:
      /\b(?:fairly\s+)?large\s+\/32\s+(?:range|block|network)\b/gi,
    replacement:
      "network block as reported by VirusTotal",
  },
  {
    pattern:
      /\bwith\s+a\s+["'“]?low[- ]to[- ]moderate\s+risk["'”]?\s+tag\b/gi,
    replacement:
      "with an appropriate confidence tag based on your organization's internal threat-intelligence policy",
  },
  {
    pattern:
      /\bconsider\s+a\s+temporary\s+or\s+long[- ]term\s+block\b[^.]*\.?/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is corroborated in your environment and policy permits",
  },
  {
    pattern:
      /\binspect\s+payloads?\b[^.]*\.?/gi,
    replacement:
      "If traffic is observed and organizational policy permits, capture relevant telemetry for analysis",
  },
  {
    pattern:
      /\bblock\s+it\s+at\s+the\s+perimeter\b/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is corroborated and policy permits",
  },
  {
    pattern:
      /\bflag\s+future\s+alerts\s+that\s+reference\s+this\s+IP\s+for\s+higher\s+severity\b/gi,
    replacement:
      "consider routing alerts referencing this IP to an analyst for contextual review",
  },
  {
    pattern:
      /\bdecide\s+on\s+block\s*[-–—]\s*if\s+you\s+find\s+malicious\s+content\b[^.]*\.?/gi,
    replacement:
      "If malicious activity is corroborated in your environment and policy permits, consider blocking the specific IP",
  },
  {
    pattern:
      /\bflagged\s+as\s+(?:suspicious|malicious|hostile|dangerous)\b/gi,
    replacement:
      "reported by one or more vendors as associated with malicious or suspicious activity",
  },
  {
    pattern:
      /\boverall\s+verdict\s*:?\s*(?:potentially\s+)?(?:malicious|suspicious|hostile)\b[^.\n]*/gi,
    replacement:
      "Overall interpretation: mixed signal requiring contextual investigation",
  },
  {
    pattern:
      /\bthe\s+presence\s+of\s+any\s+malicious\s+detection\s+warrants\s+caution\b/gi,
    replacement:
      "one or more vendors have reported malicious activity; this warrants contextual review if the IP appears in your environment",
  },
  {
    pattern:
      /\bthat\s+does\s+not\s+guarantee\s+the\s+traffic\s+shows\s+no\s+current\s+detections\b[^.]*\.?/gi,
    replacement:
      "Ownership or geography alone does not establish the trustworthiness of an address; assess the specific indicator on its own evidence.",
  },
  {
    pattern:
      /\bblock\s+or\s+closely\s+monitor\s+any\s+traffic\b/gi,
    replacement:
      "review traffic associated with this IP in context and follow your organization's policy for any blocking decision",
  },
  {
    pattern:
      /\badd\s+the\s+IP\s+\(or\s+its\s+\/\d{1,2}\s+network\s+block\)\s+to\s+any\s+threat[- ]intel\s+block\s+lists\b[^.]*\.?/gi,
    replacement:
      "consider adding the specific IP to a monitored watchlist only after malicious activity is corroborated in your environment and policy permits",
  },
  {
    pattern:
      /\brun\s+a\s+full\s+anti[- ]malware\s+scan\s+and\s+collect\s+memory\/disk\s+for\s+forensic\s+analysis\b/gi,
    replacement:
      "If additional evidence indicates endpoint compromise, follow your organization's incident-response procedure, which may include endpoint scanning and forensic collection as policy dictates",
  },
  {
    pattern:
      /\breview\s+recent\s+processes,?\s+scheduled\s+tasks,?\s+and\s+startup\s+items\s+for\s+anomalies\b/gi,
    replacement:
      "Review endpoint telemetry in the context of your organization's normal baseline if the host shows signs of compromise",
  },
  {
    pattern:
      /\bcreate\s+an\s+incident\s+ticket\s+with\s+the\s+details\s+above\b[^.]*\.?/gi,
    replacement:
      "Document findings according to your organization's incident-handling policy if escalation is warranted",
  },
  {
    pattern:
      /\bconsider\s+reporting\s+the\s+IP\s+to\s+the\s+ISP\b[^.]*\.?/gi,
    replacement:
      "If malicious activity is confirmed in your environment, follow your organization's abuse-reporting procedure",
  },
  {
    pattern:
      /\bif\s+you\s+need\s+deeper\s+analysis\b[^.]*?let\s+me\s+know\b[^.]*\.?/gi,
    replacement:
      "If you can share relevant telemetry from your environment, the assessment can be refined.",
  },
  {
    pattern:
      /\bshows\s+no\s+current\s+detections\s+in\s+the\s+available\s+data\s+for\s+this\s+IP\b/gi,
    replacement:
      "does not by itself establish that the IP is benign or safe",
  },
  {
    pattern:
      /\bnetwork\s+block\s+is\s+a\s+(?:fairly\s+)?large\s+\/\d{1,2}\b[^.]*\.?/gi,
    replacement:
      "The IP is part of a larger network block reported by VirusTotal; the size of the block does not by itself establish anything about this address.",
  },
];

const CATEGORY_CLAIM_PATTERNS = [
  {
    pattern: /\b(?:is|are)\s+(?:a\s+)?(?:C2|C&C|command\s*(?:and|&)\s*control)\s+(?:server|host|endpoint|infrastructure)\b/gi,
    replacement:
      "is reported by some vendors as associated with malicious activity; the specific operational role has not been independently established",
  },
  {
    pattern: /\b(?:is|are)\s+(?:part\s+of\s+)?(?:a\s+)?(?:botnet|ransomware\s+infrastructure|phishing\s+infrastructure|malware\s+infrastructure|compromised\s+infrastructure)\b/gi,
    replacement:
      "is reported by some vendors as associated with malicious activity; the specific operational role has not been independently established",
  },
  {
    pattern: /\bthis\s+is\s+(?:a\s+)?(?:C2|C&C|botnet|ransomware|phishing|malware)\s+(?:server|host|infrastructure|endpoint)\b/gi,
    replacement:
      "this IP is reported by some vendors as associated with malicious activity; the specific role is not established by this lookup alone",
  },
  {
    pattern:
      /\b(?:likely|possible|probable|suspected)\s+(?:C2|C&C|botnet|ransomware|phishing|spam)\s+(?:server|beacon|relay|host|infrastructure)\b/gi,
    replacement:
      "an IP that some vendors associate with malicious or suspicious activity; the specific operational role is not established by this lookup alone",
  },
  {
    pattern:
      /\bC2\s+beacon\b/gi,
    replacement:
      "an activity pattern some vendors associate with malicious infrastructure",
  },
  {
    pattern:
      /\bspam\s+relay\b/gi,
    replacement:
      "an activity pattern some vendors associate with unwanted messaging",
  },
  {
    pattern:
      /\bphishing\s+relay\b/gi,
    replacement:
      "an activity pattern some vendors associate with credential theft",
  },
  {
    pattern:
      /\bthe\s+malicious\s+detection\s+could\s+be\s+a\s+C2\s+beacon\b/gi,
    replacement:
      "one vendor has reported the IP as associated with malicious activity; the specific operational role is not established by this lookup alone",
  },
  {
    pattern:
      /\bsome\s+threat\s+actors\s+rent\s+or\s+compromise\s+ISP[- ]owned\s+IPs\s+to\s+send\s+phishing\s+emails\s+or\s+host\s+malicious\s+landing\s+pages\b[^.]*\.?/gi,
    replacement:
      "ISP-owned address space is shared infrastructure; a single vendor-reported detection does not establish the operational role of a specific IP within that space",
  },
  {
    pattern:
      /\bthe\s+IP\s+could\s+belong\s+to\s+a\s+compromised\s+device\b[^.]*\.?/gi,
    replacement:
      "the available data does not establish the ownership or state of the device using this IP",
  },
  {
    pattern:
      /\bhosting\s+(?:malware|phishing|spam|ransomware)\b/gi,
    replacement:
      "an activity pattern some vendors associate with malicious infrastructure",
  },
  {
    pattern:
      /\bbotnet\s+activity\b/gi,
    replacement:
      "activity some vendors associate with malicious infrastructure",
  },
  {
    pattern:
      /\bC2\s+server\b/gi,
    replacement:
      "infrastructure some vendors associate with malicious activity",
  },
  {
    pattern:
      /\bphishing\s+host\b/gi,
    replacement:
      "infrastructure some vendors associate with credential theft",
  },
  {
    pattern:
      /\bif\s+you\s+confirm\s+malicious\s+use\b[^.]*\.?/gi,
    replacement:
      "If additional evidence corroborates malicious activity in your environment, follow your organization's incident-response process",
  },
  {
    pattern:
      /\bcompromised\s+host\s+contacting\s+(?:a\s+)?(?:C2|C&C|command[- ]and[- ]control)\s+server\b/gi,
    replacement:
      "an endpoint whose outbound traffic warrants review if it is unexpected in your environment",
  },
  {
    pattern:
      /\battackers\s+probing\s+your\s+service\b[^.]*\.?/gi,
    replacement:
      "inbound scanning or authentication attempts against an exposed service",
  },
  {
    pattern:
      /\bparticipation\s+in\s+(?:a\s+)?(?:botnet|command[- ]and[- ]control|C2)\b[^.]*\.?/gi,
    replacement:
      "activity that some vendors associate with malicious infrastructure; the specific operational role is not established by this lookup alone",
  },
  {
    pattern:
      /\binvolvement\s+in\s+(?:scanning|brute[- ]force)\b[^.]*\.?/gi,
    replacement:
      "activity that some vendors may associate with scanning or authentication attempts; the specific role is not established by this lookup alone",
  },
  {
    pattern:
      /\bcommand[- ]and[- ]control\s*\(C2\)\s+callbacks?\b/gi,
    replacement:
      "outbound communications that some vendors associate with malicious infrastructure",
  },
  {
    pattern:
      /\bsigns\s+of\s+brute[- ]force\s+attempts,?\s+command[- ]and[- ]control\b[^.]*\.?/gi,
    replacement:
      "patterns in your telemetry that would be consistent with scanning, authentication attempts, or other activity your baselines flag as unusual",
  },
  {
    pattern: /\bC2\s+callbacks?\b/gi,
    replacement: "communications some vendors associate with malicious infrastructure",
  },
  {
    pattern: /\bdata\s+exfiltration\b/gi,
    replacement: "unusual outbound data transfer patterns",
  },
];

const ASN_SPECULATION_PATTERNS = [
  {
    pattern:
      /\b(?:because|since|as)\s+(?:the\s+)?(?:organization|org|ASN|network)\s+(?:is\s+not\s+|isn'?t\s+)(?:a\s+)?(?:typical|normal|standard)\s+(?:hosting|ISP|cloud|provider)\b[^.]*\.?/gi,
    replacement:
      "The organization or network ownership information does not by itself establish malicious activity or compromise.",
  },
  {
    pattern:
      /\bthe\s+(?:organization|ASN|network)\s+(?:is\s+)?(?:likely|probably|suspicious|untrusted)\b[^.]*\.?/gi,
    replacement:
      "The organization or network ownership information does not by itself establish malicious activity or compromise.",
  },
  {
    pattern:
      /\b(?:because|since|as)\s+(?:it'?s?\s+)?(?:from|in)\s+(?:nigeria|russia|china|north\s+korea|iran)\b[^.]*\.?/gi,
    replacement:
      "Geography alone does not establish malicious activity. Assess the IP on the strength of the specific evidence in the tool result.",
  },
  {
    pattern:
      /\bbecause\s+it'?s?\s+an?\s+ISP\s+block,?\s+many\s+legitimate\s+users\s+also\s+share\s+the\s+address\b[^.]*\.?/gi,
    replacement:
      "This IP belongs to ISP-assigned address space; the available data does not distinguish malicious from legitimate use of a shared address.",
  },
  {
    pattern:
      /\bfalse\s+positives\s+are\s+possible,?\s+especially\s+for\s+(?:harmless|benign)\s+detections\b[^.]*\.?/gi,
    replacement:
      "A single vendor detection should be interpreted alongside the full distribution of detections and any available corroborating evidence.",
  },
  {
    pattern:
      /\bthe\s+IP\s+belongs\s+to\s+a\s+relatively\s+large\s+\/\d{1,2}\s+block,?\s+typical\s+of\s+ISP[- ]assigned\b[^.]*\.?/gi,
    replacement:
      "The IP is part of a larger network block; the size of the block alone does not establish the role of any individual address within it.",
  },
  {
    pattern:
      /\b(?:a\s+)?(?:Nigerian|Russian|Chinese|North\s+Korean|Iranian)\s+(?:ISP|network|host|IP)\s+(?:may|might|could)\s+be\s+(?:a\s+)?(?:legitimate|compromised|malicious)\b[^.]*\.?/gi,
    replacement:
      "Country and ASN ownership are contextual information only; they do not by themselves establish that any particular address or subscriber is malicious.",
  },
  {
    pattern:
      /\bcompromise\s+of\s+(?:a\s+)?(?:single\s+)?(?:subscriber|service|host|account)\b[^.]*?could\s+(?:produce|generate|cause|result\s+in)\s+malicious\s+traffic\b[^.]*\.?/gi,
    replacement:
      "Shared ISP infrastructure is used by many subscribers; a single detection does not identify any specific subscriber or service as the source of the activity.",
  },
  {
    pattern:
      /\b(?:Globacom|the\s+ISP|the\s+ASN)\s+is\s+a\s+major\s+carrier\b[^.]*?\.?/gi,
    replacement:
      "The IP belongs to a large ISP's address space; the size and reach of the ISP do not by themselves establish anything about this specific address.",
  },
  {
    pattern:
      /\bbecause\s+it\s+is\s+an?\s+ISP\b[^.]*\.?/gi,
    replacement:
      "ISP-assigned address space is shared infrastructure; assess the specific address on its own evidence.",
  },
  {
    pattern:
      /\b(?:subscriber|service)\s+could\s+produce\s+malicious\s+traffic\b/gi,
    replacement:
      "shared infrastructure may produce mixed traffic patterns; specific attribution requires additional evidence",
  },
  {
    pattern:
      /\bthe\s+network\s+block\s+is\s+a\s+fairly\s+large\b[^.]*\.?/gi,
    replacement:
      "The IP is part of a larger network block reported by VirusTotal; the size of the block does not by itself establish the role of any individual address within it.",
  },
  {
    pattern:
      /\bthe\s+IP\s+could\s+be\s+a\s+(?:residential|business|data[- ]center)\b[^.]*\.?/gi,
    replacement:
      "The available data does not establish the type of subscriber using this address.",
  },
  {
    pattern:
      /\bcompromised\s+hosts\s+or\s+misconfigured\s+services\s+can\s+exist\s+on\s+any\s+ISP'?s?\s+network\b/gi,
    replacement:
      "ISP-assigned address space is shared infrastructure; individual addresses should be assessed on their own evidence",
  },
  {
    pattern:
      /\bthat\s+does\s+not\s+guarantee\s+the\s+traffic\b[^.]*\.?/gi,
    replacement:
      "Ownership or geography alone does not establish the trustworthiness of an address.",
  },
];

const BROAD_BLOCK_PATTERNS = [
  {
    pattern: /\bblock\s+(?:the\s+)?(?:entire\s+)?(?:CIDR|network|range|subnet|\/\d{1,2}|\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/\d{1,2})\b/gi,
    replacement:
      "consider blocking the specific IP if malicious activity is confirmed in your environment and policy permits; avoid blocking the broader network range solely from this lookup",
  },
  {
    pattern: /\bblock\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/\d{1,2}\b/gi,
    replacement:
      "consider blocking the specific IP if malicious activity is confirmed in your environment and policy permits; avoid blocking the broader network range solely from this lookup",
  },
  {
    pattern: /\s*\(?\s*or\s+(?:the\s+)?(?:entire\s+|whole\s+|full\s+)?(?:\/\d{1,2}|CIDR|network|range|subnet)(?:\s+block)?\s*\)?/gi,
    replacement: " (specific IP only)",
  },
  {
    pattern: /\bblock\s+(?:the\s+)?(?:IP|address)\s+\(?\s*or\s+(?:the\s+)?(?:whole|entire)?\s*(?:\/\d{1,2}|CIDR|network|range)[^)]*\)?/gi,
    replacement:
      "block the specific IP if malicious activity is confirmed in your environment and policy permits; a broader range block requires separate justification",
  },
  {
    pattern: /\bor\s+the\s+entire\s+\/\d{1,2}\s+block\b/gi,
    replacement: "or the specific IP only",
  },
  {
    pattern: /\bthe\s+whole\s+\/\d{1,2}\b/gi,
    replacement: "the specific IP",
  },
  {
    pattern:
      /\bblock\s+only\s+if\s+the\s+connection\s+is\s+unsolicited\s+inbound\b/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is confirmed in your environment and organizational policy permits; inbound-only rules may miss outbound C2 traffic if the host is compromised",
  },
  {
    pattern:
      /\bconsider\s+temporarily\s+blocking\s+the\s+IP\s+until\s+you\s+can\s+confirm[^.]*\.?/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is confirmed and organizational policy permits; if traffic is expected, document the exception instead of blocking",
  },
  {
    pattern:
      /\b(?:access[- ]list\s+\S+\s+)?(?:extended\s+)?deny\s+ip\s+any\s+host\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/gi,
    replacement:
      "(single-IP deny example omitted; construct the specific rule only after confirming the malicious activity in your environment)",
  },
  {
    pattern:
      /\bblocklist\s+add\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/gi,
    replacement:
      "(blocklist entry omitted; add only after confirming the malicious activity in your environment)",
  },
  {
    pattern: /\bnetwork[- ]wide\s+block\b/gi,
    replacement:
      "block limited to the specific IP if malicious activity is confirmed and policy permits",
  },
  {
    pattern: /\bpermanent\s+block\b/gi,
    replacement:
      "long-term block of the specific IP only after malicious activity is corroborated and policy permits",
  },
  {
    pattern:
      /\bkeep\s+the\s+IP\s+on\s+a\s+watchlist[^.]*?\.?\s*(?:if\s+additional\s+detections\s+appear[^.]*?)?\s*consider\s+a\s+permanent\s+block\b[^.]*\.?/gi,
    replacement:
      "Consider re-checking the IP periodically. If additional vendor detections appear, reassess and follow your organization's policy for blocking.",
  },
  {
    pattern:
      /\badd\s+a\s+temporary\s+block\s*\([^)]*firewall\s+deny[^)]*\)/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is confirmed in your environment and policy permits",
  },
  {
    pattern:
      /\badd\s+(?:the\s+)?(?:IP|address)\s+to\s+(?:a\s+)?(?:blocklist|deny\s+list|denylist)\b[^.]*\.?/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is corroborated in your environment and policy permits",
  },
  {
    pattern:
      /\badd\s+IP\s+to\s+blocklist\s+if\s+persistent\b/gi,
    replacement:
      "consider blocking the specific IP only if malicious activity is corroborated and policy permits",
  },
  {
    pattern:
      /\bblock\s+or\s+monitor\s+it\s+pending\s+further\s+evidence\b/gi,
    replacement:
      "review it further if it appears in your telemetry, and act per your organization's policy",
  },
  {
    pattern:
      /\bblock\s+or\s+monitor\s+traffic\s+to\/?from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b[^.]*\.?/gi,
    replacement:
      "If unexpected connections to this IP appear in your telemetry, review the associated host, direction, and application context before deciding whether to block.",
  },
  {
    pattern:
      /\badd\s+a\s+rule\s+to\s+alert\s+on\s+any\s+traffic\s+involving\s+this\s+IP\b/gi,
    replacement:
      "consider adding a monitoring rule for this IP in your detection platform, to be reviewed if it fires",
  },
  {
    pattern:
      /\bisolate\s+the\s+host(?:\(s\)|s)?\s+and\s+perform\s+a\s+malware\s+scan\b/gi,
    replacement:
      "If additional evidence indicates endpoint compromise, follow your organization's incident-response containment procedure for that endpoint.",
  },
  {
    pattern:
      /\bisolate\s+host,?\s*run\s+(?:endpoint\s+detection\s*(?:&|and)\s*response|EDR)\s+scan,?\s*reset\s+credentials\b/gi,
    replacement:
      "If additional evidence indicates endpoint compromise, follow your organization's incident-response containment procedure, which may include endpoint scanning and credential rotation as your policy dictates.",
  },
  {
    pattern:
      /\bisolate\s+the\s+host\s+from\s+the\s+network\b/gi,
    replacement:
      "If additional evidence indicates endpoint compromise, follow your organization's incident-response containment procedure",
  },
  {
    pattern:
      /\badd\s+the\s+IP\s+\(or\s+its\s+\/\d{1,2}\s+network\s+block\)\s+to\s+any\s+threat[- ]intel\s+block\s+lists\b[^.]*\.?/gi,
    replacement:
      "consider adding the specific IP to a monitored watchlist only after malicious activity is corroborated in your environment and policy permits",
  },
  {
    pattern:
      /\b(?:iptables\s+-A\s+(?:INPUT|OUTPUT)\s+-[sd]\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-j\s+(?:DROP|REJECT)|New-NetFirewallRule[^\n]*?-Action\s+Block|netsh\s+advfirewall[^\n]*?block)\b[^\n]*/gi,
    replacement:
      "(example firewall rule omitted; construct the specific rule only after confirming malicious activity in your environment and policy permits)",
  },
];

/**
 * Phase 1.8 — invented severity/priority labels and unqualified
 * certainty language not already covered by CERTAINTY_PATTERNS.
 *
 * These map directly to the "NO INCIDENT PRIORITY" and
 * "NO 'CONFIRMED' LANGUAGE" rules: no low/medium/critical/urgent
 * priority label, no "hostile IP" / "dangerous IP", no "borderline
 * malicious", no unqualified "not clean", and no "clearly malicious" /
 * "definitely malicious" outside the multi-word certainty phrases
 * CERTAINTY_PATTERNS already rewrites.
 */
const SEVERITY_LABEL_PATTERNS = [
  {
    pattern: /\b(?:low|medium|high|critical|urgent|severe)\s+priority\b/gi,
    replacement:
      "a priority determined by your organization's own triage criteria",
  },
  {
    pattern: /\bpriority\s*:\s*(?:low|medium|high|critical|urgent|severe)\b/gi,
    replacement: "priority: to be determined by your organization's triage criteria",
  },
  {
    pattern: /\b(?:hostile|dangerous)\s+IP\b/gi,
    replacement: "IP reported by some vendors as associated with malicious activity",
  },
  {
    pattern: /\bborderline\s+malicious\b/gi,
    replacement: "showing a mixed signal that does not establish maliciousness",
  },
  {
    pattern: /\b(?:this|the)\s+(?:IP|indicator|address)\s+is\s+not\s+clean\b/gi,
    replacement:
      "has one or more vendor-reported malicious or suspicious detections, which does not by itself establish current maliciousness",
  },
  {
    pattern: /\bclearly\s+malicious\b/gi,
    replacement: "reported by some vendors as associated with malicious activity",
  },
  {
    pattern: /\bdefinitely\s+malicious\b/gi,
    replacement: "reported by some vendors as associated with malicious activity",
  },
];

/**
 * Phase 1.8 — invented fixed monitoring schedules.
 *
 * Maps to the "NO FIXED MONITORING PERIOD" rule: never invent a
 * schedule such as "daily for one week" or "for 30 days" unless the
 * user or organizational policy supplied it. Rewrites such phrases to
 * an open-ended, evidence-driven monitoring statement instead of
 * silently deleting the sentence.
 */
const MONITORING_DURATION_PATTERNS = [
  {
    pattern:
      /\bmonitor(?:ing)?\s+(?:(?:it|this|the)\s+)?(?:ip\s+)?(?:daily\s+)?for\s+(?:the\s+next\s+)?\d+\s*(?:day|days|week|weeks|month|months)\b[^.]*\.?/gi,
    replacement:
      "Continue monitoring for this IP in your telemetry; adjust the review cadence according to your organization's existing monitoring policy rather than a fixed schedule invented here.",
  },
  {
    pattern:
      /\bfor\s+(?:the\s+)?next\s+\d+\s*(?:day|days|week|weeks|month|months)\b[^.]*\.?/gi,
    replacement:
      "for a period consistent with your organization's existing monitoring policy",
  },
  {
    pattern: /\brecheck\s+(?:this\s+)?(?:ip|indicator)\s+in\s+\d+\s*(?:day|days|week|weeks|month|months)\b/gi,
    replacement:
      "recheck this IP periodically, per your organization's existing monitoring policy",
  },
];

/* =========================================================================
   SECTION B — Structured-output parsing and validation
   ========================================================================= */

function parseStructuredReply(reply) {
  if (!reply || typeof reply !== "string") return null;

  const fenced = reply.match(/```json\s*([\s\S]*?)```/i);
  const raw = fenced ? fenced[1] : null;
  if (!raw) return null;

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof parsed.assessment !== "string" ||
    !Array.isArray(parsed.observed) ||
    !Array.isArray(parsed.recommendedInvestigation)
  ) {
    return null;
  }

  return parsed;
}

/**
 * Content-level validation for a structured reply.
 *
 * Phase 1.7: rejects phrases that MUST NOT appear in the model's raw
 * output regardless of context. These are imperative action
 * instructions, definitive maliciousness claims, invented severity
 * labels, and raw firewall commands — the exact class of output that
 * the deterministic normalizer is designed to replace. Conceptual
 * mentions of threat roles (C2, botnet, phishing) are NOT rejected,
 * because a correctly-written assessment may mention them in the
 * context of "the lookup does not establish X". The normalizer
 * handles those in place.
 */
function validateStructuredReply(parsed) {
  if (!parsed || typeof parsed !== "object") return false;

  // Schema checks
  if (typeof parsed.assessment !== "string") return false;
  if (!Array.isArray(parsed.observed)) return false;
  if (!Array.isArray(parsed.recommendedInvestigation)) return false;

  const haystack = [
    parsed.assessment,
    parsed.limitations,
    parsed.mitigation,
    parsed.bottomLine,
    ...(parsed.recommendedInvestigation || []),
  ]
    .filter((x) => typeof x === "string")
    .join("\n");

  if (!haystack) return true;

  const forbidden = [
    // Definitive maliciousness claims
    /\bconfirmed\s+(?:to\s+be\s+|as\s+)?malicious\b/i,
    /\bdefinitively\s+malicious\b/i,
    /\bproven\s+malicious\b/i,
    /\bclearly\s+malicious\b/i,
    /\bdefinitely\s+malicious\b/i,
    /\bthe\s+IP\s+is\s+malicious\b/i,
    /\bthe\s+IP\s+is\s+not\s+clean\b/i,
    /\b(?:this|the)\s+(?:IP|indicator|address)\s+is\s+not\s+clean\b/i,

    // Invented severity / verdict labels (Phase 1.8: full "NO INCIDENT
    // PRIORITY" rule set, not just "high priority")
    /\bpotentially\s+hostile\b/i,
    /\bmoderate\s+risk\b/i,
    /\b(?:low|medium|high|critical|urgent|severe)\s+priority\b/i,
    /\bpriority\s*:\s*(?:low|medium|critical|urgent|severe)\b/i,
    /\b(?:hostile|dangerous)\s+IP\b/i,
    /\bborderline\s+malicious\b/i,

    // Raw imperative block instructions
    /\biptables\s+-A\b/i,
    /\bNew-NetFirewallRule\b/i,
    /\bdeny\s+ip\s+any\s+host\b/i,
    /\bblocklist\s+add\b/i,

    // Broad-range blocking directives
    /\bblock\s+the\s+(?:\/\d{1,2}|CIDR|network|range)\b/i,

    // Unconditional containment directives
    /\bisolate\s+the\s+host\b/i,
    /\bquarantine\s+the\s+endpoint\b/i,
    /\bblock\s+or\s+quarantine\b/i,

    // Safe-to-ignore verdicts
    /\bsafe\s+to\s+ignore\b/i,

    // Phase 1.8: invented fixed monitoring schedules
    /\bmonitor(?:ing)?\s+(?:(?:it|this|the)\s+)?(?:ip\s+)?(?:daily\s+)?for\s+(?:the\s+next\s+)?\d+\s*(?:day|days|week|weeks|month|months)\b/i,
  ];

  return !forbidden.some((p) => p.test(haystack));
}

/* =========================================================================
   SECTION C — SECURITY NORMALIZATION (the security boundary)
   ========================================================================= */

function normalizeStructuredSecurityAssessment(parsed) {
  if (!parsed || typeof parsed !== "object") return parsed;

  const out = JSON.parse(JSON.stringify(parsed));

  const evidence = extractEvidence(out.observed || []);

  if (out.target && Array.isArray(out.observed)) {
    const indicatorIndex = out.observed.findIndex((item) => item && String(item.field || "").toLowerCase() === "indicator");
    if (indicatorIndex >= 0) out.observed[indicatorIndex].value = String(out.target);
    else out.observed.unshift({ field: "Indicator", value: String(out.target), source: "VirusTotal" });
  }

  if (typeof out.title !== "string" || !out.title.trim()) {
    out.title = "VirusTotal IP Investigation";
  }

  out.assessment = normalizeAssessmentText(out.assessment, evidence);
  out.confidence = deriveConfidence(evidence, out.confidence);
  out.limitations = normalizeLimitationsText(out.limitations, evidence);
  out.recommendedInvestigation = normalizeRecommendations(
    out.recommendedInvestigation,
    evidence
  );
  out.mitigation = normalizeMitigationText(out.mitigation, evidence);
  out.bottomLine = normalizeBottomLineText(out.bottomLine, evidence);

  return out;
}

/* -------------------------------------------------------------------------
   Evidence extraction
   ------------------------------------------------------------------------- */

function extractEvidence(observed) {
  const result = {
    malicious: null,
    suspicious: null,
    harmless: null,
    undetected: null,
    reputation: null,
    lastAnalysis: null,
    hasData: false,
  };

  if (!Array.isArray(observed)) return result;

  for (const item of observed) {
    if (!item || typeof item !== "object") continue;
    const field = String(item.field || "").toLowerCase();
    const value = String(item.value || "");
    const num = parseInt(value.replace(/[^\d-]/g, ""), 10);

    if (/malicious/.test(field) && !isNaN(num)) {
      result.malicious = num;
      result.hasData = true;
    } else if (/suspicious/.test(field) && !isNaN(num)) {
      result.suspicious = num;
      result.hasData = true;
    } else if (/harmless/.test(field) && !isNaN(num)) {
      result.harmless = num;
      result.hasData = true;
    } else if (/undetected/.test(field) && !isNaN(num)) {
      result.undetected = num;
      result.hasData = true;
    } else if (/reputation/.test(field) && !isNaN(num)) {
      result.reputation = num;
      result.hasData = true;
    } else if (/last\s*analysis|last_analysis/.test(field)) {
      result.lastAnalysis = value;
      result.hasData = true;
    }
  }

  return result;
}

/* -------------------------------------------------------------------------
   Assessment text normalization
   ------------------------------------------------------------------------- */

function normalizeAssessmentText(text, evidence) {
  const base =
    typeof text === "string" && text.trim() ? text.trim() : "";

  let cleaned = stripThreatRoleClaims(base);
  cleaned = stripCategoricalMaliciousnessClaims(cleaned);
  cleaned = stripReputationInterpretation(cleaned);

  const calibrated = buildCalibratedAssessment(evidence);

  if (!cleaned) return calibrated;

  if (/weak and mixed|mixed signal|elevated concern|no detections/i.test(cleaned)) {
    return cleaned;
  }

  return `${calibrated}\n\n${cleaned}`;
}

function buildCalibratedAssessment(evidence) {
  const m = evidence.malicious;
  const s = evidence.suspicious;
  const h = evidence.harmless;
  const u = evidence.undetected;

  if (!evidence.hasData || m === null) {
    return "The available VirusTotal intelligence is insufficient to make a calibrated assessment. The reputation value and detection counts should be interpreted together, not in isolation.";
  }

  const totalNeg = (m || 0) + (s || 0);
  const totalClean = (h || 0) + (u || 0);

  if (m === 0 && (s === 0 || s === null)) {
    return "The available VirusTotal intelligence reports no malicious or suspicious detections. This does not by itself establish that the IP is benign or safe to ignore; the absence of detections is not proof of safety.";
  }

  if (totalNeg >= 10) {
    return `The available VirusTotal intelligence shows an elevated signal: ${m} malicious and ${s || 0} suspicious detections, alongside ${h || 0} harmless and ${u || 0} undetected results. This warrants contextual investigation if the IP appears in your environment. The detection counts alone do not establish the IP's specific operational role or current state.`;
  }

  if (totalNeg >= 1) {
    return `The available VirusTotal intelligence presents a weak and mixed signal. ${m} vendor${m === 1 ? "" : "s"} report${m === 1 ? "s" : ""} a malicious detection and ${s || 0} report${(s || 0) === 1 ? "s" : ""} a suspicious detection, while ${totalClean} report${totalClean === 1 ? "s" : ""} harmless or undetected results. This does not establish that the IP is currently malicious or that it represents C2, botnet, phishing, or other specific malicious infrastructure.`;
  }

  return "The available VirusTotal intelligence does not allow a confident assessment.";
}

function stripThreatRoleClaims(text) {
  if (!text) return "";
  return text
    .replace(
      /\b(?:likely|possible|probable|suspected)\s+(?:C2|C&C|botnet|ransomware|phishing|spam)\s+(?:server|beacon|relay|host|infrastructure)\b/gi,
      "infrastructure that some vendors associate with malicious or suspicious activity"
    )
    .replace(/\bC2\s+beacon\b/gi, "an activity pattern some vendors associate with malicious infrastructure")
    .replace(/\bspam\s+relay\b/gi, "an activity pattern some vendors associate with unwanted messaging")
    .replace(/\bphishing\s+relay\b/gi, "an activity pattern some vendors associate with credential theft")
    .replace(/\b(?:C2|C&C|command\s*(?:and|&)\s*control)\s+(?:server|host|endpoint|infrastructure)\b/gi, "infrastructure that some vendors associate with malicious activity")
    .replace(/\b(?:botnet|ransomware\s+infrastructure|phishing\s+infrastructure|malware\s+infrastructure|compromised\s+infrastructure)\b/gi, "infrastructure that some vendors associate with malicious activity");
}

function stripCategoricalMaliciousnessClaims(text) {
  if (!text) return "";
  return text
    .replace(
      /\b(?:confirmed|definitively|proven|established)\s+(?:to be\s+)?(?:malicious|hostile|a\s+threat|compromised|infected)\b/gi,
      "reported by some vendors as associated with malicious activity"
    )
    .replace(
      /\b(?:is|are)\s+(?:a\s+)?(?:malicious|hostile)\s+(?:IP|address|host|server|infrastructure)\b/gi,
      "is reported by some vendors as associated with malicious activity"
    )
    .replace(
      /\b(?:confirmed|definitively|proven)\s+(?:malicious|hostile)\s+(?:detection|activity|indicator|signal|result)\b/gi,
      "vendor-reported malicious detection"
    )
    .replace(/\bhigh[- ]priority\s+alert\b/gi, "potentially significant signal");
}

function stripReputationInterpretation(text) {
  if (!text) return "";
  return text
    .replace(
      /\breputation\s+(?:value\s+)?(?:of\s+)?[-–—]?\d+\s+(?:indicates|means|signals|suggests|implies)\b[^.]*\.?/gi,
      "The reputation value is a source-specific signal and should be interpreted alongside the individual detection results rather than treated as a probability of maliciousness."
    )
    .replace(
      /\b(?:just\s+)?(?:below|above)\s+neutral\b/gi,
      "negative within the source's proprietary scale"
    )
    .replace(
      /\b(?:slightly|mildly|somewhat)\s+(?:negative|positive)\b/gi,
      "mixed within the source's proprietary scale"
    )
    .replace(
      /\b(?:low|high)[- ]risk\b/gi,
      "showing a mixed signal"
    );
}

/* -------------------------------------------------------------------------
   Confidence derivation
   ------------------------------------------------------------------------- */

function deriveConfidence(evidence, modelValue) {
  const m = evidence.malicious;
  const s = evidence.suspicious;

  if (m === null) return "low";

  const totalNeg = (m || 0) + (s || 0);

  if (totalNeg >= 10) return "moderate";
  if (totalNeg >= 1) return "low";
  return "low";
}

/* -------------------------------------------------------------------------
   Limitations text normalization
   ------------------------------------------------------------------------- */

function normalizeLimitationsText(text, evidence) {
  const parts = [];

  if (evidence.lastAnalysis) {
    parts.push(
      `The findings reflect the available VirusTotal analysis from ${evidence.lastAnalysis} and may not represent the IP's current state.`
    );
  }

  parts.push(
    "VirusTotal intelligence alone does not establish that the IP is currently malicious, that the infrastructure is compromised, or that an internal system communicating with the IP is compromised."
  );

  return parts.join(" ");
}

/* -------------------------------------------------------------------------
   Recommendations normalization
   ------------------------------------------------------------------------- */

const STANDARD_RECOMMENDATIONS = [
  "If the IP appears in firewall, proxy, DNS, or SIEM telemetry, review the associated source host, destination port, protocol, timestamps, frequency, and application context.",
  "If the communication is unexpected, investigate the associated endpoint and network telemetry according to your organization's incident-response procedures.",
  "If additional threat-intelligence sources corroborate malicious activity, increase the investigation priority accordingly.",
  "If no communication with this IP is observed in your environment, no immediate containment action is indicated from this lookup alone.",
];

function normalizeRecommendations(recommendations, evidence) {
  return STANDARD_RECOMMENDATIONS.slice();
}

/* -------------------------------------------------------------------------
   Mitigation text normalization
   ------------------------------------------------------------------------- */

function normalizeMitigationText(text, evidence) {
  return "If malicious activity is corroborated in your environment and organizational policy permits, consider blocking the specific IP address. Do not block the broader network range solely because this IP appears in threat-intelligence results.";
}

/* -------------------------------------------------------------------------
   Bottom line normalization
   ------------------------------------------------------------------------- */

function normalizeBottomLineText(text, evidence) {
  const m = evidence.malicious;
  const s = evidence.suspicious;

  if (m === null) {
    return "The available intelligence does not support a confident conclusion. If this IP appears in your environment, review the associated traffic.";
  }

  const totalNeg = (m || 0) + (s || 0);

  if (totalNeg === 0) {
    return "The available intelligence reports no detections. This does not establish that the IP is benign or safe to ignore.";
  }

  if (totalNeg >= 10) {
    return "The available intelligence reports an elevated malicious/suspicious signal. Investigate if the IP appears in your environment; the detection counts alone do not establish current maliciousness.";
  }

  return "The available intelligence reports a limited but non-zero malicious/suspicious signal. Investigate only if the IP appears in your environment; the lookup alone does not establish current malicious activity.";
}

/* =========================================================================
   SECTION D — Markdown rendering of a normalized structured object
   ========================================================================= */

function renderStructuredReply(parsed) {
  const lines = [];

  if (parsed.title) lines.push(`## ${parsed.title}`);
  if (parsed.target) lines.push(`### Target\n${parsed.target}`);

  if (Array.isArray(parsed.observed) && parsed.observed.length > 0) {
    lines.push("### Observed Intelligence");
    for (const item of parsed.observed) {
      const src = item && item.source ? ` _(${item.source})_` : "";
      const field = item && item.field ? item.field : "(field)";
      const value = item && item.value ? item.value : "";
      lines.push(`- ${field}: ${value}${src}`);
    }
  }

  if (parsed.assessment) {
    lines.push(`### Assessment\n${parsed.assessment}`);
  }

  if (parsed.confidence) {
    lines.push(`### Confidence\n${capitalizeFirst(parsed.confidence)}`);
  }

  if (parsed.limitations) {
    lines.push(`### Limitations\n${parsed.limitations}`);
  }

  if (
    Array.isArray(parsed.recommendedInvestigation) &&
    parsed.recommendedInvestigation.length > 0
  ) {
    lines.push("### Recommended Investigation");
    parsed.recommendedInvestigation.forEach((step, i) => {
      lines.push(`${i + 1}. ${step}`);
    });
  }

  if (parsed.mitigation) {
    lines.push(`### Mitigation\n${parsed.mitigation}`);
  }

  if (parsed.bottomLine) {
    lines.push(`### Bottom Line\n${parsed.bottomLine}`);
  }

  return lines.join("\n\n");
}

function capitalizeFirst(s) {
  if (!s || typeof s !== "string") return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/* =========================================================================
   SECTION E — Final regex sweep and CIDR scrubber
   ========================================================================= */

/**
 * CIDR scrubber, Phase 1.7.
 *
 * Rewrites wider-than-/32 CIDR tokens inside blocking/deny
 * recommendations so the reply never recommends blocking a broader
 * range. It MUST NOT touch:
 *   - the Observed Intelligence section,
 *   - bullet lines,
 *   - Markdown table rows,
 *   - CIDRs that are being *referenced* rather than *recommended as
 *     blocking targets*.
 *
 * A CIDR is treated as a reference (and preserved) when it is
 * preceded by a reference word such as "the", "than", "in", "at", or
 * a reference verb such as "appears", "represents", "is", "was",
 * "has", "had". It is treated as a blocking target (and rewritten to
 * /32) otherwise.
 */
function scrubResidualCIDRsFromBlocking(text) {
  if (!text || typeof text !== "string") return text;
  const lines = text.split("\n");
  const out = [];

  let inObservedSection = false;
  let inObservedTable = false;

  for (const line of lines) {
    if (/^\s*#{1,6}\s+Observed\s+Intelligence\b/i.test(line)) {
      inObservedSection = true;
      inObservedTable = false;
      out.push(line);
      continue;
    }

    if (/^\s*#{1,6}\s+/.test(line)) {
      inObservedSection = false;
      inObservedTable = false;
      out.push(line);
      continue;
    }

    if (inObservedSection) {
      out.push(line);
      continue;
    }

    if (/^\s*[-*•]\s+/.test(line)) {
      out.push(line);
      continue;
    }

    if (/^\s*\|.*\|\s*$/.test(line)) {
      inObservedTable = true;
      out.push(line);
      continue;
    }

    if (inObservedTable && /^\s*$/.test(line)) {
      inObservedTable = false;
      out.push(line);
      continue;
    }

    if (inObservedTable) {
      out.push(line);
      continue;
    }

    if (/\b(?:block|deny)\b/i.test(line) && /\/\d{1,2}\b/.test(line)) {
      const cleaned = line.replace(
        /((?:\b(?:the|than|in|at)\s+)|(?:\b(?:appears?|represents?|is|was|has|had)\s+))?(\/\d{1,2})\b/gi,
        (match, prefix, cidr) => {
          // Preserve referenced observations in their original form.
          if (prefix) return match;
          const bits = parseInt(cidr.slice(1), 10);
          if (bits === 32) return cidr;
          return "/32";
        }
      );
      out.push(cleaned);
    } else {
      out.push(line);
    }
  }

  return out.join("\n");
}


/* =========================================================================
   SECTION F — Raw evidence bridge
   ========================================================================= */

function unwrapEvidenceObject(value, depth = 0) {
  if (!value || typeof value !== "object" || depth > 6) return null;
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = unwrapEvidenceObject(item, depth + 1);
      if (found) return found;
    }
    return null;
  }

  const keys = Object.keys(value).map((k) => k.toLowerCase());
  const expected = ["malicious", "suspicious", "harmless", "undetected", "reputation", "lastanalysisdate", "last_analysis_date"];
  if (expected.some((k) => keys.includes(k))) return value;

  for (const key of ["data", "result", "response", "attributes", "analysis", "evidence", "raw"]) {
    if (value[key]) {
      const found = unwrapEvidenceObject(value[key], depth + 1);
      if (found) return found;
    }
  }
  return null;
}

function firstSuccessfulVirusTotalEvidence(rawToolEvidence) {
  if (!Array.isArray(rawToolEvidence)) return null;
  const item = rawToolEvidence.find((entry) => entry && entry.toolName === "virustotal_ip_lookup" && entry.ok === true && entry.output);
  if (!item) return null;
  return { entry: item, data: unwrapEvidenceObject(item.output) || item.output };
}

function readField(obj, names) {
  if (!obj || typeof obj !== "object") return undefined;
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(obj, name) && obj[name] !== undefined && obj[name] !== null) return obj[name];
  }
  return undefined;
}

function buildStructuredAssessmentFromRawEvidence(rawToolEvidence, target) {
  const found = firstSuccessfulVirusTotalEvidence(rawToolEvidence);
  if (!found) return null;
  const data = found.data || {};
  const inputIp = found.entry.input && found.entry.input.ip;
  const indicator = readField(data, ["ip", "indicator", "id"]) || inputIp || target || undefined;

  const observed = [];
  const add = (field, value) => {
    if (value !== undefined && value !== null && value !== "") observed.push({ field, value: String(value), source: "VirusTotal" });
  };
  add("Indicator", indicator);
  add("country", readField(data, ["country", "countryOrRegion"]));
  add("asOwner", readField(data, ["asOwner", "as_owner", "asOwnerName"]));
  add("asn", readField(data, ["asn", "autonomousSystemNumber"]));
  add("network", readField(data, ["network", "networkRange", "cidr"]));
  add("reputation", readField(data, ["reputation"]));
  add("malicious", readField(data, ["malicious", "maliciousCount"]));
  add("suspicious", readField(data, ["suspicious", "suspiciousCount"]));
  add("harmless", readField(data, ["harmless", "harmlessCount"]));
  add("undetected", readField(data, ["undetected", "undetectedCount"]));
  add("lastAnalysisDate", readField(data, ["lastAnalysisDate", "last_analysis_date", "lastAnalysis"]));

  if (!indicator && observed.length === 0) return null;

  const parsed = {
    title: "VirusTotal IP Investigation",
    target: indicator || target || "",
    observed,
    assessment: "",
    confidence: "low",
    limitations: "",
    recommendedInvestigation: [],
    mitigation: "",
    bottomLine: "",
  };

  const normalized = normalizeStructuredSecurityAssessment(parsed);
  return renderStructuredReply(normalized);
}


const EXTERNAL_INTELLIGENCE_PROVIDERS = new Set([
  "virustotal", "abuseipdb", "shodan", "ipinfo", "censys",
  "viewdns", "urlscan", "securitytrails", "mozilla_observatory", "hibp",
]);

const INTERNAL_TELEMETRY_PROVIDER_PATTERNS = [
  /^(?:edr|xdr|endpoint|endpoint_security)$/i,
  /^(?:siem|splunk|sentinel|sentinelone|elastic|qradar|chronicle|defender)$/i,
  /^(?:firewall|fw|network_firewall|ngfw)$/i,
  /^(?:dns|dns_logs|resolver|proxy|web_proxy)$/i,
  /^(?:authentication|auth|identity|idp|iam)$/i,
  /^(?:cloudtrail|azure_activity|azure_activity_logs|cloud_audit|gcp_audit)$/i,
  /^(?:kubernetes_audit|k8s_audit|application_logs|app_logs|network_flow|netflow|packet_capture|ids|ips)$/i,
];

function isInternalTelemetrySource(source) {
  if (!source || typeof source !== "object") return false;
  const provider = String(source.provider || "").trim();
  const tool = String(source.tool || "").trim();
  if (EXTERNAL_INTELLIGENCE_PROVIDERS.has(provider.toLowerCase())) return false;
  if (INTERNAL_TELEMETRY_PROVIDER_PATTERNS.some((pattern) => pattern.test(provider))) return true;
  if (INTERNAL_TELEMETRY_PROVIDER_PATTERNS.some((pattern) => pattern.test(tool.replace(/_lookup$|_scan$/i, "")))) return true;

  // Be deliberately conservative with source metadata. A technical field
  // such as `connection`, `network`, or `dns` inside an external provider is
  // not environmental telemetry. Only an explicitly internal source can
  // establish this dimension.
  const sourceType = String(source.sourceType || source.category || source.evidenceSource || "").toLowerCase();
  return /^(internal|environmental|telemetry)$/.test(sourceType);
}

function sourceHasMeaningfulEvidence(source) {
  // Meaningfulness is a canonical normalized field. Do not infer it from
  // status or from the presence of arbitrary provider data.
  return !!source && source.quality?.meaningful === true;
}

function deriveFinalInvestigationAssessment(investigation) {
  const sources = Array.isArray(investigation?.sources) ? investigation.sources : [];
  const meaningfulSources = sources.filter(sourceHasMeaningfulEvidence);
  const meaningfulProviders = new Set(
    meaningfulSources.map((source) => String(source.provider || "").trim().toLowerCase()).filter(Boolean)
  );
  const internalSources = meaningfulSources.filter(isInternalTelemetrySource);
  const internalTelemetryExists = internalSources.length > 0;

  const externalReputationFindings = (Array.isArray(investigation?.findings) ? investigation.findings : [])
    .filter((finding) => finding && finding.evidenceType === "reputation" &&
      Array.isArray(finding.providers) && finding.providers.some((provider) => EXTERNAL_INTELLIGENCE_PROVIDERS.has(String(provider).toLowerCase())));
  const externalReputationElevated = externalReputationFindings.some((finding) =>
    String(finding.severity || "").toLowerCase() === "elevated" ||
    /elevated|malicious|abuse confidence/i.test(String(finding.description || ""))
  );

  const externalThreat = externalReputationElevated ? "elevated" :
    meaningfulSources.some((source) => EXTERNAL_INTELLIGENCE_PROVIDERS.has(String(source.provider || "").toLowerCase())) ? "unknown" : "unknown";

  let environmentalRisk = "unknown";
  if (internalTelemetryExists) {
    const environmentalFindings = (Array.isArray(investigation?.findings) ? investigation.findings : [])
      .filter((finding) => finding && (finding.evidenceType === "environmental" || finding.evidenceType === "behavioral"));
    const direct = environmentalFindings.some((finding) => String(finding.strength || "").toLowerCase() === "direct");
    const corroborated = environmentalFindings.some((finding) => String(finding.strength || "").toLowerCase() === "corroborated");
    environmentalRisk = direct ? "elevated" : corroborated ? "elevated" : "unknown";
  }

  const failedOrNonMeaningful = sources.some((source) => {
    const status = String(source?.status || "").toLowerCase();
    return !["success"].includes(status) || !sourceHasMeaningfulEvidence(source);
  });
  const evidenceCoverage = meaningfulSources.length === 0 ? "none" :
    meaningfulSources.length >= 2 ? "broad" : "limited";
  const sourceAvailability = failedOrNonMeaningful ? "partial" : "complete";

  const externalIntelligenceConfidence = externalThreat === "elevated"
    ? ((new Set(externalReputationFindings.flatMap((finding) => finding.providers || [])).size >= 2) ? "high" : "moderate")
    : meaningfulSources.length >= 2 ? "moderate" : "low";
  const environmentalAssessmentConfidence = internalTelemetryExists ? "moderate" : "low";

  const overallConfidence = externalIntelligenceConfidence === "high" && environmentalAssessmentConfidence === "low"
    ? "high_external_low_environmental"
    : externalIntelligenceConfidence === "high" && environmentalAssessmentConfidence !== "low"
      ? "high"
      : "moderate";

  const overallConfidenceText = overallConfidence === "high_external_low_environmental"
    ? "High confidence in the external intelligence assessment; low confidence regarding environmental impact because no internal telemetry was supplied."
    : overallConfidence === "high"
      ? "High confidence based on the available external intelligence and environmental evidence."
      : "Confidence is limited by the available evidence and source coverage.";

  return {
    meaningfulSources,
    meaningfulProviders,
    meaningfulProviderCount: meaningfulProviders.size,
    internalSources,
    internalTelemetryExists,
    externalThreat,
    environmentalRisk,
    evidenceCoverage,
    sourceAvailability,
    externalIntelligenceConfidence,
    environmentalAssessmentConfidence,
    overallConfidence,
    overallConfidenceText,
  };
}

function sourcesForCount(investigation) {
  const sources = Array.isArray(investigation?.sources) ? investigation.sources : [];
  return new Set(sources.map((source) => String(source?.provider || "").trim().toLowerCase()).filter(Boolean)).size || sources.length;
}

function renderInvestigationReport(investigation) {
  if (!investigation || typeof investigation !== "object") return "";
  const lines = [];
  const typeLabel = investigation.targetType || "unknown";
  const title = `${typeLabel.charAt(0).toUpperCase() + typeLabel.slice(1)} Security Investigation`;
  lines.push(`## ${title}`);
  lines.push(`### Target\n${investigation.target || "Unknown"}`);
  lines.push(`### Target Type\n${typeLabel}`);
  lines.push(`### Investigation Status\n${investigation.status || "unknown"}`);

  const statusIcon = (status) => status === "success" ? "✓" : (["not_required","skipped"].includes(status) ? "—" : "⚠");
  const providerLabels = {virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",urlscan:"URLScan",shodan:"Shodan",ipinfo:"IPinfo",censys:"Censys",securitytrails:"SecurityTrails",mozilla_observatory:"Mozilla Observatory",viewdns:"ViewDNS",hibp:"Have I Been Pwned"};
  const renderValue = (value) => Array.isArray(value) ? value.map((item) => typeof item === "object" ? JSON.stringify(item) : String(item)).join(", ") : (typeof value === "object" && value !== null ? JSON.stringify(value) : String(value));

  lines.push("### Threat Intelligence Sources");
  for (const source of Array.isArray(investigation.sources) ? investigation.sources : []) {
    const status = source.status || "unknown";
    const label = providerLabels[source.provider] || source.provider || "unknown";
    lines.push(`- ${statusIcon(status)} ${label} — ${status}`);
    if ((status === "success" || status === "partial" || status === "empty") && source.findings && typeof source.findings === "object") {
      const entries = Object.entries(source.findings);
      if (!entries.length) lines.push("  - No provider records returned.");
      for (const [field, value] of entries) lines.push(`  - ${field}: ${renderValue(value)}`);
    }
    if (source.quality) lines.push(`  - evidenceQuality: ${source.quality.directness}; meaningful=${source.quality.meaningful}; freshness=${source.quality.freshness?.status || "unknown"}`);
    for (const limitation of Array.isArray(source.limitations) ? source.limitations : []) lines.push(`  - limitation: ${limitation}`);
    for (const error of Array.isArray(source.errors) ? source.errors : []) if (error?.message) lines.push(`  - reason: ${String(error.message).slice(0,500)}`);
  }

  if (investigation.findings?.length) {
    lines.push("### Key Findings");
    for (const finding of investigation.findings) {
      const providers = Array.isArray(finding.providers) && finding.providers.length ? ` (${finding.providers.join(", ")})` : "";
      lines.push(`- [${finding.evidenceType || "context"}; ${finding.strength || "inconclusive"}] ${finding.description}${providers}`);
    }
  }

  const censysSource = (Array.isArray(investigation.sources) ? investigation.sources : []).find((source) =>
    String(source?.provider || "").toLowerCase() === "censys" && sourceHasMeaningfulEvidence(source)
  );
  if (censysSource) {
    const services = censysSource.findings?.services;
    const serviceText = Array.isArray(services) && services.length ? `multiple services, including ${services.some((service) => /80/.test(JSON.stringify(service))) ? "TCP/80" : "observed TCP services"}` : "multiple observed services";
    lines.push(`- [network; direct] Censys observed ${serviceText} on the host, corroborating the Tor-exit infrastructure context without by itself establishing malicious activity. (Censys)`);
  }
  lines.push("### Correlated Evidence");
  if (investigation.correlations?.length) for (const item of investigation.correlations) lines.push(`- [${item.evidenceType || "correlation"}; ${item.strength || item.confidence || "corroborated"}] ${item.description}`);
  else lines.push("- No genuine cross-provider correlation was established from meaningful evidence.");

  lines.push("### Conflicts");
  if (investigation.conflicts?.length) for (const item of investigation.conflicts) lines.push(`- ${item.description} Resolution: ${item.resolution || "unresolved"}.`);
  else lines.push("- No same-dimension provider conflict was identified.");

  const assessment = deriveFinalInvestigationAssessment(investigation);

  // SecurityAssessment owns the final semantic boundary. Do not trust an
  // upstream aggregate that may have counted technical observations from
  // external providers as environmental telemetry. Provider count is also
  // derived here from normalized meaningful sources, never from LLM text.
  lines.push("### External Threat Assessment");
  lines.push(`- External threat: ${assessment.externalThreat}`);

  lines.push("### Environmental Risk");
  lines.push(`- Environmental risk: ${assessment.environmentalRisk}`);
  if (!assessment.internalTelemetryExists) lines.push("- No internal/environmental telemetry was supplied; external intelligence does not establish environmental compromise or impact.");

  lines.push("### Evidence Coverage");
  lines.push(`- ${assessment.evidenceCoverage}`);
  lines.push(`- Source availability: ${assessment.sourceAvailability}`);
  lines.push(`- Meaningful providers: ${assessment.meaningfulProviderCount} / ${sourcesForCount(investigation)}`);

  lines.push("### Confidence");
  lines.push(`- External intelligence confidence: ${assessment.externalIntelligenceConfidence}`);
  lines.push(`- Environmental assessment confidence: ${assessment.environmentalAssessmentConfidence}`);
  lines.push(`- Overall investigation confidence: ${assessment.overallConfidenceText}`);
  lines.push(`- ${assessment.meaningfulSources.length} meaningful source result(s) across ${assessment.meaningfulProviderCount} provider(s).`);

  lines.push("### MITRE ATT&CK");
  if (Array.isArray(investigation.mitre) && investigation.mitre.length) for (const item of investigation.mitre) lines.push(`- ${item.techniqueId || "Potential mapping"}: ${item.techniqueName || ""} — ${item.rationale || ""}`);
  else lines.push("- No technique confidently mapped from the available evidence.");

  lines.push("### Limitations");
  for (const limitation of Array.isArray(investigation.limitations) ? investigation.limitations : []) lines.push(`- ${limitation}`);

  lines.push("### Recommended Investigation");
  const hasEnvironmental = investigation.risk?.environmentalRisk && investigation.risk.environmentalRisk !== "unknown";
  lines.push("1. If the indicator appears in firewall, proxy, DNS, SIEM, network-flow, or endpoint telemetry, correlate timestamps, source asset, destination port/protocol, frequency, and application context.");
  lines.push("2. If the communication is unexpected, review the affected endpoint/process and associated DNS, EDR, authentication, and network telemetry.");
  lines.push("3. If independent intelligence and internal telemetry corroborate malicious activity, follow the organization's incident-response procedures and controlled remediation workflow.");
  if (!hasEnvironmental) lines.push("4. If the indicator does not appear in the environment, record the external intelligence for context and continue normal monitoring rather than treating the absence as proof of benignness.");

  lines.push("### Bottom Line");
  if (assessment.externalThreat === "elevated" && assessment.environmentalRisk === "unknown") {
    lines.push("The target has elevated external threat-reputation indicators based on the available intelligence. The evidence does not establish compromise, successful intrusion, or environmental impact; internal telemetry is required to determine what, if anything, happened inside the user's environment.");
  } else if (assessment.environmentalRisk === "unknown") {
    lines.push("The available external intelligence is insufficient to determine environmental impact. Internal telemetry is required to establish whether the target affected the environment.");
  } else {
    lines.push("The investigation assessment is based on the supplied external intelligence and available environmental telemetry, with source limitations documented above.");
  }

  return lines.join("\n\n");
}

/* =========================================================================
   SECTION F — Public API
   ========================================================================= */

function applySecurityAssessment(reply, context = {}) {
  const rawToolEvidence = Array.isArray(context.rawToolEvidence) ? context.rawToolEvidence : [];
  const usedThreatIntel = Array.isArray(context.toolsUsed) &&
    context.toolsUsed.some((tool) => tool && /_(lookup|scan)$/.test(tool));

  // The investigation object is the canonical internal assessment input.
  // Raw provider evidence remains authoritative for source-specific facts.
  if (context.investigation && typeof context.investigation === "object") {
    return applyRegexSweep(renderInvestigationReport(context.investigation), context);
  }

  if (usedThreatIntel && rawToolEvidence.length > 0) {
    const deterministic = buildStructuredAssessmentFromRawEvidence(rawToolEvidence, context.target);
    if (deterministic) return applyRegexSweep(deterministic, context);
  }

  if (!reply || typeof reply !== "string") return reply;
  const parsed = parseStructuredReply(reply);
  if (parsed && validateStructuredReply(parsed)) {
    const normalized = normalizeStructuredSecurityAssessment(parsed);
    const rendered = renderStructuredReply(normalized);
    return applyRegexSweep(rendered, context);
  }
  return applyRegexSweep(reply, context);
}

function applyRegexSweep(reply, context = {}) {
  if (!reply || typeof reply !== "string") return reply;

  const toolsUsed = Array.isArray(context.toolsUsed) ? context.toolsUsed : [];
  const usedThreatIntel = toolsUsed.some((tool) => tool && /_(lookup|scan)$/.test(tool));

  let out = reply;

  for (const { pattern, replacement } of CERTAINTY_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  for (const { pattern, replacement } of CATEGORY_CLAIM_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  for (const { pattern, replacement } of ASN_SPECULATION_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  for (const { pattern, replacement } of BROAD_BLOCK_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  for (const { pattern, replacement } of SEVERITY_LABEL_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  for (const { pattern, replacement } of MONITORING_DURATION_PATTERNS) {
    out = out.replace(pattern, replacement);
  }

  out = scrubResidualCIDRsFromBlocking(out);

  if (
    usedThreatIntel &&
    !/limitations?|confidence|does not (?:establish|prove)/i.test(out)
  ) {
    out +=
      "\n\n### Limitations\n\nThis assessment is based on the available threat-intelligence data only. It does not, by itself, establish that the IP is currently malicious, that any infrastructure is compromised, or that any internal system communicating with this IP is compromised.";
  }

  out = out.replace(/[ \t]+\n/g, "\n").replace(/\n{4,}/g, "\n\n\n");

  return out.trim() === reply.trim() ? reply : out;
}

/**
 * Observability helper. Returns true if the reply contains phrasing
 * that the deterministic normalization layer is designed to eliminate
 * but which the regex sweep may not reliably catch. Used by the server
 * to decide whether an unstructured tool reply should be retried.
 */
function hasUnsafeUnstructuredContent(reply) {
  if (!reply || typeof reply !== "string") return false;

  const patterns = [
    /\bhosting\s+of\s+a\s+(?:phishing|malware|spam|ransomware)\s+(?:site|page|server)\b/i,
    /\bparticipation\s+in\s+(?:a\s+)?(?:botnet|command[- ]and[- ]control|C2)\b/i,
    /\binvolvement\s+in\s+scanning\s+or\s+brute[- ]force\s+attempts\b/i,
    /\bisolate\s+the\s+host/i,
    /\bquarantine\s+the\s+endpoint/i,
    /\bblock\s+or\s+quarantine\b/i,
    /\badd\s+(?:the\s+)?IP\s+to\s+(?:a\s+)?(?:blocklist|deny\s+list|denylist)\b/i,
    /\bblock\s+or\s+monitor\s+it\s+pending\s+further\s+evidence\b/i,
    /\ba\s+(?:Nigerian|Russian|Chinese|North\s+Korean|Iranian)\s+ISP\s+(?:may|might|could)\s+be\b/i,
    /\bsafest\s+posture\s+is\s+to\s+treat\b/i,
    /\btreat\s+(?:it\s+|this\s+|the\s+(?:IP|address|host)\s+)?as\s+suspicious\b/i,
    /\bC2\s+server\b/i,
    /\bphishing\s+host\b/i,
    /\bhosting\s+(?:malware|phishing|spam|ransomware)\b/i,
    /\bbotnet\s+activity\b/i,
    /\biptables\s+-A\b/i,
    /\bNew-NetFirewallRule\b/i,
    /\bdeny\s+ip\s+any\s+host\b/i,
    /\bthe\s+IP\s+is\s+not\s+clean\b/i,
    /\b(?:this|the)\s+(?:IP|indicator|address)\s+is\s+not\s+clean\b/i,
    /\bpotentially\s+hostile\b/i,
    /\bmoderate\s+risk\b/i,
    /\b(?:low|medium|high|critical|urgent|severe)\s+priority\b/i,
    /\bpriority\s*:\s*(?:low|medium|critical|urgent|severe)\b/i,
    /\b(?:hostile|dangerous)\s+IP\b/i,
    /\bborderline\s+malicious\b/i,
    /\bclearly\s+malicious\b/i,
    /\bdefinitely\s+malicious\b/i,
    /\bIOC\s+for\s+this\s+IP\b/i,
    /\boverall\s+verdict\s*:?\s*(?:potentially\s+)?(?:malicious|suspicious|hostile)\b/i,
    // Phase 1.8: invented fixed monitoring schedule
    /\bmonitor(?:ing)?\s+(?:(?:it|this|the)\s+)?(?:ip\s+)?(?:daily\s+)?for\s+(?:the\s+next\s+)?\d+\s*(?:day|days|week|weeks|month|months)\b/i,
  ];

  return patterns.some((p) => p.test(reply));
}

module.exports = {
  applySecurityAssessment,
  applyRegexSweep,
  parseStructuredReply,
  validateStructuredReply,
  normalizeStructuredSecurityAssessment,
  renderStructuredReply,
  extractEvidence,
  hasUnsafeUnstructuredContent,
  buildStructuredAssessmentFromRawEvidence,
  renderInvestigationReport,
};