const net = require("net");

const {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  successResult,
} = require("./provider-utils");

const DEFAULT_TIMEOUT_MS =
  Number(process.env.VIEWDNS_TIMEOUT_MS) || 8000;

function target(input) {
  const domain = String(
    input?.domain || ""
  ).trim();

  const ip = String(
    input?.ip || ""
  ).trim();

  if (
    domain &&
    /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(
      domain
    )
  ) {
    return {
      kind: "domain",
      value: domain,
    };
  }

  if (ip && net.isIP(ip)) {
    return {
      kind: "ip",
      value: ip,
    };
  }

  return null;
}

function normalizeOperationError(
  operation,
  result
) {
  if (
    result?.status === "rejected"
  ) {
    const reason =
      result.reason;

    if (
      reason?.category ===
      "tool_timeout"
    ) {
      return {
        status: "timeout",
        message: "Request timed out",
      };
    }

    return {
      status:
        reason?.category ||
        "unavailable",
      message:
        reason?.message ||
        "Request failed",
    };
  }

  const response =
    result?.value?.response;

  if (!response) {
    return {
      status: "unavailable",
      message:
        `${operation} request failed`,
    };
  }

  return {
    status:
      statusForHttp(
        response.status
      ),
    message:
      `HTTP ${response.status}`,
  };
}

function createViewDNSTool({
  apiKey,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  return {
    name: "viewdns_lookup",

    description:
      "Look up DNS, reverse-DNS, WHOIS and infrastructure relationships using ViewDNS.",

    inputSchema: {
      type: "object",

      properties: {
        domain: {
          type: "string",
          minLength: 3,
          maxLength: 253,
        },

        ip: {
          type: "string",
          minLength: 2,
          maxLength: 45,
        },
      },

      additionalProperties: false,
      minProperties: 1,
    },

    category: "threat-intelligence",
    targetTypes: [
      "domain",
      "ip",
    ],

    readOnly: true,
    destructive: false,
    riskLevel: "read",
    requiresApproval: false,

    async execute(input) {
      const t = target(input);

      // ------------------------------------------------------------
      // Input validation
      // ------------------------------------------------------------

      if (!t) {
        return publicResult(
          "viewdns",
          "error",
          "Invalid domain or IP target"
        );
      }

      // ------------------------------------------------------------
      // Credential validation
      // ------------------------------------------------------------

      if (!apiKey) {
        return publicResult(
          "viewdns",
          "unauthorized",
          "ViewDNS API key is not configured"
        );
      }

      const host = t.value;

      // ------------------------------------------------------------
      // ViewDNS operations currently used by this provider
      //
      // Keep these independent so one failure does not discard
      // successful results from the other operation.
      // ------------------------------------------------------------

      const operations = [
        {
          name: "reverseIp",

          url:
            `https://api.viewdns.info/reverseip/` +
            `?host=${encodeURIComponent(host)}` +
            `&apikey=${encodeURIComponent(apiKey)}` +
            `&output=json`,
        },

        {
          name: "whois",

          url:
            `https://api.viewdns.info/whois/v2/` +
            `?domain=${encodeURIComponent(host)}` +
            `&apikey=${encodeURIComponent(apiKey)}` +
            `&output=json`,
        },
      ];

      try {
        // ----------------------------------------------------------
        // Execute independent operations concurrently.
        //
        // Promise.allSettled() ensures that one timeout/error does
        // not cancel the other ViewDNS request.
        // ----------------------------------------------------------

        const settled =
          await Promise.allSettled(
            operations.map(
              (operation) =>
                fetchWithRetry(
                  operation.url,
                  {
                    timeoutMs,

                    headers: {
                      Accept:
                        "application/json",
                    },
                  }
                )
            )
          );

        const findings = {
          target: host,
          lookupType: t.kind,
        };

        const errors = {};

        let successes = 0;

        // ----------------------------------------------------------
        // Preserve successful operations and record failed ones
        // independently.
        // ----------------------------------------------------------

        for (
          let index = 0;
          index < settled.length;
          index += 1
        ) {
          const operation =
            operations[index];

          const result =
            settled[index];

          if (
            result.status ===
            "fulfilled"
          ) {
            const {
              response,
              payload,
            } = result.value;

            if (
              response.status === 200 &&
              payload &&
              typeof payload === "object"
            ) {
              successes += 1;

              const viewDnsResponse =
                payload.response;

              // ----------------------------------------------------
              // Reverse IP
              // ----------------------------------------------------

              if (
                operation.name ===
                "reverseIp"
              ) {
                if (
                  viewDnsResponse?.domains !==
                  undefined
                ) {
                  findings.reverseIpDomains =
                    viewDnsResponse.domains;
                }

                if (
                  viewDnsResponse?.domain_count !==
                  undefined
                ) {
                  findings.reverseIpDomainCount =
                    viewDnsResponse.domain_count;
                }
              }

              // ----------------------------------------------------
              // WHOIS
              // ----------------------------------------------------

              if (
                operation.name ===
                "whois"
              ) {
                if (
                  viewDnsResponse?.matches !==
                  undefined
                ) {
                  findings.reverseWhoisMatches =
                    viewDnsResponse.matches;
                }

                if (
                  viewDnsResponse?.records !==
                  undefined
                ) {
                  findings.whoisRecords =
                    viewDnsResponse.records;
                }

                if (
                  viewDnsResponse?.result_count !==
                  undefined
                ) {
                  findings.whoisResultCount =
                    viewDnsResponse.result_count;
                }

                if (
                  viewDnsResponse?.owner !==
                  undefined
                ) {
                  findings.owner =
                    viewDnsResponse.owner;
                }
              }
            } else {
              const status =
                statusForHttp(
                  response.status
                );

              errors[operation.name] = {
                status:
                  status ||
                  "error",
                message:
                  `HTTP ${response.status}`,
              };
            }
          } else {
            errors[operation.name] =
              normalizeOperationError(
                operation.name,
                result
              );
          }
        }

        // ----------------------------------------------------------
        // All operations succeeded
        // ----------------------------------------------------------

        if (
          successes ===
          operations.length
        ) {
          return successResult(
            "viewdns",
            findings
          );
        }

        // ----------------------------------------------------------
        // At least one operation succeeded.
        //
        // IMPORTANT:
        // Return the successful data instead of discarding it.
        // ----------------------------------------------------------

        if (successes > 0) {
          return {
            ...successResult(
              "viewdns",
              findings
            ),

            status: "partial",

            errors,

            limitations: [
              "One or more requested ViewDNS lookups were unavailable.",
            ],
          };
        }

        // ----------------------------------------------------------
        // No useful operation succeeded.
        //
        // Preserve the individual operation errors so callers know
        // exactly what failed.
        // ----------------------------------------------------------

        return {
          ...publicResult(
            "viewdns",
            "error",
            "ViewDNS did not return usable lookup data"
          ),

          errors,
        };
      } catch (error) {
        console.error(
          "[ViewDNS] Tool execution error:",
          {
            message: error?.message,
            category: error?.category,
          }
        );

        return publicResult(
          "viewdns",
          error?.category ===
            "tool_timeout"
            ? "timeout"
            : "unavailable",
          error?.message ||
            "ViewDNS request failed"
        );
      }
    },
  };
}

module.exports = {
  createViewDNSTool,
};