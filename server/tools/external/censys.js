const net = require("net");

const {
  fetchWithRetry,
  statusForHttp,
  publicResult,
  successResult,
  compactObject,
} = require("./provider-utils");

const DEFAULT_TIMEOUT_MS =
  Number(process.env.CENSYS_TIMEOUT_MS) || 8000;
const MAX_CENSYS_ERROR_LOG_BYTES = 128;

function censysErrorDiagnostic(status) {
  const safeStatus = Number.isInteger(status) && status >= 100 && status <= 599
    ? status
    : null;
  const diagnostic = {
    status: safeStatus,
    category: safeStatus === null ? "error" : statusForHttp(safeStatus),
  };
  if (Buffer.byteLength(JSON.stringify(diagnostic), "utf8") > MAX_CENSYS_ERROR_LOG_BYTES) {
    return { status: null, category: "error" };
  }
  return diagnostic;
}

function createCensysTool({
  apiToken,
  organizationId,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  return {
    name: "censys_ip_lookup",

    description:
      "Look up observed internet services and host information for an IP using the Censys Platform API.",

    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          minLength: 2,
          maxLength: 45,
        },
      },
      required: ["ip"],
      additionalProperties: false,
    },

    category: "threat-intelligence",
    targetTypes: ["ip"],
    readOnly: true,
    destructive: false,
    riskLevel: "read",
    requiresApproval: false,

    async execute(input) {
      const ip = String(input?.ip || "").trim();

      // ------------------------------------------------------------
      // Input validation
      // ------------------------------------------------------------

      if (!net.isIP(ip)) {
        return publicResult(
          "censys",
          "error",
          "Invalid IP address"
        );
      }

      // ------------------------------------------------------------
      // Credential validation
      // ------------------------------------------------------------

      if (!apiToken) {
        return publicResult(
          "censys",
          "not_configured",
          "CENSYS_API_TOKEN is not configured"
        );
      }

      try {
        // ----------------------------------------------------------
        // Censys Platform API
        //
        // GET /v3/global/asset/host/{host_id}
        //
        // Authentication:
        // Authorization: Bearer <CENSYS_API_TOKEN>
        //
        // organization_id is optional.
        // ----------------------------------------------------------

        const params = new URLSearchParams();

        if (organizationId) {
          params.set("organization_id", organizationId);
        }

        const baseUrl =
          `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(
            ip
          )}`;

        const url = params.toString()
          ? `${baseUrl}?${params.toString()}`
          : baseUrl;

        const headers = {
          Accept:
            "application/vnd.censys.api.v3.host.v1+json",
          Authorization: `Bearer ${apiToken}`,
        };

        const { response, payload } =
          await fetchWithRetry(url, {
            timeoutMs,
            headers,
          });

        // ----------------------------------------------------------
        // HTTP error handling
        // ----------------------------------------------------------

        if (!response.ok) {
          const diagnostic = censysErrorDiagnostic(response.status);
          console.warn(
            "[Censys] Provider request failed",
            diagnostic
          );

          return publicResult(
            "censys",
            statusForHttp(response.status),
            "Censys request failed"
          );
        }

        // ----------------------------------------------------------
        // Validate response
        // ----------------------------------------------------------

        if (
          !payload?.result ||
          typeof payload.result !== "object"
        ) {
          return publicResult(
            "censys",
            "error",
            "Censys returned an unexpected response shape"
          );
        }

        /*
         * Expected Platform API shape:
         *
         * {
         *   "result": {
         *     "resource": {
         *       ...
         *     }
         *   }
         * }
         *
         * Keep the fallback to payload.result because some
         * API responses can expose the resource directly.
         */

        const resource =
          payload.result.resource &&
          typeof payload.result.resource === "object"
            ? payload.result.resource
            : payload.result;

        // ----------------------------------------------------------
        // Services
        // ----------------------------------------------------------

        const services =
          Array.isArray(resource.services)
            ? resource.services
                .slice(0, 20)
                .map((service) =>
                  compactObject({
                    port: service?.port,

                    serviceName:
                      service?.service_name,

                    extendedServiceName:
                      service?.extended_service_name,

                    transportProtocol:
                      service?.transport_protocol,

                    observedAt:
                      service?.observed_at,

                    software:
                      service?.software,

                    banner:
                      service?.banner,

                    labels:
                      service?.labels,
                  })
                )
            : [];

        // ----------------------------------------------------------
        // Determine evidence quality
        // ----------------------------------------------------------

        const meaningful =
          services.length > 0 ||
          Boolean(resource.autonomous_system) ||
          Boolean(resource.location) ||
          Boolean(resource.dns);

        // ----------------------------------------------------------
        // Return normalized result
        // ----------------------------------------------------------

        return successResult(
          "censys",
          compactObject({
            ip:
              resource.ip || ip,

            location:
              resource.location,

            autonomousSystem:
              resource.autonomous_system,

            services,

            dns:
              resource.dns,

            labels:
              resource.labels,

            lastUpdated:
              resource.last_updated_at,

            meaningful,

            evidenceQuality:
              meaningful
                ? "observational"
                : "contextual",
          })
        );
      } catch (error) {
        console.error(
          "[Censys] Tool execution error:",
          {
            message: error?.message,
            category: error?.category,
          }
        );

        return publicResult(
          "censys",
          error?.category === "tool_timeout"
            ? "timeout"
            : "unavailable",
          error?.message ||
            "Censys request failed"
        );
      }
    },
  };
}

module.exports = {
  createCensysTool,
};
