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
          "Censys API token is not configured"
        );
      }

      try {
        // ----------------------------------------------------------
        // Censys Platform API
        //
        // Current endpoint:
        // GET /v3/global/asset/host/{host_id}
        //
        // Censys recommends organization_id as a query parameter.
        // ----------------------------------------------------------

        const params = new URLSearchParams();

        if (organizationId) {
          params.set("organization_id", organizationId);
        }

        const baseUrl =
          `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(ip)}`;

        const url = params.toString()
          ? `${baseUrl}?${params.toString()}`
          : baseUrl;

        const headers = {
          Accept:
            "application/vnd.censys.api.v3.host.v1+json",
          Authorization: `Bearer ${apiToken}`,
        };

        const { response, payload } = await fetchWithRetry(
          url,
          {
            timeoutMs,
            headers,
          }
        );

        // ----------------------------------------------------------
        // HTTP error handling
        // ----------------------------------------------------------

        if (!response.ok) {
          /*
           * IMPORTANT:
           * Do not expose the Authorization header or token.
           *
           * We only extract the safe error information returned
           * by Censys.
           */

          let errorDetails = "";

          if (payload && typeof payload === "object") {
            const safePayload = compactObject({
              error: payload.error,
              code: payload.code,
              message: payload.message,
              detail: payload.detail,
              title: payload.title,
              type: payload.type,
            });

            if (Object.keys(safePayload).length > 0) {
              errorDetails = `: ${JSON.stringify(safePayload)}`;
            }
          } else if (typeof payload === "string") {
            errorDetails = `: ${payload.slice(0, 500)}`;
          }

          console.warn(
            `[Censys] HTTP ${response.status}`,
            {
              ip,
              status: response.status,
              message: errorDetails || "No error body returned",
            }
          );

          return publicResult(
            "censys",
            statusForHttp(response.status),
            `Censys returned HTTP ${response.status}${errorDetails}`
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
         * Censys Platform API:
         *
         * {
         *   "result": {
         *     "resource": {
         *       ...
         *     }
         *   }
         * }
         */

        const resource =
          payload.result.resource &&
          typeof payload.result.resource === "object"
            ? payload.result.resource
            : payload.result;

        // ----------------------------------------------------------
        // Services
        // ----------------------------------------------------------

        const services = Array.isArray(resource.services)
          ? resource.services
              .slice(0, 20)
              .map((service) =>
                compactObject({
                  port: service.port,

                  serviceName:
                    service.service_name,

                  extendedServiceName:
                    service.extended_service_name,

                  transportProtocol:
                    service.transport_protocol,

                  observedAt:
                    service.observed_at,

                  software:
                    service.software,

                  banner:
                    service.banner,

                  labels:
                    service.labels,
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
          error?.message || "Censys request failed"
        );
      }
    },
  };
}

module.exports = {
  createCensysTool,
};