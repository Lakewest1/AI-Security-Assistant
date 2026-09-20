/**
 * ToolValidator
 *
 * Independent server-side validation of model-supplied tool arguments.
 * The model is never trusted to enforce its own schema.
 */

function isPlainObject(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isValidIPv4(value) {
  if (typeof value !== "string") return false;

  const parts = value.trim().split(".");
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

class ToolValidator {
  validate(tool, input) {
    if (!tool) {
      return {
        valid: false,
        reason: "tool not found",
      };
    }

    const schema =
      tool.inputSchema || {
        type: "object",
        properties: {},
        additionalProperties: false,
      };

    if (!isPlainObject(input)) {
      return {
        valid: false,
        reason: "input must be a plain object",
      };
    }

    if (schema.type && schema.type !== "object") {
      return {
        valid: false,
        reason: "tool input schema must be an object schema",
      };
    }

    const props = schema.properties || {};
    const required = Array.isArray(schema.required)
      ? schema.required
      : [];
    const additionalAllowed =
      schema.additionalProperties !== false;

    for (const key of required) {
      if (!(key in input)) {
        return {
          valid: false,
          reason: `missing required field: ${key}`,
        };
      }
    }

    if (!additionalAllowed) {
      for (const key of Object.keys(input)) {
        if (!(key in props)) {
          return {
            valid: false,
            reason: `unexpected field: ${key}`,
          };
        }
      }
    }

    for (const [key, value] of Object.entries(input)) {
      const spec = props[key];
      if (!spec) continue;

      const expectedType = spec.type;

      if (expectedType) {
        const actualType = Array.isArray(value)
          ? "array"
          : value === null
            ? "null"
            : typeof value;

        if (actualType !== expectedType) {
          return {
            valid: false,
            reason: `field "${key}" must be ${expectedType}, got ${actualType}`,
          };
        }
      }

      if (
        expectedType === "string" &&
        typeof value === "string"
      ) {
        if (
          Number.isFinite(spec.maxLength) &&
          value.length > spec.maxLength
        ) {
          return {
            valid: false,
            reason: `field "${key}" exceeds maxLength`,
          };
        }

        if (Number.isFinite(spec.minLength) &&
            value.length < spec.minLength) {
          return {
            valid: false,
            reason: `field "${key}" is shorter than minLength`,
          };
        }

        if (spec.pattern) {
          let regex = null;

          try {
            regex = new RegExp(spec.pattern);
          } catch {
            return {
              valid: false,
              reason: `field "${key}" has an invalid validation pattern`,
            };
          }

          if (!regex.test(value)) {
            return {
              valid: false,
              reason: `field "${key}" fails pattern check`,
            };
          }
        }

        if (
          spec.format === "ipv4" &&
          !isValidIPv4(value)
        ) {
          return {
            valid: false,
            reason: `field "${key}" must be a valid IPv4 address`,
          };
        }
      }

      if (Array.isArray(spec.enum) &&
          !spec.enum.includes(value)) {
        return {
          valid: false,
          reason: `field "${key}" has an unsupported value`,
        };
      }

      if (typeof spec.validate === "function") {
        const custom = spec.validate(value);

        if (custom !== true) {
          return {
            valid: false,
            reason:
              typeof custom === "string"
                ? custom
                : `field "${key}" failed validation`,
          };
        }
      }
    }

    return { valid: true };
  }
}

ToolValidator.isValidIPv4 = isValidIPv4;

module.exports = ToolValidator;
