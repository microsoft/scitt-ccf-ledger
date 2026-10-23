// ----- SCITT Constitution starts here -----
//
// The marker above is used by the patch_constitution tool, as a way to split an
// existing service's constitution in its operator and application halves, and
// update only the latter.
//
// Do not remove it! Do not add anything before it.

const jwtSchemaDraft = "http://json-schema.org/draft-07/schema#";

function validateJwtClaimsSchema(schema, field, root = true) {
  if (schema === null || Array.isArray(schema) || typeof schema !== "object") {
    throw new Error(`${field} must be an object`);
  }
  const allowed = root
    ? ["$schema", "type", "properties", "required", "anyOf"]
    : ["type", "properties", "required"];
  for (const key of Object.keys(schema)) {
    if (!allowed.includes(key)) {
      throw new Error(`${field}.${key} is not supported`);
    }
  }
  if ((root || schema.type !== undefined) && schema.type !== "object") {
    throw new Error(`${field}.type must be object`);
  }
  if (root && schema.$schema !== jwtSchemaDraft) {
    throw new Error(`${field} requires JSON Schema draft-07`);
  }

  const properties = schema.properties === undefined ? {} : schema.properties;
  if (properties === null || Array.isArray(properties) || typeof properties !== "object") {
    throw new Error(`${field}.properties must be an object`);
  }
  const required = schema.required === undefined ? [] : schema.required;
  if (!Array.isArray(required) || new Set(required).size !== required.length) {
    throw new Error(`${field}.required must list distinct claim names`);
  }
  for (const [key, value] of Object.entries(properties)) {
    if (value === null || Array.isArray(value) || typeof value !== "object" ||
        Object.keys(value).length !== 1 || !Object.hasOwn(value, "const") ||
        !required.includes(key)) {
      throw new Error(`${field}.properties.${key} must be a required const claim`);
    }
  }
  for (const key of required) {
    if (typeof key !== "string" || !Object.hasOwn(properties, key)) {
      throw new Error(`${field}.required references an undefined claim`);
    }
  }

  if (root && schema.anyOf !== undefined) {
    if (!Array.isArray(schema.anyOf) || schema.anyOf.length === 0) {
      throw new Error(`${field}.anyOf must be a non-empty array`);
    }
    for (const [i, alternative] of schema.anyOf.entries()) {
      validateJwtClaimsSchema(alternative, `${field}.anyOf[${i}]`, false);
    }
  }
  if (required.length === 0 && (!root || schema.anyOf === undefined)) {
    throw new Error(`${field} must constrain at least one claim`);
  }
}

actions.set("set_scitt_configuration",
  new Action(
    function(args) {
      checkType(args.configuration, "object", "configuration");
      checkType(args.configuration.policy, "object?", "configuration.policy");
      if (args.configuration.policy) {
        checkType(args.configuration.policy.acceptedAlgorithms, "array?", "configuration.policy.acceptedAlgorithms");
        if (args.configuration.policy.acceptedAlgorithms) {
          for (const [i, alg] of args.configuration.policy.acceptedAlgorithms.entries()) {
            checkType(alg, "string", `configuration.policy.acceptedAlgorithms[${i}]`);
          }
        }
        checkType(args.configuration.policy.policyScript, "string?", "configuration.policy.policyScript");
        checkType(args.configuration.policy.policyRego, "string?", "configuration.policy.policyRego");
      }

      checkType(args.configuration.authentication, "object?", "configuration.authentication");
      if (args.configuration.authentication) {
        checkType(args.configuration.authentication.allowUnauthenticated, "boolean?", "configuration.authentication.allowUnauthenticated");
        checkType(args.configuration.authentication.allowUnauthenticatedReads, "boolean?", "configuration.authentication.allowUnauthenticatedReads");
        checkType(args.configuration.authentication.jwt, "object?", "configuration.authentication.jwt");
        if (args.configuration.authentication.jwt) {
          const jwt = args.configuration.authentication.jwt;
          if (Array.isArray(jwt)) {
            throw new Error("configuration.authentication.jwt must be an object");
          }
          if (jwt.$schema !== undefined) {
            validateJwtClaimsSchema(jwt, "configuration.authentication.jwt");
          } else {
            if (jwt.type !== undefined || jwt.properties !== undefined ||
                jwt.required !== undefined || jwt.anyOf !== undefined) {
              throw new Error("configuration.authentication.jwt.$schema is required for schema validation");
            }
            checkType(jwt.requiredClaims, "object?", "configuration.authentication.jwt.requiredClaims");
            if (jwt.requiredClaims !== null && Array.isArray(jwt.requiredClaims)) {
              throw new Error("configuration.authentication.jwt.requiredClaims must be an object");
            }
          }
          if (jwt.anyOfClaims !== undefined || jwt.oneOfClaims !== undefined) {
            throw new Error("configuration.authentication.jwt.anyOfClaims and oneOfClaims are not supported");
          }
        }
      }

      checkType(args.configuration.maxSignedStatementBytes, "integer?", "configuration.maxSignedStatementBytes");

      checkType(args.configuration.serviceIssuer, "string?", "configuration.serviceIssuer");
    },
    function(args) {
      ccf.kv["public:ccf.gov.scitt.configuration"].set(getSingletonKvKey(), ccf.jsonCompatibleToBuf(args.configuration));
    }))

// The marker below is used by the patch_constitution tool.
// Do not remove it! Do not add anything after it.
// ----- SCITT Constitution ends here -----
