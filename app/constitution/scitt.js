// ----- SCITT Constitution starts here -----
//
// The marker above is used by the patch_constitution tool, as a way to split an
// existing service's constitution in its operator and application halves, and
// update only the latter.
//
// Do not remove it! Do not add anything before it.

actions.set("set_scitt_configuration",
  new Action(
    function(args) {
      checkType(args.configuration, "object", "configuration");
      checkType(args.configuration.policy, "object?", "configuration.policy");
      if (args.configuration.policy) {
        checkType(args.configuration.policy.accepted_algorithms, "array?", "configuration.policy.accepted_algorithms");
        if (args.configuration.policy.accepted_algorithms) {
          for (const [i, alg] of args.configuration.policy.accepted_algorithms.entries()) {
            checkType(alg, "string", `configuration.policy.accepted_algorithms[${i}]`);
          }
        }
        checkType(args.configuration.policy.accepted_did_issuers, "array?", "configuration.policy.accepted_did_issuers");
        if (args.configuration.policy.accepted_did_issuers) {
          for (const [i, alg] of args.configuration.policy.accepted_did_issuers.entries()) {
            checkType(alg, "string", `configuration.policy.accepted_did_issuers[${i}]`);
          }
        }
        checkType(args.configuration.policy.policy_script, "string?", "configuration.policy.policy_script");
      }

      checkType(args.configuration.authentication, "object?", "configuration.authentication");
      if (args.configuration.authentication) {
        checkType(args.configuration.authentication.allow_unauthenticated, "boolean?", "configuration.authentication.allow_unauthenticated");
        checkType(args.configuration.authentication.jwt, "object?", "configuration.authentication.jwt");
        if (args.configuration.authentication.jwt) {
          checkType(args.configuration.authentication.jwt.required_claims, "object?", "configuration.authentication.jwt.required_claims");
        }
      }

      checkType(args.configuration.service_identifier, "string?", "configuration.service_identifier");
    },
    function(args) {
      ccf.kv["public:ccf.gov.scitt.configuration"].set(getSingletonKvKey(), ccf.jsonCompatibleToBuf(args.configuration));
    }))

// The marker below is used by the patch_constitution tool.
// Do not remove it! Do not add anything after it.
// ----- SCITT Constitution ends here -----
