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
        checkType(args.configuration.authentication.jwt, "object?", "configuration.authentication.jwt");
        if (args.configuration.authentication.jwt) {
          checkType(args.configuration.authentication.jwt.requiredClaims, "object?", "configuration.authentication.jwt.requiredClaims");
        }
      }

      checkType(args.configuration.serviceIssuer, "string?", "configuration.serviceIssuer");
    },
    function(args) {
      ccf.kv["public:ccf.gov.scitt.configuration"].set(getSingletonKvKey(), ccf.jsonCompatibleToBuf(args.configuration));
    }))

// The marker below is used by the patch_constitution tool.
// Do not remove it! Do not add anything after it.
// ----- SCITT Constitution ends here -----
