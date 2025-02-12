# SCITT Configuration Guide

When SCITT-CCF nodes are first deployed, they are started with an initial [node configuration](https://microsoft.github.io/CCF/main/operations/configuration.html).

Members registered in the initial node configuration must then be [activated](https://microsoft.github.io/CCF/main/governance/adding_member.html#activating-a-new-member).

Members can then make and vote on [proposals](https://microsoft.github.io/CCF/main/governance/proposals.html) to update SCITT service configuration.

Once SCITT is appropriately configured members can vote to [open the service](https://microsoft.github.io/CCF/main/governance/open_network.html#opening-the-network).
- Note: SCITT does not require CCF-style "users" to be configured.

## SCITT Configuration

SCITT configuration can be set via the `set_scitt_configuration` action within a governance proposal. Each item in `args.configuration` within `set_scitt_configuration` is a separate configuration option. Existing configuration options are outlined in the sections below.

Example configuration proposal, using a JavaScript policy:
```
{
  "actions": [
    {
      "name": "set_scitt_configuration",
      "args": {
        "configuration": {
          "policy": {
            "policyScript": "export function apply(profile, phdr) { if (profile !== 'IETF') { return 'Unexpected profile'; } if (!phdr.issuer) {return 'Issuer not found'} if (phdr.issuer !== 'did:x509:0:sha256:HnwZ4lezuxq/GVcl/Sk7YWW170qAD0DZBLXilXet0jg=::eku:1.3.6.1.4.1.311.10.3.13') { return 'Invalid issuer'; } }"
          },
          "authentication": {
            "allowUnauthenticated": false,
            "jwt": {
              "requiredClaims": {
                "aud": "scitt",
                "iss": "https://authserver.com/",
                "http://unique.claim/department_id": "654987"
              }
            }
          }
        }
      }
    }
  ]
}
```

Example configuration proposal, using a Rego policy:
```
{
  "actions": [
    {
      "name": "set_scitt_configuration",
      "args": {
        "configuration": {
          "policy": {
            "\npackage policy\n\nissuer_allowed if {\n    input.phdr.cwt.iss == "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13"\n}\n\nseconds_since_epoch := time.now_ns() / 1000000000\n\niat_in_the_past if {\n    input.phdr.cwt.iat < seconds_since_epoch\n}\n\nsvn_undefined if {\n    not input.phdr.cwt.svn\n}\n\nsvn_positive if {\n    input.phdr.cwt.svn >= 0\n}\n\nallow if {\n    issuer_allowed\n    iat_in_the_past\n    svn_undefined\n}\n\nallow if {\n    issuer_allowed\n    iat_in_the_past\n    svn_positive\n}\n"
          },
          "authentication": {
            "allowUnauthenticated": false,
            "jwt": {
              "requiredClaims": {
                "aud": "scitt",
                "iss": "https://authserver.com/",
                "http://unique.claim/department_id": "654987"
              }
            }
          }
        }
      }
    }
  ]
}
```

## SCITT API Authentication
API authentication can be turned off entirely or JWT authentication can be set up.
Until a JWT provider is configured or API authentication is disabled, the initial configuration rejects all API requests as unauthorized.

### Disabling API Authentication
If API authentication is disabled then requests won't require any form of authentication. (Claims submitted via the API are still validated.)

Example `set_scitt_configuration` snippet:
```json
"authentication": {
  "allowUnauthenticated": true
}
```

### JWT API Authentication
If JWT authentication is enabled then API requests must include a header containing an acceptable JWT from a trusted identity provider. For more details see the [CCF documentation on JWTs](https://microsoft.github.io/CCF/main/build_apps/auth/jwt.html).
- JWT providers can be configured via the `set_jwt_issuer` action as explained in the [CCF documentation](https://microsoft.github.io/CCF/main/build_apps/auth/jwt.html#setting-up-a-token-issuer-with-manual-key-refresh).

Extra `requiredClaims` can be configured which must then be present in an API request's JWT for authentication to succeed.

To enable JWT authentication in SCITT, add the following config to a `set_scitt_configuration` action:
```json
"authentication": {
  "allowUnauthenticated": false,
  "jwt": {
    "requiredClaims": {
      "foo": "bar",
    }
  }
}
```

## Policy object

### Accepted algorithms
List of accepted COSE signature algorithms when verifying signatures in submitted claims.
If not set, the default accepted algorithms are shown in the example snippet below.
- Note: Items in the accepted algorithms list are case sensitive.

Example `set_scitt_configuration` snippet:
```json
"acceptedAlgorithms": ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EDDSA"]
```

### Policy script
JS code that determines whether an entry should be accepted. Should export an `apply` function taking 2 arguments `(claim_profile, protected_header)`, and return true if the entry should be accepted or a string describing why the entry has failed the policy.

`claim_profile` is a string representation of a [`scitt::SignedStatementProfile`](https://github.com/microsoft/scitt-ccf-ledger/blob/main/app/src/profiles.h#L10) value, mapped through [`scitt::js::claim_profile_to_js_val()`](https://github.com/microsoft/scitt-ccf-ledger/blob/main/app/src/policy_engine.h#L20).

`protected_header` is an object representation of the subset of COSE protected header parameters parsed by scitt-ccf-ledger, namely:

- alg (Number)
- crit (Array containing values of type Number or String)
- kid (String)
- issuer (String)
- feed (String)
- svn (Number)
- cty (Number or String)
- x5chain (Array of String values)
- cwt (object), containing
  - iss (string)
  - sub (string)
  - iat (Number)
  - svn (Number)

The mapping takes place in [`scitt::js::protected_header_to_js_val()`](https://github.com/microsoft/scitt-ccf-ledger/blob/main/app/src/policy_engine.h#L44).

Policy scripts are executed by the [CCF JavaScript runtime](https://github.com/microsoft/CCF/blob/main/include/ccf/js/core/runtime.h), which wraps and extends [QuickJS](https://bellard.org/quickjs/). Most ES2023 features are [supported](https://test262.fyi/#|qjs).

Example `set_scitt_configuration` snippet:
```json
"policy": {
  "policyScript": "export function apply(profile, phdr) {\n  if (profile === \"X509\") { return true; }\n  return \"Only X509 claim profile is allowed\";\n}"
}
```

### Policy rego
Rego code that determines whether an entry should be accepted. The package must be called "policy", and expose a rule called "allow" that must evaluate to `true` when the value of `input` is acceptable.

`input` is set to a JSON object with the following fields:

`profile` is a string representation of a [`scitt::SignedStatementProfile`](https://github.com/microsoft/scitt-ccf-ledger/blob/main/app/src/profiles.h#L10) value, mapped through [`scitt::js::claim_profile_to_js_val()`](https://github.com/microsoft/scitt-ccf-ledger/blob/main/app/src/policy_engine.h#L20).

`phdr` is an object representation of the subset of COSE protected header parameters parsed by scitt-ccf-ledger, namely:

- alg (Number)
- cty (Number or String)
- cwt (object), containing
  - iss (string)
  - sub (string)
  - iat (Number)
  - svn (Number)

Example `set_scitt_configuration` snippet:
```json
"policy": {
  "policyRego": "package policy\ndefault allow := false\n allow if input.profile == \"X509\""
}
```

## CCF specific configuration

Please refer to the latest [CCF configuration documentation](https://microsoft.github.io/CCF/main/operations/configuration.html) to understand all of the possible options.

### Receipt issuance

Receipts can contain the issuer and subject fields identifying the service.

To use the specific values in the receipts please set it through the [CCF v6 configuration](https://microsoft.github.io/CCF/main/operations/configuration.html):

```json
"cose_signatures": {
  "issuer": "myservicedomain.com",
  "subject": "scitt.ccf.signature.v1"
}
```

Once the value is set it will be easy to discover the public keys via `$issuer/.well-known/transparency-configuration` endpoint.

## Trust stores
SCITT has a trust store that can be configured: `x509_roots`.

### X509 Roots
CA certificates which are used as trusted roots during verification of submitted claims which use an X509 certificate for identity rather than a DID.

Example governance proposal:
```json
{
  "actions": [
    {
      "name": "set_ca_cert_bundle",
      "args": {
        "name": "x509_roots",
        "cert_bundle": "-----BEGIN CERTIFICATE-----\nMI...<Omitted for brevity>...Eo\n-----END CERTIFICATE-----\n"
      }
    }
  ]
}
```
