# SCITT Configuration Guide

When SCITT-CCF nodes are first deployed, they are started with an initial [node configuration](https://microsoft.github.io/CCF/main/operations/configuration.html).

Members registered in the initial node configuration must then be [activated](https://microsoft.github.io/CCF/main/governance/adding_member.html#activating-a-new-member).

Members can then make and vote on [proposals](https://microsoft.github.io/CCF/main/governance/proposals.html) to update SCITT service configuration.

Once SCITT is appropriately configured members can vote to [open the service](https://microsoft.github.io/CCF/main/governance/open_network.html#opening-the-network).
- Note: SCITT does not require CCF-style "users" to be configured.

## SCITT Configuration

SCITT configuration can be set via the `set_scitt_configuration` action within a governance proposal. Each item in `args.configuration` within `set_scitt_configuration` is a separate configuration option. Existing configuration options are outlined in the sections below.

Example configuration proposal:
```json
{
  "actions": [
    {
      "name": "set_scitt_configuration",
      "args": {
        "configuration": {
          "policy": {
            "policyScript": "export function apply(phdr) { if (!phdr.issuer) {return 'Issuer not found'} else if (phdr.issuer !== 'did:x509:0:sha256:HnwZ4lezuxq/GVcl/Sk7YWW170qAD0DZBLXilXet0jg=::eku:1.3.6.1.4.1.311.10.3.13') { return 'Invalid issuer'; } return true; }"
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
JS code that determines whether an entry should be accepted. Should export an `apply` function taking multiple arguments, and return true if the entry should be accepted or a string describing why the entry has failed the policy.

Policy scripts are executed by the [CCF JavaScript runtime](https://github.com/microsoft/CCF/blob/main/include/ccf/js/core/runtime.h), which wraps and extends [QuickJS](https://bellard.org/quickjs/). Most ES2023 features are [supported](https://test262.fyi/#|qjs).

Example `set_scitt_configuration` snippet:
```json
"policy": {
  "policyScript": "export function apply (phdr, uhdr, payload, details) { return true; }"
}
```

Function argument mapping takes place in [`scitt::js::protected_header_to_js_val()`](https://github.com/microsoft/scitt-ccf-ledger/blob/main/app/src/policy_engine.h).

Function arguments:
1. `protected_headers` (Object) representation of the subset of COSE protected header parameters parsed by scitt-ccf-ledger

    ```
    {
      // Algorithm identifier (integer)
      alg?: number,
      
      // Critical headers array
      crit?: Array<number | string>,
      
      // Key ID
      kid?: string,
      
      // Issuer
      issuer?: string,
      
      // Feed
      feed?: string,
      
      // Issued at timestamp
      iat?: number,
      
      // Software version number
      svn?: number,
      
      // Content type (can be integer or string)
      cty?: number | string,
      
      // X.509 certificate chain (array of PEM strings)
      x5chain?: string[],
      
      // CWT Claims object
      cwt: {
        iss?: string,  // Issuer
        sub?: string,  // Subject
        iat?: number,  // Issued at
        svn?: number   // Software version number
      },
      
      // Microsoft CSS Dev TSS Map
      "msft-css-dev": {
        attestation?: ArrayBuffer,
        attestation_type?: string,
        
        // COSE Key object
        cose_key?: {
          kty?: number,           // Key type
          crv?: number,           // Curve (for EC keys)
          n?: ArrayBuffer,        // Modulus (for RSA keys)
          x_e?: ArrayBuffer,      // X coordinate (EC) or exponent (RSA)
          y?: ArrayBuffer         // Y coordinate (EC only)
        },
        
        // SHA-256 hash of COSE key (hex string)
        cose_key_sha256?: string,
        
        snp_endorsements?: ArrayBuffer,
        uvm_endorsements?: ArrayBuffer,
        ver?: number  // Version
      }
    }
    ```

2. `unprotected_headers` (Object) object representation of the subset of COSE unprotected header parameters parsed by scitt-ccf-ledger

    ```
    {
      // X.509 certificate chain (array of PEM strings)
      x5chain?: string[]
    }
    ```

3. `payload` (ArrayBuffer)

    ```
    ArrayBuffer
    ```

4. `verified_sev_snp_details` (Object) present when signature issuer is `did:attestedsvc`, details added after the signature and the attestation verification

    ```
    {
      // Empty object if no attestation details
      // OR if attestation details exist:
      
      // See https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
      // Section 7.3 - Table 23 for the semantics and size of the following fields before their
      // encoding to hex string.

      // Measurement (hex string)
      measurement?: string,
      
      // Report data (hex string)
      report_data?: string,

      // Host data (hex string)
      host_data?: string,
      
      // See https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
      // for additional detail on the UVM Endorsements object and reference values for the Confidential ACI platform

      // UVM Endorsements object
      uvm_endorsements?: {
        did: string,   // Decentralized identifier
        feed: string,  // Feed identifier
        svn: string    // Software version number
      }
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

Once the value is set, the public keys can be discoverd through the `$issuer/.well-known/transparency-configuration` endpoint.