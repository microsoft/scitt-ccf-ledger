# A Rough Guide to SCITT Configuration

When SCITT-CCF nodes are first deployed, they are booted with initial [node configuration](https://microsoft.github.io/CCF/main/operations/configuration.html).

Members registered in the inital node configuration must then be [activated](https://microsoft.github.io/CCF/main/governance/adding_member.html#activating-a-new-member).

Members can then make and vote on [proposals](https://microsoft.github.io/CCF/main/governance/proposals.html) to update SCITT service configuration.

Once SCITT is apropriately configured members can vote to [open](https://microsoft.github.io/CCF/main/governance/open_network.html#opening-the-network) the service.
- Note: SCITT does not require CCF style `Users` to be configured.

# SCITT Configuration

SCITT config can be set via the `set_scitt_configuration` action within a governance proposal. Each item in `args.configuration` within `set_scitt_configuration` is a separate configuration option. Existing configuration options are outlined in the sections below.

Example config proposal:
```
{
  "actions": [
    {
      "name": "set_scitt_configuration",
      "args": {
        "configuration": {
          "authentication": <auth-snippet-omitted-for-brevity>,
          "service_identifier": "did:web:example.com%3A8000:scitt"
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
```
"authentication": {
  "allow_unauthenticated": True
}
```

### JWT API Authentication
If JWT authentication is enabled then API requests must include a header containing an acceptable JWT from a trusted identity provider. For more details see the [CCF documentation on JWTs](https://microsoft.github.io/CCF/main/build_apps/auth/jwt.html).
- JWT providers can be configured via the `set_jwt_issuer` action as explained in the [CCF documentation](https://microsoft.github.io/CCF/main/build_apps/auth/jwt.html#setting-up-a-token-issuer-with-manual-key-refresh).

Extra `required_claims` can be configured which must then be present in an API request's JWT for authentication to succeed.

To enable JWT authentication in SCITT, add the following config to a `set_scitt_configuration` action:
```
"authentication": {
  "allow_unauthenticated": False,
  "jwt": {
    "required_claims": {
      "foo": "bar",
        ...
    }
  }
}
```

## Service ID
The long-term stable identifier of this service, as a DID.
If set, it will be used to populate the issuer field of receipts.

Example `set_scitt_configuration` snippet:
```
"service_identifier": "did:web:example.com%3A8000:scitt"
```

## Accepted algorithms
List of accepted COSE signature algorithms when verifying signatures in submitted claims.
- Note: Items in the accepted algorithms list are case sensitive.

Example `set_scitt_configuration` snippet:
```
"accepted_algorithms": [ES256, ES384, ES512, PS256, PS384, PS512, EDDSA]
```

## Truststores
SCITT has two truststores that can be configured; `x509_roots`, and `did_web_tls_roots`.

### X509 Roots
CA certificates which are used as trusted roots during verification of submitted claims which use an X509 certificate for identity rather than a DID.

Example governance proposal:
```
{
  "actions": [
    {
      "name": "set_ca_cert_bundle",
      "args": {
        "name": x509_roots,
        "cert_bundle": "-----BEGIN CERTIFICATE-----\nMI...<Omitted for brevity>...Eo\n-----END CERTIFICATE-----\n"
      }
    }
  ]
}
```

### DID Web TLS Roots
CA certificates which are used as trusted roots during DID web resolution (as part of claim verification) to validate the connection to the server hosting a DID web document.

Example governance proposal:
```
{
  "actions": [
    {
      "name": "set_ca_cert_bundle",
      "args": {
        "name": did_web_tls_roots,
        "cert_bundle": "-----BEGIN CERTIFICATE-----\nMI...<Omitted for brevity>...Eo\n-----END CERTIFICATE-----\n"
      }
    }
  ]
}
```