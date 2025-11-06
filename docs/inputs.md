# Support for inputs

The ledger only accepts specific binary payloads ("signed statements") to be validated and stored. In addition to that the registration policies are used to verify the signed statements.

## Signed Statements Support

scitt-ccf-ledger implements registration for two kinds of Signed Statements:

1. Statements signed with an X.509 certificate chain ([schema](schemas/x509-signed-statement.cddl)), which make use of header parameters defined in [RFC9360](https://www.rfc-editor.org/rfc/rfc9360.html), and [`did:x509`](https://github.com/microsoft/did-x509) issuers.
2. Statements signed with hardware-attested, ephemeral keys ([schema](schemas/attestedsvc-signed-statement.cddl)), which are currently experimental, and make use `did:attestedsvc` issuers.

## Registration policies

Upon registration of signed statements, in addition to the expected verification, acceptance policies are executed against the data in the statements. Please refer to the [configuration page](./configuration.md) and [tests](../test/test_configuration.py) to understand how signed statement attributes are used.