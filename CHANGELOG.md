# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## TODO Add missing versions



## [0.10.2]

### Changes
* Upgrade to CCF 5.0.10 (#233)

## [0.10.1]

### Changes
* Upgrade to CCF 5.0.7 (#228)

## [0.10.0]

### Changes
* Upgrade to CCF 5.0.6 (#223)
* Add AMD SEV-SNP platform support (#224)
* Add CI pipeline stages for the SNP platform (#225)

## [0.9.0]

### Changes
- Updating URL from ccf.dev (#204)
- Add configurable policy via sandboxed JS execution (#203)
- did:x509 issuer support in IETF profile (#206)
- Allow svn parameter in the protected header (#209)
- example policy script and how to configure the application in dev (#210)
- Adds SGX build using custom 1ES GitHub SGX pool (#213)
- New cli argument allowing to specify receipt type to get after submission (#212)
- Accept CWT_Claims in envelopes, and expose them to policy (#211)
- Resolve Codeql complaints by @ivarprudnikov in (#215)
- Update build status badges on readme [ci skip] (#214)

## [0.8.0]

### Changes
- Improve reproducibility steps (#194)
- Fix CBOR encoder buffer overflow for large claims (#196)
- Update the CCF version to 5.0.0 (#200)
- Fix the path to runtime version (#201)
- Update OneBranch pipeline (#202)

## [0.7.2]

### Changes
- Update to CCF 4.0.17 (#192)

## [0.7.1]

### Changes
- Update to CCF 4.0.16 (#188)
- Update readme with issues encountered and workaround (#186)

## [0.7.0]

### Added
- Adds mrenclave measurement to the receipt protected header (#176)

### Changes
- Update pyscitt CLI and demo scripts for claims verification scenarios (#183)
- Update to CCF 4.0.15 (#184)
- Simplifies CTS demo scripts, adds AKV example (#182)
- Fix demo links (#180)

## [0.6.1]

### Changes
- Show how to configure accepted DID issuers (#175)
- Add more debug logs in the main SCITT controllers (#177)
- Update to CCF 4.0.14 (#178)

## [0.6.0]

### Added
- Add sample scripts for signing SCITT claims with certificates in Azure Key Vault (#172)

### Changes
- Update CCF to 4.0.12 and add support for OpenSSL 3.x (#173)
- Update CCF constitution to be compatible with the new ccf.crypto package (#171)
- Update README with new pyscitt package (#170)

## [0.5.3]

### Added
- Add GitHub action to publish pyscitt CLI to PyPi (#169)

## [0.5.2]

### Changes
- Refactor and modify CTS demo scripts (#167)
- Allow self-signed end-entity certs (#168)

## [0.5.1]
### Added
- Add CA cert support to CLI for TLS verification (#166)

### Fixed
- Temporarily disable flaky ASAN build job (#165)

## [0.5.0]
### Added
- Adds tag based workflow to build and release CLI (#161)
- Add support for COSE signing in python clients and tests (#154)
- Add utility scripts for demos and testing (#158)
- Doc with steps to reproduce mrenclave (#153)
- Adds new GitHub action to run unit tests (#146)
- Add documentation to build and push docker images (#145)

### Changes
- Upgrade to CCF 4.0.7 (#156)
- Defaults to did resolver if service params not passed when validating (#160)
- Print MRENCLAVE after the docker build (#151)
- Updated Azure Pipelines pool (#150)
- Wait for cchost config to be available (#144)
- Refactor perf tests (#143)
- Switch the operations callback to use an indexing strategy. (#140)
- Enhance devcontainer config (#139)
- Don't store operation contexts in the KV. (#137)

### Fixed
- Fix security vulnerabilities related to cryptography package (#159)
- Fix SCITT demo script (#142)
- Fix load test (#138)

## [0.4.0]
### Added
- Auth errors are now logged (#130).
- Output from the did:web resolution subprocess is now logged (#136).
- The service DID document is now also available at the well-known endpoint (#128).

### Changes
- Update to CCF 3.0.9 (#136).

## [0.3.0]
### Added
- Add [documentation](https://github.com/microsoft/scitt-ccf-ledger/blob/main/docs/configuration.md) on configuration (#103).
- did:web resolution failures are now logged and returned to clients through the updated REST API (#125).

### Changes
- Update to CCF 3.0.6 (#118).
- REST API has been updated to reflect changes in the IETF specificiation (#108). Note that this is a breaking change.
- Tighten certificate validation for X.509-based claim profiles (#104). Note that self-signed end-entity certificates are not supported anymore as trust anchors.

### Fixed
- Fix a memory leak when generating receipts (#102).
- Fix a crash when decoding malformed X.509 certificates (#97).
- Fix decoding of non-string content type COSE header parameter (#97).
- Fix a use-after-free bug in the historic query LRU cache (#109).

## [0.2.1]
### Changed
- Include all past service identities in the DID endpoint (#85).

### Fixed
- Don't hardcode localhost in did:web resolver callback address (#92).

## [0.2.0]
### Added
- Add support for Notary COSE profile (#73). Note that this is currently experimental and not supported by the IETF specifications that are being developed.
- Add support for `x-ms-request-id`/`x-ms-client-request-id` correlation headers (#79). All log messages originating from the app include the request id and, if available, the client request id. Note that support for W3C Trace Context headers may be added in the future.
- Emit log messages for each request (#79).
- Add `GET /scitt/did.json` endpoint that returns a DID document of the service in support of resolvable service identifiers in receipts (#68). Note that this is still experimental and will likely change. For now, only the current service identity key is included in the DID document, which means that receipts issued with old identities cannot be validated yet.
- Add option in `pyscitt` to sign governance proposals using Azure Key Vault (#54).

### Changed
- Change test clients to not use `/app` prefix when making API calls during testing (#64). Note that CCF started exposing app endpoints both at the root as well as the old `/app` prefix. It is recommended that clients remove the `/app` prefix.
- Change `kid` to be a relative DID URL by prefixing with `#` (#67). This is a breaking change in claims that use DIDs as issuers.
- Enable authentication for read-only app endpoints (#78). Previously, only `POST /entries` used authentication.
- Reduce `retry-after` response header value from 3 to 1 second for historical queries (#76).

### Removed
- Remove the `/constitution` endpoint in favour of CCF's built-in `/gov/kv/constitution` endpoint (#65). This endpoint is currently used in `pyscitt` to patch an existing constitution.

### Fixed
- Change the signature in receipts from ASN1/DER to IEEE encoding (#61). Note that this is a breaking change.

## [0.1.0]
### Added
- Add a `update_scitt_constitution` governance command to pyscitt (#3). This allows to update just the SCITT part of an existing constitution, leaving the rest intact.
- Add `/app/constitution` endpoint to retrieve the current constitution (#3).
- Add `/app/version` endpoint to retrieve release version (#42). This is equivalent to the git tag of the repository.
- Extend configuration to restrict issuers (#13). By default, all issuers are allowed.
- Add experimental `iss` and `kid` fields to receipts (#35). To enable this, the `service_identifier` field has to be set in the SCITT-specific configuration. Note that the existing `service_id` field in receipts is still kept for now.

### Changed
- Update to CCF 3.0.2 from 2.0.8 (#45). The QCBOR and t_cose libraries are now consumed from CCF itself.
- Update to pycose 1.0 (#34).
- Return a nice error instead of 500 when no prefix tree has been committed yet (#26).

## [0.1.0-dev.1]
### Added
- Initial release.

[0.4.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.1.0-dev.1...0.1.0
[0.1.0-dev.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.1.0-dev.1
