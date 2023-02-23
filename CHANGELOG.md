# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [0.3.0]
### Added
- Add [documentation](https://github.com/microsoft/scitt-ccf-ledger/blob/main/docs/configuration.md) on configuration (#103).

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

[0.3.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.1.0-dev.1...0.1.0
[0.1.0-dev.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.1.0-dev.1
