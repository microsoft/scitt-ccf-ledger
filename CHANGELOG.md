# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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

### Fixed


## [0.1.0-dev.1]
### Added
- Initial release.

[0.1.0]: https://github.com/microsoft/scitt-ccf-ledger/compare/0.1.0-dev.1...0.1.0
[0.1.0-dev.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.1.0-dev.1
