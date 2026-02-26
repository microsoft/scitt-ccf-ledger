# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [0.16.5]
### Changes
- 56132cd Bump azurelinux/base/core from 3.0.20260107 to 3.0.20260204 in /docker (#362)
- d466c16 Update cryptography version to 46.* in setup.py (#361)
- eb2f430 Update CCF version from 6.0.21 to 6.0.23 (#360)
- e29be23 Remove failing pypi release step (#358)

## [0.16.4]
### Changes
- c4493a7 add a simple throughput benchmark calculation (#356)
- 659e5bc Update CCF version from 6.0.19 to 6.0.21 (#355)
- 57bc6b3 steps to sign with cosesigntool (#353)

## [0.16.3]
### Changes
- 02a6680 Update CCF version from 6.0.17 to 6.0.19 (#351)
- 165c443 Set redirection strategy for all endpoints and follow redirects in pyscitt CLI   (#350)
- 538676e Docs describing how to run on azure confidential containers (#349)
- 41e1dcb Bump azurelinux/base/core from 3.0.20251206 to 3.0.20260107 in /docker (#348)
- 0400bb2 Update cbor2 version requirement in setup.py (#346)
- 51602d7 Update CCF_VERSION to 6.0.17 (#347)

## [0.16.2]
### Changes
- 7d26f4d Update CCF version from 6.0.15 to 6.0.17 (#344)
- 09a998a Bump azurelinux/base/core from 3.0.20251106 to 3.0.20251206 in /docker (#343)
- d561159 Allow untagged iat(6) values (#341)
- 693dc69 Bump azurelinux/base/core from 3.0.20251030 to 3.0.20251106 in /docker (#342)
- c8349d5 Readme improvements (#340)
- 70d4b92 Bump azurelinux/base/core from 3.0.20250910 to 3.0.20251030 in /docker (#339)

## [0.16.1]
### Changes
- 874f312 Refactor Dockerfile to enable Dependabot detection of Azure Linux base image (#336)
- 949b296 Configure Dependabot for Docker updates (#337)
- 9ff6ad6 Update CCF version from 6.0.14 to 6.0.15 (#335)
- c0558e5 Update to Readme and addition of signed statement schemas (#333)
- f622d93 Fix Python type-checking error (#334)
- d447157 update changelog for 0.16.0 (#332)

## [0.16.0]
### Changes
- fa3f2d7 crit verification for x509 path (#331)
- f0c1a7e Update to attestedsvc map (#326)
- 9ac6e4c Update CCF version from 6.0.12 to 6.0.14 across all configuration files and code (#328)

## [0.15.2]
### Changes
- 935ff03 Update CCF version from 6.0.10 to 6.0.12 across all configuration files and code (#324)
- 66c9741 Drop unused profiles.h file (#323)
- ab6f66d Remove now-unnecessary test proxy (#320)
- 8af10e7 Use KS4 network in ADO PR builds (#322)
- 891b978 Use release builds for benchmarks (#318)
- ea20022 Add performance test for Attested Service signed statements (#319)

## [0.15.1]
### Changes
- 6493384 Expose reported TCB to policy (#316)
- df1a28d Remove default constructed attestation details (#315)
- 40ead73 Remove now-unused ifdefs present for OpenSSL 1.1.1 (pre-3) support (#314)
- a1cfc58 Expose host_data to registration policy (#313)

## [0.15.0]
### Changes
- adds changelog checks
- updates CCF to 6.0.10
- 4c57779 Adds latest attested signature to functional tests (#310)
- 29bdb67 Use private pip feed when building in ADO (#308)
- 2098d69 did:attestedsvc:msft-css-dev signature issuer verification with attestation verification and detail exposure to policy (#305)

## [0.14.3]
### Changes
- f7cc892 Update CCF version from 6.0.5 to 6.0.9 across all configuration files and code (#306)

## [0.14.2]
### Changes
- 06ddcc0 [CLI] Verify transparent statement using issuer endpoint in the receipt (#302)

## [0.14.1]
### Changes
- 3c95b0b Update CCF version from 6.0.3 to 6.0.5 across all configuration files and code (#303)
- cdcc431 Update CCF version from 6.0.1 to 6.0.3 across all configuration files (#301)
- 284b286 adds simple cose unit test to check if headers get parsed (#300)

## [0.14.0]
### Changes
- 535cf94 Fix release action after upgrade to Azure Linux 3 (#299)
- c84db70 Update to CCF 6.0.1 and use Azure Linux 3.0 (#298)

## [0.13.2]
### Changes
- e4e7473 Add option to redirect cchost logs to local port in SNP images (#296)
- 2617335 Removed apt.llvm.org from Docker Images (#295)

## [0.13.1]
### Changes
- 19b086d Add option to redirect cchost logs to file in SNP images (#294)
- 3992622 Removed Python dependencies step and launchpad repositories (#289)

## [0.13.0]
### Changes
- 6573a5c update demo readme and scripts and minor changes in pyscitt client and test infra module (#288)
- 9a5bf53 Document standard alignment of the implementation (#252)
- ea64668 Consolidate on IETF SCITT profile/policyScript (#278)
- 0da0b47 Update CCF to 6.0.0-rc0 (#284)
- 39470bf Add new test payload (#287)
- 19d20f4 Update runners to ubuntu-latest (#286)
- d8be7d0 Fix pretty receipt for COSE receipts (#271)
- 2c63a86 Align with scrapi feb4 (#274)
- 7fe83ed Support both python3.8 and 3.10 in docker (#281)
- ccd1537 Upgraded to Python3.10  (#280)
- 986fbb5 Removed launchpad.net repository (#279)

## [0.12.2]
### Changes
- d3c851a Update change log 0.12.1 (#276)
- a3ca4e5 update ccf to 6-dev20 (#275)
- f94a47d Delete dpkg list files containing ppa.lauchpad.net from docker images (#273)
- 8b87934 Move bencher from PoC to main readme (#269)
- 7a921ed Dead code removal pass (#270)
- 2e31535 Remove python from images, change version string, update reproducibility doc for amd sev snp (#265)
- fbf7ca4 Remove support for Notary signatures (#261)

## [0.12.1]

### Changes
* Upgrade to CCF 6.0.0-dev20 (#275)

## [0.12.0]
## [0.12.0-pre]
### Changes
- 1647ebe Update to CCF 6.0.0-dev16 (#259)
- de20351 Remove unnecessary submodule init from build script (#257)
- 7759208 Clean up SGX references (#258)
- 46b7720 Add /.well-known/transparency-configuration and /jwks endpoints (#253)
- 4ea33ee Use consistent camelCase in http api (#256)
- ce11795 Remove unused code (#255)
- 6877a7e Fix CTS demo scripts following the recent pyscitt CLI updates (#254)

## [0.11.0]
### Changes
- bfd6592 Adds fuzzing to POST entries endpoint (#251)
- 69b9f53 Upgrade to 6.0.0-dev8 and de-duplicate wrappers (#250)
- 52c2f40 Drop did:web sample (#249)
- 3328eeb Remove CCF_UNSAFE (#248)
- 1cc543b Implement COSE receipts in scitt-ccf-ledger (#245)
- 97799de Adds ASAN build to GH actions (#239)
- 12bf0b0 Set up CODEOWNERS (#242)
- 312bb89 Remove deprecated governance signing type (#235)

## [0.10.3]
### Changes
- 474d31c Relax CCF version in Python dependencies in Pyscitt library (#234)

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

## [0.9.1]
### Changes
- 2cd8fc9 CLI: extract payload from COSE envelopes (#222)
- 5dbfa2d remove remaining prefix tree mentions
- fd0a463 Azure DevOps to use private feeds for Python deps in PR builds (#221)
- df76d5a Bump the pip cryptography to 43 and ccf to 5.0.4 (#220)
- 64ba84f Remove unused prefix-tree support (#216)
- 35f72ea Fixes pretty-receipt command for COSE envelopes with embedded receipts (#219)
- c81408c Use PEM parsing provided in pycose library (#218)

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
[0.7.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.7.1
[0.10.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.10.0
[0.7.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.7.0
[0.10.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.10.2
[0.6.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.6.1
[0.10.3]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.10.3
[0.10.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.10.1
[0.5.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.5.0
[0.14.3]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.14.3
[0.9.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.9.1
[0.5.3]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.5.3
[0.14.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.14.0
[0.14.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.14.2
[0.13.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.13.1
[0.7.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.7.2
[0.12.0-pre]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.12.0-pre
[0.14.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.14.1
[0.13.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.13.0
[0.12.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.12.0
[0.8.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.8.0
[0.11.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.11.0
[0.12.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.12.1
[0.13.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.13.2
[0.6.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.6.0
[0.12.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.12.2
[0.5.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.5.1
[0.9.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.9.0
[0.5.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.5.2
[0.15.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.15.0
[0.15.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.15.1
[0.15.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.15.2
[0.16.0]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.16.0
[0.16.1]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.16.1
[0.16.2]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.16.2
[0.16.3]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.16.3
[0.16.4]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.16.4
[0.16.5]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/0.16.5
