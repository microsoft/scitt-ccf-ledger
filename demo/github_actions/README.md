# GitHub Actions keyless signing into SCITT

This example signs the exact bytes of an input file with `pyscitt` and submits
the COSE signed statement to a **running, configured ledger**. The custom
[composite Action](../../.github/actions/scitt-sign/action.yml) uses:

```text
fresh P-256 key --signed CSR + GitHub job OIDC token--> Fulcio --> certificate
input file + key + certificate --pyscitt/ES256--> COSE --submit--> SCITT + receipt
```

The private key is randomly generated for each invocation, **not derived from a
bearer token**. Only the CSR and GitHub token are sent to Fulcio. The input file,
token, and private key are not uploaded to Rekor; the file is sent to the ledger,
and neither the token nor private key is included in the COSE envelope or saved
to disk. This is not a Sigstore bundle or a Rekor transparency-log example.

Signing uses `pyscitt.crypto.Signer` and `crypto.sign_statement(cwt=True)`, the
same implementation used by `scitt sign --uses-cwt` in
[`2-claim-generator.sh`](../transparency-service-poc/2-claim-generator.sh).
`pyscitt` creates the standard algorithm, content-type, protected certificate
chain, and CWT issuer headers; the example adds no custom headers.

## Trust and the authorization boundary

GitHub's token authenticates the workflow to Fulcio, which binds its public key
to GitHub identity in a short-lived code-signing certificate. Fulcio is an
explicit additional trust authority. The public service at
`https://fulcio.sigstore.dev` records certificate identity in public certificate
transparency logs; repository/workflow information can become public, including
for private repositories. This simplified Action uses the public Fulcio service
and its bundled trusted root; do not use it if that disclosure or CA trust is
unacceptable.

**The ledger, not the Action, decides which identities may submit.** Ledger
governance installs a registration policy that requires:

| Bound identity | Check |
| --- | --- |
| Signing authority | Exact trusted root fingerprint in the certificate-bound `did:x509` issuer |
| Signing workflow | Exact GitHub workflow URI including repository and ref, bound to the certificate SAN |
| Code-signing key | Code-signing EKU in the certificate-bound issuer |
| Registration time | Currently valid certificate chain |

The existing ledger verifier authenticates the COSE signature and `did:x509`
CA/EKU/SAN predicates before its existing policy engine runs. The policy only
uses the already available CWT issuer, certificate chain, and
`ccf.crypto.isValidX509CertChain`; no changes to the native application are needed.

This example uses a **non-reusable signing workflow**. Its SAN identifies the
repository, workflow file, and ref. A reusable workflow can have the same signer
SAN for different calling repositories; this policy **does not distinguish those
callers**. It also does not inspect immutable repository/owner IDs, triggering
events, or runner environments. Repository renames, transfers, and recreation
require policy review. Protect the allowed workflow/ref and restrict dispatch
privileges. The policy does not guarantee that workflow code is benign or that
the input file's contents are correct.

OIDC tokens are bearer credentials: a stolen, unexpired token can also be used
to obtain certificates outside the runner. The claims identify the GitHub job,
not the physical location of signing or the provenance of the input file.

Public Fulcio issues short-lived certificates, and the Action rejects a lifetime
outside `(0, 600]` seconds. The private key does not mathematically expire. The
policy checks current validity, not certificate lifetime duration, and restricts
when the certificate can authorize **new registrations**. It does not provide
replay prevention during that window, revoke compromised keys, or retroactively
remove accepted statements. Current validity is checked against the CCF node's
host clock; this example adds no trusted timestamp service. Historical receipt
verification remains separate from certificate validity at registration.

The signing leaf may omit `BasicConstraints`, as permitted for end-entity
certificates by [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9).
An explicit `ca=true` leaf is rejected, and the pinned root must still declare
itself a CA. Required GitHub issuer, code-signing EKU, workflow SAN, key binding,
certificate validity, and chain-signature checks are unchanged.

## 1. Build and configure the ledger

Start the ledger using the [usual build/run instructions](../../README.md).
Its existing `did:x509` verifier and registration policy engine suffice. A
GitHub-hosted runner needs to be able to reach the configured HTTPS endpoint; a
ledger running only on your laptop's localhost is not reachable.

Install `pyscitt` using Python 3.12 or later, from the repository root:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install ./pyscitt
```

The bundled `fulcio-root.pem` is the public Sigstore Fulcio root from
[sigstore/root-signing](https://github.com/sigstore/root-signing/blob/main/targets/fulcio_v1.crt.pem).
Its SHA-256 certificate fingerprint is
`3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1`.
The Action and policy generator use this root automatically, independently of
the caller's working directory. It is an explicit trust pin, not a root trusted
just because Fulcio returned it. Review it before use; root rotation requires
updating the bundled root and regenerating the ledger policy.

Generate a policy for the actual signing workflow, including its repository
and exact ref:

```sh
.venv/bin/python -m demo.github_actions.policy \
  --workflow 'https://github.com/OWNER/REPOSITORY/.github/workflows/github-oidc-ledger.yml@refs/heads/main' \
  --allow-unauthenticated \
  --out github-policy.json
```

`--allow-unauthenticated` deliberately disables **API bearer authentication**
for this demo, not COSE signature validation or registration policy. This
simplified Action supplies no ledger API bearer token, so the example requires
that API configuration. Use `--configuration existing-configuration.json` to
preserve other configuration settings; inspect the result before proposing it.
Without an existing configuration or the explicit flag, API authentication
defaults to enabled. A SCITT configuration proposal replaces the service
configuration. API authentication and signing identity are separate: the GitHub
OIDC token is exchanged with Fulcio, **not** accepted as a ledger API token.

Install this configuration through ledger governance, using a member's
credentials, **outside** the signing job:

```sh
.venv/bin/scitt governance propose_configuration \
  --url https://LEDGER \
  --member-cert MEMBER_CERT.pem --member-key MEMBER_KEY.pem \
  --configuration github-policy.json
```

For a private ledger TLS CA, add `--cacert SERVICE_CA.pem`.
Never give the signing Action governance credentials.

## 2. Run with real GitHub OIDC

### Temporary build-pipeline signing probe

The [Build and test workflow](../../.github/workflows/build-test.yml) contains a
temporary `GitHub OIDC/Fulcio signing check` job. Pushing `feat/github-oidc-e2e`
triggers this existing build workflow and the probe, even without an open PR.
Same-repository pull requests from that branch also run it. The permissions
`contents: read` and `id-token: write` are scoped to that job; existing build jobs
do not gain OIDC permissions, and fork PRs do not run the probe.

The job uses the production signing function to request a real GitHub token for
`sigstore`, exchange a fresh signed CSR with public Fulcio, sign the sample JSON
file with `pyscitt`, and verify the resulting COSE signature. It needs no ledger
URL or API credentials. Failures in issuance, certificate validation, or signing
fail the job; only a successfully verified statement is uploaded as the
`github-oidc-fulcio-cose` artifact, retained for one day. Neither the bearer token
nor private key is saved. The public certificate-transparency disclosure described
above still applies.

Remove the temporary job and feature-branch push trigger after validating live
issuance.

### Ledger submission workflow

Publish the workflow on the repository's default branch (required for
`workflow_dispatch`), with the example also committed on the branch/ref allowed
by policy. Then dispatch
[`github-oidc-ledger.yml`](../../.github/workflows/github-oidc-ledger.yml) from
that ref, passing the running ledger's HTTPS URL. It signs
`demo/github_actions/payload.json` by default and uploads the signed and
transparent statements as artifacts.

The Action needs `permissions: id-token: write`. It requests the audience
`sigstore`, which public Fulcio requires. The audience is selected when requesting
the GitHub token, not derived from an already issued token.

Example use from this checkout:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  - id: register
    uses: ./.github/actions/scitt-sign
    with:
      file: artifact.json
      content-type: application/json
      ledger-url: https://LEDGER
      # service-ca: path/to/ledger-tls-ca.pem
```

Once published, a different caller repository can reference
`microsoft/scitt-ccf-ledger/.github/actions/scitt-sign@FULL_COMMIT_SHA` directly.
Alternatively, check this Action's repository out separately at a reviewed commit
and reference its local `.github/actions/scitt-sign` directory. Keep the caller's
input file and optional ledger TLS CA paths relative to its workspace, pin
the Action version, and configure policy for the caller's signing workflow.

Inputs are passed through environment variables rather than interpolated into
shell commands. The Action creates an isolated runner-temp Python environment,
generates its signing key only in process memory, masks the OIDC token, enforces
HTTPS and timeouts, and refuses credential-bearing redirects. TLS verification
is always enabled; use `service-ca` when the ledger uses a private TLS CA.

Required inputs are `file` and `ledger-url`. Optional inputs are `content-type`,
`service-ca`, and `output-dir`. The Fulcio endpoint, trusted root, and token
audience are not Action inputs.

Outputs:

| Output | Value |
| --- | --- |
| `transaction-id` | Committed ledger transaction ID |
| `signed-statement` | Absolute path to `signed-statement.cose` |
| `transparent-statement` | Absolute path to `transparent-statement.cose` with a verified receipt |

The output directory also contains `submission.json`. Receipt verification uses
the service keys obtained from the configured ledger over its authenticated TLS
connection. No artifact is reported as a successful submission if signing,
registration, or receipt verification fails.

## 3. Deterministic local end-to-end coverage

The tests generate a test CA and real Fulcio-shaped certificates. An in-process
HTTP transport substitutes for GitHub/Fulcio, while ledger tests submit the actual
COSE envelopes to a real managed CCF ledger and verify its receipts. No public
OIDC or CA calls are made:

```sh
./run_functional_tests.sh -k GitHub
```

Offline exchange tests can also be run without a ledger:

```sh
.venv/bin/python -m pip install -r test/requirements.txt
.venv/bin/python -m pytest -q test/test_github_oidc.py::TestGitHubActionOffline
```

Tests cover signing leaves with and without `BasicConstraints`, fresh keys, exact
binary payload bytes, CSR proof of possession,
missing OIDC permissions, malformed responses, key mismatch, HTTPS/redirect
handling, wrong CA/workflow/repository/ref, forged issuer claims,
expired/future/overlong certificates, tampering, and compatibility with the
existing JS/Rego issuer policies and `scitt sign --uses-cwt` headers.
The Action entrypoint verifies ledger TLS with a supplied CA.
The tests also demonstrate that ordinary `did:x509` policy
behavior does **not** change: expiry enforcement belongs to this example's
registration policy.
The offline suite also checks the probe's verified artifact and ensures Fulcio
refusal, payload mismatch, and invalid signatures fail without creating an output
file.

## Reference implementations and specifications

- [Sigstore Python GitHub Action](https://github.com/sigstore/gh-action-sigstore-python):
  GitHub OIDC plus ephemeral keyless signing, rather than stored signing keys.
- [sigstore-python signing](https://github.com/sigstore/sigstore-python/blob/main/sigstore/sign.py)
  and [Fulcio client](https://github.com/sigstore/sigstore-python/blob/main/sigstore/_internal/fulcio/client.py):
  fresh key generation and a signed CSR exchanged for a Fulcio certificate.
- [GitHub OIDC documentation](https://docs.github.com/en/actions/concepts/security/openid-connect):
  token permissions and claims. Do not infer repository identity by parsing `sub`;
  subject formats can change.
- [Fulcio identity extensions](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md),
  [GitHub CI-provider configuration](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml),
  and [CI-provider principal](https://github.com/sigstore/fulcio/blob/main/pkg/identity/ciprovider/principal.go):
  source repository versus signer workflow, immutable IDs, and DER encodings.
- [`did:x509` specification](https://github.com/microsoft/did-x509/blob/main/specification.md):
  CA fingerprints, SAN URI predicates, and code-signing EKU.
