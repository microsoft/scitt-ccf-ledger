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

## Trust and the authorization boundary

GitHub's token authenticates the workflow to Fulcio, which binds its public key
to GitHub identity in a short-lived code-signing certificate. Fulcio is an
explicit additional trust authority. The public service at
`https://fulcio.sigstore.dev` records certificate identity in public certificate
transparency logs; repository/workflow information can become public, including
for private repositories. Use an appropriately configured private Fulcio
instance if that disclosure or public CA trust is unacceptable.

**The ledger, not the Action, decides which identities may submit.** Ledger
governance installs a registration policy that requires:

| Bound identity | Check |
| --- | --- |
| Signing authority | Exact trusted root fingerprint in the certificate-bound `did:x509` issuer |
| GitHub issuer | `https://token.actions.githubusercontent.com`, CA-signed extension `.8` |
| Signing workflow | Exact workflow URI including its ref, both SAN and extension `.9` |
| Source repository | Exact repository URI (`.12`), immutable repository ID (`.15`), and owner ID (`.17`) |
| Source revision | Exact ref (`.14`); optional signing workflow commit digest (`.10`) |
| Execution context | Expected event (`.20`) and runner environment (`.11`) |
| Short-lived registration | Positive certificate lifetime at most 600 seconds, plus currently valid chain |

The OID prefix is `1.3.6.1.4.1.57264.1`. Modern Fulcio values are DER UTF8String
encodings, not the raw strings used by older extensions. Policies compare the
authenticated raw extension bytes and reject missing or duplicate identity
extensions.

A reusable workflow can have the **same signer SAN in jobs from different source
repositories**. Checking only that SAN would authorize unintended callers. The
independent source-repository URI and immutable IDs prevent that. Names alone are
also insufficient when a repository is renamed, transferred, or deleted and
recreated. Protect the allowed branch/workflow, restrict dispatch privileges, and
optionally pin the workflow digest. The policy does not guarantee that allowed
workflow code is benign, that every GitHub Action is trusted, or that the file's
contents are correct.

OIDC tokens are bearer credentials: a stolen, unexpired token can also be used
to obtain certificates outside the runner. The claims identify the GitHub job,
not the physical location of signing or the provenance of the input file.

The private key does not mathematically expire. The policy restricts when its
certificate can authorize **new registrations**. It does not provide replay
prevention during that window, revoke compromised keys, or retroactively remove
accepted statements. Current validity is checked against the CCF node's host
clock; this example adds no trusted timestamp service. Historical receipt
verification remains separate from certificate validity at registration.

## 1. Build and configure the ledger

Use a ledger built from this revision: the example needs the new protected-leaf
certificate policy metadata described in [configuration.md](../../docs/configuration.md).
Start it using the [usual build/run instructions](../../README.md). A GitHub-hosted
runner needs to be able to reach the configured HTTPS endpoint; a ledger running
only on your laptop's localhost is not reachable. A self-hosted runner requires
an administrator-selected `--runner self-hosted` policy.

Install `pyscitt` using Python 3.12 or later, from the repository root:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install ./pyscitt
```

The bundled `fulcio-root.pem` is the public Sigstore Fulcio root from
[sigstore/root-signing](https://github.com/sigstore/root-signing/blob/main/targets/fulcio_v1.crt.pem).
Its SHA-256 certificate fingerprint is
`3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1`.
This is an explicit trust pin, not a root downloaded from the issuing endpoint
at signing time. Review it before trusting it; root rotation requires deliberately
updating both the Action configuration and ledger policy. For a private Fulcio
deployment, substitute its trusted root and endpoint.

Obtain the immutable IDs as the ledger administrator, for example:

```sh
gh api repos/OWNER/REPOSITORY --jq '{repository_id: .id, owner_id: .owner.id}'
```

Generate a policy for the actual repository and workflow. The numbers below
are placeholders to replace with the API results. The default allowed source
ref is `refs/heads/main`, event is `workflow_dispatch`, and runner is `github-hosted`:

```sh
.venv/bin/python -m demo.github_actions.policy \
  --fulcio-root demo/github_actions/fulcio-root.pem \
  --repository OWNER/REPOSITORY \
  --repository-id 123 --owner-id 456 \
  --workflow 'https://github.com/OWNER/REPOSITORY/.github/workflows/github-oidc-ledger.yml@refs/heads/main' \
  --allow-unauthenticated \
  --out github-policy.json
```

`--allow-unauthenticated` deliberately disables **API bearer authentication**
for this demo, not COSE signature validation or registration policy. Omit it
for an authenticated service and use `--configuration existing-configuration.json`
to preserve its JWT requirements and other configuration settings. Without an
existing configuration, API authentication defaults to enabled. A SCITT
configuration proposal replaces the service configuration, so inspect the
generated JSON before proposing it. API authentication and signing identity
are separate: the GitHub OIDC token is exchanged with Fulcio, **not** automatically
accepted as a ledger API token.

Use `--ref`, `--event`, or `--runner` to change the corresponding policy checks.
Use `--workflow-digest FULL_LOWERCASE_COMMIT_SHA` to pin the signing workflow's
CA-signed Git commit digest. For a reusable workflow, `--workflow` must identify
the reusable signer workflow while `--repository`, immutable IDs, and `--ref`
must identify the **calling/source** repository.

Install this configuration through ledger governance, using a member's
credentials, **outside** the signing job:

```sh
.venv/bin/scitt governance propose_configuration \
  --url https://LEDGER \
  --member-cert MEMBER_CERT.pem --member-key MEMBER_KEY.pem \
  --configuration github-policy.json
```

For a private ledger TLS CA, add `--cacert SERVICE_CA.pem`. Use `--development`
only for a local demo with deliberately disabled ledger TLS verification.
Never give the signing Action governance credentials.

## 2. Run with real GitHub OIDC

Publish the workflow on the repository's default branch (required for
`workflow_dispatch`), with the example also committed on the branch/ref allowed
by policy. Then dispatch
[`github-oidc-ledger.yml`](../../.github/workflows/github-oidc-ledger.yml) from
that ref, passing the running ledger's HTTPS URL. It signs
`demo/github_actions/payload.json` by default and uploads the signed and
transparent statements as artifacts. An optional `SCITT_AUTH_TOKEN` repository
secret supplies a separately authorized ledger API bearer token.

The Action needs `permissions: id-token: write`. Example use from this checkout:

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
      fulcio-root: demo/github_actions/fulcio-root.pem
      # service-ca: path/to/ledger-tls-ca.pem
      # auth-token: ${{ secrets.SCITT_AUTH_TOKEN }}
```

Once published, a different caller repository can reference
`microsoft/scitt-ccf-ledger/.github/actions/scitt-sign@FULL_COMMIT_SHA` directly.
Alternatively, check this Action's repository out separately at a reviewed commit
and reference its local `.github/actions/scitt-sign` directory. Keep the caller's
input file and explicitly trusted root CA paths relative to its workspace, pin
the Action version, and configure policy for the caller's repository identity.

Inputs are passed through environment variables rather than interpolated into
shell commands. The Action creates an isolated runner-temp Python environment,
generates its signing key only in process memory, masks the OIDC token, enforces
HTTPS and timeouts, and refuses credential-bearing redirects. TLS verification
is enabled by default. `development: "true"` disables only ledger TLS verification,
not OIDC or Fulcio TLS.

Required inputs are `file`, `ledger-url`, and `fulcio-root`. Optional inputs are
`fulcio-url`, `audience` (default `sigstore`), `content-type`, `service-ca`,
`auth-token`, `output-dir`, and `development`. A private Fulcio instance must
trust GitHub's OIDC issuer and the configured audience, and emit the modern
GitHub identity extensions listed above.

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

Tests cover fresh keys, exact binary payload bytes, CSR proof of possession,
missing OIDC permissions, malformed responses, key mismatch, HTTPS/redirect
handling, wrong CA/repository/IDs/issuer/ref/workflow/event/runner, unexpected
callers of a trusted reusable workflow, expired/future/overlong certificates,
tampering, and JS/Rego metadata mapping. Native unit tests retain duplicate
extension values. The tests also demonstrate that ordinary `did:x509` policy
behavior does **not** change: expiry enforcement belongs to this example's
registration policy.

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
