# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import cbor2
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pycose.headers import Algorithm, ContentType, X5chain
from pycose.keys.cosekey import CoseKey
from pycose.messages import Sign1Message

from demo.github_actions import policy, sign
from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import verify_transparent_statement

from .infra.assertions import service_error

WORKFLOW = (
    "https://github.com/octo/example/.github/workflows/submit.yml@refs/heads/main"
)
PAYLOAD = b'{"artifact":"example"}\n\x00\xff'
ENVIRONMENT = {
    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/token?existing=1&audience=old",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-request-credential",
}


def github_claims() -> dict[str, str]:
    return {
        "issuer": policy.GITHUB_ISSUER,
        "workflow": WORKFLOW,
        "workflow_digest": "a" * 40,
        "runner": "github-hosted",
        "repository": "https://github.com/octo/example",
        "ref": "refs/heads/main",
        "repository_id": "123",
        "owner_id": "456",
        "event": "workflow_dispatch",
    }


class FulcioCA:
    def __init__(self, *, intermediate: bool = False):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Fulcio")])
        now = datetime.now(UTC)
        self.root = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()
                ),
                False,
            )
            .add_extension(
                x509.KeyUsage(
                    False, False, False, False, False, True, True, False, False
                ),
                True,
            )
            .sign(self.key, hashes.SHA256())
        )
        self.pem = self.root.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.issuer = self.root
        self.issuer_key = self.key
        self.chain = [self.pem]
        if intermediate:
            self.issuer_key = ec.generate_private_key(ec.SECP256R1())
            self.issuer = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")])
                )
                .issuer_name(self.root.subject)
                .public_key(self.issuer_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=180))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(
                        self.issuer_key.public_key()
                    ),
                    False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        self.key.public_key()
                    ),
                    False,
                )
                .add_extension(
                    x509.KeyUsage(
                        False, False, False, False, False, True, True, False, False
                    ),
                    True,
                )
                .sign(self.key, hashes.SHA256())
            )
            self.chain.insert(
                0, self.issuer.public_bytes(serialization.Encoding.PEM).decode("ascii")
            )

    def certificate(
        self,
        public_key,
        *,
        claims: dict[str, str] | None = None,
        san: str = WORKFLOW,
        lifetime: int = 600,
        offset: int = -30,
        ca: bool = False,
        eku: bool = True,
    ) -> x509.Certificate:
        before = datetime.now(UTC) + timedelta(seconds=offset)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.issuer.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(before)
            .not_valid_after(before + timedelta(seconds=lifetime))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.issuer_key.public_key()
                ),
                False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]),
                True,
            )
        )
        if eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False
            )
        for name, value in (claims if claims is not None else github_claims()).items():
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(policy.FULCIO_OIDS[name]), policy.der_utf8(value)
                ),
                False,
            )
        return builder.sign(self.issuer_key, hashes.SHA256())

    def statement(self, *, payload: bytes = PAYLOAD, **kwargs) -> bytes:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = self.certificate(key.public_key(), **kwargs)
        signer = crypto.Signer(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            algorithm="ES256",
            issuer=policy.signing_issuer(self.pem, kwargs.get("san", WORKFLOW)),
            x5c=[
                leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                *self.chain,
            ],
        )
        return crypto.sign_statement(
            signer, payload, "application/octet-stream", cwt=True
        )

    def registration_policy(self, **kwargs) -> dict:
        return policy.registration_policy(
            self.pem,
            repository="octo/example",
            repository_id="123",
            owner_id="456",
            workflow=WORKFLOW,
            **kwargs,
        )


@pytest.fixture
def fulcio_ca():
    return FulcioCA()


@dataclass
class MockFulcio:
    ca: FulcioCA
    certificate_options: dict = field(default_factory=dict)
    response_variant: str = "signedCertificateEmbeddedSct"
    mismatch_key: bool = False
    include_root: bool = False
    requests: list[httpx.Request] = field(default_factory=list)
    certificates: list[x509.Certificate] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "oidc.example":
            assert request.method == "GET"
            assert request.url.params["existing"] == "1"
            assert request.url.params["audience"] == "sigstore"
            assert (
                request.headers["authorization"] == "Bearer runner-request-credential"
            )
            return httpx.Response(200, json={"value": "test-github-jwt"})
        assert str(request.url) == "https://fulcio.example/api/v2/signingCert"
        assert request.method == "POST"
        assert request.headers["authorization"] == "Bearer test-github-jwt"
        body = json.loads(request.content)
        assert set(body) == {"certificateSigningRequest"}
        assert PAYLOAD not in request.content
        csr = x509.load_pem_x509_csr(
            base64.b64decode(body["certificateSigningRequest"], validate=True)
        )
        assert csr.is_signature_valid
        assert len(csr.subject) == 0
        public_key = (
            ec.generate_private_key(ec.SECP256R1()).public_key()
            if self.mismatch_key
            else csr.public_key()
        )
        leaf = self.ca.certificate(public_key, **self.certificate_options)
        self.certificates.append(leaf)
        certificates = [
            leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            *self.ca.chain[:-1],
        ]
        if self.include_root:
            certificates.append(self.ca.pem)
        return httpx.Response(
            200,
            json={self.response_variant: {"chain": {"certificates": certificates}}},
        )


def action_statement(mock: MockFulcio, *, payload: bytes = PAYLOAD) -> bytes:
    with httpx.Client(transport=httpx.MockTransport(mock)) as session:
        return sign.sign_payload(
            payload,
            mock.ca.pem,
            session,
            content_type="application/octet-stream",
            fulcio_url="https://fulcio.example",
            environment=ENVIRONMENT,
        )


class TestGitHubActionOffline:
    @pytest.mark.parametrize(
        "variant", ["signedCertificateEmbeddedSct", "signedCertificateDetachedSct"]
    )
    @pytest.mark.parametrize("include_root", [False, True])
    def test_oidc_csr_cose_flow(self, fulcio_ca, capsys, variant, include_root):
        mock = MockFulcio(
            fulcio_ca, response_variant=variant, include_root=include_root
        )
        statement = action_statement(mock)
        message = Sign1Message.decode(statement)
        assert message.payload == PAYLOAD
        assert message.phdr[Algorithm].identifier == -7
        assert message.phdr[ContentType] == "application/octet-stream"
        assert len(message.phdr[X5chain]) == 2
        assert message.phdr[crypto.CWTClaims][crypto.CWT_ISS] == policy.signing_issuer(
            fulcio_ca.pem, WORKFLOW
        )
        assert isinstance(message.phdr[crypto.CWTClaims][crypto.CWT_IAT], int)
        leaf = x509.load_der_x509_certificate(message.phdr[X5chain][0])
        message.key = CoseKey.from_pem_public_key(
            crypto.get_cert_public_key(
                leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
            )
        )
        assert message.verify_signature()
        assert b"test-github-jwt" not in statement
        assert b"PRIVATE KEY" not in statement
        assert capsys.readouterr().out == "::add-mask::test-github-jwt\n"

    def test_fresh_keys_per_invocation(self, fulcio_ca):
        mock = MockFulcio(fulcio_ca)
        action_statement(mock)
        action_statement(mock, payload=b"")
        assert mock.certificates[0].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != mock.certificates[1].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def test_intermediate_chain(self):
        ca = FulcioCA(intermediate=True)
        message = Sign1Message.decode(action_statement(MockFulcio(ca)))
        assert len(message.phdr[X5chain]) == 3
        assert message.phdr[X5chain][-1] == ca.root.public_bytes(
            serialization.Encoding.DER
        )

    def test_untrusted_certificate_response(self, fulcio_ca):
        mock = MockFulcio(FulcioCA())
        with httpx.Client(transport=httpx.MockTransport(mock)) as session:
            with pytest.raises(ValueError, match="configured authority"):
                sign.sign_payload(
                    PAYLOAD,
                    fulcio_ca.pem,
                    session,
                    fulcio_url="https://fulcio.example",
                    environment=ENVIRONMENT,
                )

    def test_missing_oidc_permissions(self):
        with httpx.Client(
            transport=httpx.MockTransport(
                lambda _: pytest.fail("No request should be sent")
            )
        ) as session:
            with pytest.raises(ValueError, match="id-token: write"):
                sign.github_token(session, {}, "sigstore")

    @pytest.mark.parametrize(
        "url",
        [
            "http://fulcio.example",
            "https://user:secret@fulcio.example",
            "https://fulcio.example/#fragment",
        ],
    )
    def test_https_only(self, url):
        with pytest.raises(ValueError, match="HTTPS URL"):
            sign.https_url(url, "Test URL")

    @pytest.mark.parametrize("endpoint", ["oidc", "fulcio"])
    def test_credential_redirects_rejected(self, fulcio_ca, endpoint):
        requests = []

        def handler(request):
            requests.append(request)
            if endpoint == "fulcio" and request.url.host == "oidc.example":
                return httpx.Response(200, json={"value": "test-github-jwt"})
            return httpx.Response(307, headers={"location": "https://other.example"})

        with httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=True
        ) as session:
            with pytest.raises(httpx.HTTPStatusError, match="307"):
                sign.sign_payload(
                    PAYLOAD,
                    fulcio_ca.pem,
                    session,
                    fulcio_url="https://fulcio.example",
                    environment=ENVIRONMENT,
                )
        assert len(requests) == (1 if endpoint == "oidc" else 2)

    @pytest.mark.parametrize("body", [{}, {"value": 42}, {"value": ""}, ["token"]])
    def test_malformed_oidc_response(self, body):
        with httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
        ) as session:
            with pytest.raises(ValueError, match="token"):
                sign.github_token(session, ENVIRONMENT, "sigstore")

    @pytest.mark.parametrize(
        "body",
        [
            {},
            [],
            {"signedCertificateEmbeddedSct": {}},
            {"signedCertificateEmbeddedSct": {"chain": {"certificates": []}}},
            {"signedCertificateEmbeddedSct": {"chain": {"certificates": [123]}}},
        ],
    )
    def test_malformed_fulcio_response(self, fulcio_ca, body):
        def handler(request):
            return httpx.Response(
                200,
                json=(
                    {"value": "test-github-jwt"}
                    if request.url.host == "oidc.example"
                    else body
                ),
            )

        with httpx.Client(transport=httpx.MockTransport(handler)) as session:
            with pytest.raises(ValueError, match="Fulcio"):
                sign.sign_payload(
                    PAYLOAD,
                    fulcio_ca.pem,
                    session,
                    fulcio_url="https://fulcio.example",
                    environment=ENVIRONMENT,
                )

    @pytest.mark.parametrize(
        "options, mismatch, error",
        [
            ({}, True, "ephemeral signing key"),
            ({"offset": -1200}, False, "expired"),
            ({"offset": 300}, False, "not yet valid"),
            ({"lifetime": 0}, False, "not short lived"),
            ({"lifetime": 601}, False, "not short lived"),
            ({"ca": True}, False, "CA certificate"),
            (
                {"claims": github_claims() | {"issuer": "https://other.example"}},
                False,
                "GitHub Actions identity",
            ),
            ({"san": "https://other.example/workflow"}, False, "workflow URI"),
        ],
    )
    def test_bad_certificates(self, fulcio_ca, options, mismatch, error):
        mock = MockFulcio(fulcio_ca, certificate_options=options, mismatch_key=mismatch)
        with pytest.raises(ValueError, match=error):
            action_statement(mock)

    def test_explicit_root_required(self, fulcio_ca):
        with pytest.raises(ValueError, match="exactly one"):
            policy.trusted_root(fulcio_ca.pem * 2)
        leaf = fulcio_ca.certificate(
            ec.generate_private_key(ec.SECP256R1()).public_key()
        )
        with pytest.raises(ValueError, match="CA certificate"):
            policy.trusted_root(leaf.public_bytes(serialization.Encoding.PEM).decode())

    @pytest.mark.parametrize("length", [0, 127, 128, 255, 256])
    def test_fulcio_utf8_encoding(self, length):
        value = "a" * length
        encoded = policy.der_utf8(value)
        assert encoded[0] == 12
        if encoded[1] < 128:
            assert encoded[1] == length
            assert encoded[2:] == value.encode()
        else:
            size = encoded[1] & 127
            assert int.from_bytes(encoded[2 : 2 + size]) == length
            assert encoded[2 + size :] == value.encode()

    def test_policy_cli_preserves_configuration(self, fulcio_ca, tmp_path, monkeypatch):
        root = tmp_path / "root.pem"
        root.write_text(fulcio_ca.pem)
        original = {
            "authentication": {
                "allowUnauthenticated": False,
                "jwt": {"requiredClaims": {"aud": "ledger"}},
            },
            "maxSignedStatementBytes": 32768,
        }
        configuration = tmp_path / "configuration.json"
        configuration.write_text(json.dumps(original))
        output = tmp_path / "github-policy.json"
        monkeypatch.setattr(
            "sys.argv",
            [
                "policy",
                "--fulcio-root",
                str(root),
                "--repository",
                "octo/example",
                "--repository-id",
                "123",
                "--owner-id",
                "456",
                "--workflow",
                WORKFLOW,
                "--configuration",
                str(configuration),
                "--out",
                str(output),
            ],
        )
        policy.main()
        result = json.loads(output.read_text())
        assert result["authentication"] == original["authentication"]
        assert result["maxSignedStatementBytes"] == original["maxSignedStatementBytes"]
        assert result["policy"]["acceptedAlgorithms"] == ["ES256"]


class TestGitHubLedgerPolicy:
    @pytest.mark.parametrize("intermediate", [False, True])
    def test_action_to_running_ledger(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        trust_store,
        tmp_path,
        intermediate,
    ):
        if intermediate:
            fulcio_ca = FulcioCA(intermediate=True)
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = action_statement(MockFulcio(fulcio_ca))
        outputs = sign.submit(client, statement, tmp_path)
        assert (tmp_path / "signed-statement.cose").read_bytes() == statement
        transparent = (tmp_path / "transparent-statement.cose").read_bytes()
        assert Sign1Message.decode(transparent).payload == PAYLOAD
        verify_transparent_statement(transparent, trust_store, statement)
        assert re.fullmatch(r"\d+\.\d+", outputs["transaction-id"])
        assert json.loads((tmp_path / "submission.json").read_text()) == outputs

    @pytest.mark.parametrize("valid_receipt", [False, True])
    def test_action_entrypoint(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        tmp_path,
        monkeypatch,
        capsys,
        valid_receipt,
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        (tmp_path / "payload.bin").write_bytes(PAYLOAD)
        (tmp_path / "root.pem").write_text(fulcio_ca.pem)
        github_output = tmp_path / "github-output"
        for name, value in {
            "SCITT_WORKSPACE": str(tmp_path),
            "SCITT_FILE": "payload.bin",
            "SCITT_LEDGER_URL": client.url,
            "SCITT_FULCIO_ROOT": "root.pem",
            "SCITT_FULCIO_URL": "https://fulcio.example",
            "SCITT_OUTPUT_DIR": "output",
            "SCITT_DEVELOPMENT": "true",
            "GITHUB_OUTPUT": str(github_output),
        }.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr("sys.argv", ["sign"])
        real_sign_payload = sign.sign_payload

        def exchange(payload, root_pem, session, **kwargs):
            with httpx.Client(
                transport=httpx.MockTransport(MockFulcio(fulcio_ca))
            ) as mock_session:
                return real_sign_payload(
                    payload, root_pem, mock_session, environment=ENVIRONMENT, **kwargs
                )

        monkeypatch.setattr(sign, "sign_payload", exchange)
        if not valid_receipt:

            def reject_receipt(*_):
                raise ValueError("Receipt verification failed")

            monkeypatch.setattr(sign, "verify_transparent_statement", reject_receipt)
            with pytest.raises(SystemExit) as error:
                sign.main()
            assert error.value.code == 1
            assert not github_output.exists()
            assert not (tmp_path / "output/transparent-statement.cose").exists()
            assert "::error::Receipt verification failed" in capsys.readouterr().err
        else:
            sign.main()
            outputs = dict(
                line.split("=", 1) for line in github_output.read_text().splitlines()
            )
            assert set(outputs) == {
                "transaction-id",
                "signed-statement",
                "transparent-statement",
            }
            assert (
                json.loads((tmp_path / "output/submission.json").read_text()) == outputs
            )

    @pytest.mark.parametrize(
        "claim, value",
        [
            ("repository", "https://github.com/unexpected/repository"),
            ("repository_id", "999"),
            ("owner_id", "999"),
            ("issuer", "https://other.example"),
            ("ref", "refs/heads/untrusted"),
            (
                "workflow",
                "https://github.com/unexpected/repo/.github/workflows/x.yml@main",
            ),
            ("event", "pull_request"),
            ("runner", "self-hosted"),
        ],
    )
    def test_reject_unexpected_identity(
        self, fulcio_ca, client: Client, configure_service, claim, value
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = fulcio_ca.statement(claims=github_claims() | {claim: value})
        with service_error("PolicyFailed:.*Unexpected GitHub identity claim"):
            client.submit_signed_statement_and_wait(statement)

    def test_unexpected_repo_cannot_reuse_trusted_workflow(
        self, fulcio_ca, client: Client, configure_service
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = fulcio_ca.statement(
            claims=github_claims()
            | {
                "repository": "https://github.com/attacker/source",
                "repository_id": "789",
                "owner_id": "999",
            }
        )
        assert Sign1Message.decode(statement).phdr[crypto.CWTClaims][
            crypto.CWT_ISS
        ] == (policy.signing_issuer(fulcio_ca.pem, WORKFLOW))
        with service_error("PolicyFailed:.*Unexpected GitHub identity claim"):
            client.submit_signed_statement_and_wait(statement)

    def test_reject_missing_identity(
        self, fulcio_ca, client: Client, configure_service
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        claims = github_claims()
        del claims["repository_id"]
        with service_error("PolicyFailed:.*Unexpected GitHub identity claim"):
            client.submit_signed_statement_and_wait(fulcio_ca.statement(claims=claims))

    def test_reject_untrusted_ca(self, fulcio_ca, client: Client, configure_service):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("PolicyFailed:.*Unexpected signing authority"):
            client.submit_signed_statement_and_wait(FulcioCA().statement())

    def test_reject_wrong_workflow_san(
        self, fulcio_ca, client: Client, configure_service
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("PolicyFailed:.*Unexpected signing authority"):
            client.submit_signed_statement_and_wait(
                fulcio_ca.statement(
                    san="https://github.com/octo/example/.github/workflows/other.yml@refs/heads/main"
                )
            )

    def test_optional_workflow_digest(
        self, fulcio_ca, client: Client, configure_service
    ):
        configure_service(
            {"policy": fulcio_ca.registration_policy(workflow_digest="a" * 40)}
        )
        client.submit_signed_statement_and_wait(fulcio_ca.statement())
        with service_error("PolicyFailed:.*Unexpected GitHub identity claim"):
            client.submit_signed_statement_and_wait(
                fulcio_ca.statement(
                    claims=github_claims() | {"workflow_digest": "b" * 40}
                )
            )

    @pytest.mark.parametrize("offset", [-1200, 300])
    def test_certificate_validity_is_policy_specific(
        self, fulcio_ca, client: Client, configure_service, offset
    ):
        statement = fulcio_ca.statement(offset=offset)
        configure_service(
            {"policy": {"policyScript": "export function apply() { return true; }"}}
        )
        client.submit_signed_statement_and_wait(statement)
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("PolicyFailed:.*expired, not yet valid, or untrusted"):
            client.submit_signed_statement_and_wait(statement)

    @pytest.mark.parametrize("lifetime", [0, 601])
    def test_reject_invalid_certificate_lifetime(
        self, fulcio_ca, client: Client, configure_service, lifetime
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("PolicyFailed:.*not short lived"):
            client.submit_signed_statement_and_wait(
                fulcio_ca.statement(lifetime=lifetime)
            )

    def test_reject_payload_tampering(
        self, fulcio_ca, client: Client, configure_service
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = cbor2.loads(fulcio_ca.statement())
        statement.value[2] = b"tampered"
        with service_error("InvalidInput"):
            client.submit_signed_statement_and_wait(cbor2.dumps(statement))

    @pytest.mark.parametrize("language", ["js", "rego"])
    def test_authenticated_metadata_mapping(
        self, fulcio_ca, client: Client, configure_service, language
    ):
        oid = policy.FULCIO_OIDS["repository_id"]
        expected = policy.der_utf8("123").hex()
        if language == "js":
            registration = {"policyScript": f"""
export function apply(phdr) {{
    return phdr.x509.validitySeconds === 600 &&
        phdr.x509.extensions[{json.dumps(oid)}].length === 1 &&
        phdr.x509.extensions[{json.dumps(oid)}][0] === {json.dumps(expected)}
        ? true : "Certificate metadata mismatch";
}}
"""}
        else:
            registration = {"policyRego": f"""
package policy
default allow := false
allow if {{
    input.phdr["X.509"].validitySeconds == 600
    input.phdr["X.509"].extensions[{json.dumps(oid)}] == [{json.dumps(expected)}]
}}
errors contains "Certificate metadata mismatch" if {{ not allow }}
"""}
        configure_service({"policy": registration})
        client.submit_signed_statement_and_wait(fulcio_ca.statement())
        with service_error("PolicyFailed:.*Certificate metadata mismatch"):
            client.submit_signed_statement_and_wait(
                fulcio_ca.statement(claims=github_claims() | {"repository_id": "999"})
            )
