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

from demo.github_actions import policy, sign, smoke_test
from pyscitt import crypto
from pyscitt.cli.main import main as cli_main
from pyscitt.client import Client
from pyscitt.verify import verify_cose_sign1, verify_transparent_statement

from . import policies
from .infra.assertions import service_error

WORKFLOW = (
    "https://github.com/octo/example/.github/workflows/submit.yml@refs/heads/main"
)
PAYLOAD = b'{"artifact":"example"}\n\x00\xff'
ENVIRONMENT = {
    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/token?existing=1&audience=old",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-request-credential",
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
        oidc_issuer: str | None = policy.GITHUB_ISSUER,
        san: str = WORKFLOW,
        lifetime: int = 600,
        offset: int = -30,
        ca: bool = False,
        basic_constraints: bool = True,
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
        if basic_constraints:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), True
            )
        if eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False
            )
        if oidc_issuer is not None:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(policy.GITHUB_ISSUER_OID),
                    policy.der_utf8(oidc_issuer),
                ),
                False,
            )
        return builder.sign(self.issuer_key, hashes.SHA256())

    def statement(
        self, *, payload: bytes = PAYLOAD, issuer: str | None = None, **kwargs
    ) -> bytes:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = self.certificate(key.public_key(), **kwargs)
        signer = crypto.Signer(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            issuer=issuer
            or policy.signing_issuer(self.pem, kwargs.get("san", WORKFLOW)),
            x5c=[
                leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                *self.chain,
            ],
        )
        return crypto.sign_statement(
            signer, payload, "application/octet-stream", cwt=True
        )

    def registration_policy(self) -> dict:
        return policy.registration_policy(self.pem, workflow=WORKFLOW)


@pytest.fixture
def fulcio_ca(tmp_path, monkeypatch):
    ca = FulcioCA()
    root = tmp_path / "fulcio-root.pem"
    root.write_text(ca.pem)
    monkeypatch.setattr(policy, "FULCIO_ROOT", root)
    return ca


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
        assert str(request.url) == "https://fulcio.sigstore.dev/api/v2/signingCert"
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
            session,
            content_type="application/octet-stream",
            environment=ENVIRONMENT,
        )


class TestGitHubActionOffline:
    @pytest.mark.parametrize(
        "variant", ["signedCertificateEmbeddedSct", "signedCertificateDetachedSct"]
    )
    @pytest.mark.parametrize("include_root", [False, True])
    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_oidc_csr_cose_flow(
        self, fulcio_ca, capsys, variant, include_root, basic_constraints
    ):
        mock = MockFulcio(
            fulcio_ca,
            certificate_options={"basic_constraints": basic_constraints},
            response_variant=variant,
            include_root=include_root,
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
        assert set(message.phdr) == {Algorithm, ContentType, X5chain, crypto.CWTClaims}
        assert set(message.phdr[crypto.CWTClaims]) == {crypto.CWT_ISS}
        leaf = x509.load_der_x509_certificate(message.phdr[X5chain][0])
        if not basic_constraints:
            with pytest.raises(x509.ExtensionNotFound):
                leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        message.key = CoseKey.from_pem_public_key(
            crypto.get_cert_public_key(
                leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
            )
        )
        assert message.verify_signature()
        assert b"test-github-jwt" not in statement
        assert b"PRIVATE KEY" not in statement
        assert capsys.readouterr().out == "::add-mask::test-github-jwt\n"

    @pytest.mark.parametrize("failure", [None, "fulcio", "payload", "signature"])
    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_live_smoke_entrypoint(
        self, fulcio_ca, tmp_path, monkeypatch, capsys, failure, basic_constraints
    ):
        input_path = tmp_path / "payload.bin"
        input_path.write_bytes(PAYLOAD)
        output_path = tmp_path / "output/signed-statement.cose"
        monkeypatch.setattr(
            "sys.argv",
            ["smoke_test", "--file", str(input_path), "--out", str(output_path)],
        )
        for name, value in ENVIRONMENT.items():
            monkeypatch.setenv(name, value)
        mock = MockFulcio(
            fulcio_ca, certificate_options={"basic_constraints": basic_constraints}
        )

        def handler(request):
            if failure == "fulcio" and request.url.host == "fulcio.sigstore.dev":
                return httpx.Response(400, json={"message": "Signing request refused"})
            return mock(request)

        real_client = httpx.Client

        def create_client(**kwargs):
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(smoke_test.httpx, "Client", create_client)
        real_sign_payload = sign.sign_payload

        def sign_for_test(payload, session, **kwargs):
            statement = real_sign_payload(
                b"different" if failure == "payload" else payload, session, **kwargs
            )
            if failure == "signature":
                statement = statement[:-1] + bytes([statement[-1] ^ 1])
            return statement

        monkeypatch.setattr(sign, "sign_payload", sign_for_test)
        if failure is not None:
            with pytest.raises(SystemExit) as error:
                smoke_test.main()
            assert error.value.code == 1
            assert not output_path.exists()
            error_output = capsys.readouterr().err
            assert "::error::" in error_output
            assert {
                "fulcio": "400",
                "payload": "COSE payload does not match",
                "signature": "signature is invalid",
            }[failure] in error_output
        else:
            smoke_test.main()
            statement = output_path.read_bytes()
            message = Sign1Message.decode(statement)
            assert message.payload == PAYLOAD
            assert message.phdr[ContentType] == "application/json"
            leaf = crypto.cert_der_to_pem(message.phdr[X5chain][0])
            verify_cose_sign1(statement, crypto.get_cert_public_key(leaf))
            assert b"test-github-jwt" not in statement
            assert b"PRIVATE KEY" not in statement
            output = capsys.readouterr().out
            assert "::add-mask::test-github-jwt\n" in output
            assert "Created and verified Fulcio-backed COSE signature" in output

    def test_fresh_keys_per_invocation(self, fulcio_ca):
        mock = MockFulcio(fulcio_ca)
        action_statement(mock)
        action_statement(mock, payload=b"")
        assert mock.certificates[0].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != mock.certificates[1].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def test_intermediate_chain(self, fulcio_ca):
        ca = FulcioCA(intermediate=True)
        policy.FULCIO_ROOT.write_text(ca.pem)
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
                    session,
                    environment=ENVIRONMENT,
                )

    def test_missing_oidc_permissions(self):
        with httpx.Client(
            transport=httpx.MockTransport(
                lambda _: pytest.fail("No request should be sent")
            )
        ) as session:
            with pytest.raises(ValueError, match="id-token: write"):
                sign.github_token(session, {})

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
                    session,
                    environment=ENVIRONMENT,
                )
        assert len(requests) == (1 if endpoint == "oidc" else 2)

    @pytest.mark.parametrize("body", [{}, {"value": 42}, {"value": ""}, ["token"]])
    def test_malformed_oidc_response(self, body):
        with httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
        ) as session:
            with pytest.raises(ValueError, match="token"):
                sign.github_token(session, ENVIRONMENT)

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
                    session,
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
                {"oidc_issuer": "https://other.example"},
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

    @pytest.mark.parametrize("options", [{"eku": False}, {"oidc_issuer": None}])
    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_missing_identity_extensions(self, fulcio_ca, options, basic_constraints):
        with pytest.raises(x509.ExtensionNotFound) as error:
            action_statement(
                MockFulcio(
                    fulcio_ca,
                    certificate_options={
                        **options,
                        "basic_constraints": basic_constraints,
                    },
                )
            )
        assert error.value.oid == (
            x509.ExtendedKeyUsage.oid
            if "eku" in options
            else ObjectIdentifier(policy.GITHUB_ISSUER_OID)
        )

    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_trusted_root_validation(self, fulcio_ca, basic_constraints):
        with pytest.raises(ValueError, match="exactly one"):
            policy.trusted_root(fulcio_ca.pem * 2)
        leaf = fulcio_ca.certificate(
            ec.generate_private_key(ec.SECP256R1()).public_key(),
            basic_constraints=basic_constraints,
        )
        error = ValueError if basic_constraints else x509.ExtensionNotFound
        with pytest.raises(
            error, match="CA certificate" if basic_constraints else "BasicConstraints"
        ):
            policy.trusted_root(leaf.public_bytes(serialization.Encoding.PEM).decode())

    def test_bundled_public_fulcio_root(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        root = policy.trusted_root(policy.FULCIO_ROOT.read_text())
        assert root.fingerprint(hashes.SHA256()).hex() == (
            "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1"
        )

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

    @pytest.mark.parametrize("allow_unauthenticated", [False, True])
    def test_policy_cli_defaults(
        self, fulcio_ca, tmp_path, monkeypatch, allow_unauthenticated
    ):
        output = tmp_path / "github-policy.json"
        arguments = ["policy", "--workflow", WORKFLOW, "--out", str(output)]
        if allow_unauthenticated:
            arguments.append("--allow-unauthenticated")
        monkeypatch.setattr("sys.argv", arguments)
        policy.main()
        assert json.loads(output.read_text()) == {
            "authentication": {"allowUnauthenticated": allow_unauthenticated},
            "policy": fulcio_ca.registration_policy(),
        }

    def test_pyscitt_cli_header_compatibility(self, fulcio_ca, tmp_path, monkeypatch):
        key = ec.generate_private_key(ec.SECP256R1())
        monkeypatch.setattr(sign.ec, "generate_private_key", lambda _: key)
        statement = action_statement(MockFulcio(fulcio_ca))
        message = Sign1Message.decode(statement)
        payload_path = tmp_path / "payload.bin"
        payload_path.write_bytes(PAYLOAD)
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        chain_path = tmp_path / "chain.pem"
        chain_path.write_text(
            "".join(crypto.cert_der_to_pem(cert) for cert in message.phdr[X5chain])
        )
        output_path = tmp_path / "cli-statement.cose"
        cli_main(
            [
                "sign",
                "--statement",
                str(payload_path),
                "--key",
                str(key_path),
                "--x5c",
                str(chain_path),
                "--issuer",
                policy.signing_issuer(fulcio_ca.pem, WORKFLOW),
                "--content-type",
                "application/octet-stream",
                "--out",
                str(output_path),
                "--uses-cwt",
            ]
        )
        cli_message = Sign1Message.decode(output_path.read_bytes())
        assert cli_message.phdr == message.phdr
        assert cli_message.uhdr == message.uhdr == {}
        assert cli_message.payload == message.payload == PAYLOAD
        for signed in [message, cli_message]:
            signed.key = CoseKey.from_pem_public_key(
                crypto.get_cert_public_key(
                    crypto.cert_der_to_pem(signed.phdr[X5chain][0])
                )
            )
            assert signed.verify_signature()

    @pytest.mark.parametrize(
        "option",
        [
            "--fulcio-root",
            "--fulcio-url",
            "--audience",
            "--auth-token",
            "--development",
        ],
    )
    def test_removed_options_rejected(self, option, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["sign", option, "unused"])
        with pytest.raises(SystemExit) as error:
            sign.main()
        assert error.value.code == 2
        assert f"unrecognized arguments: {option}" in capsys.readouterr().err


class TestGitHubLedgerPolicy:
    @pytest.mark.parametrize("intermediate", [False, True])
    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_action_to_running_ledger(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        trust_store,
        tmp_path,
        intermediate,
        basic_constraints,
    ):
        if intermediate:
            fulcio_ca = FulcioCA(intermediate=True)
            policy.FULCIO_ROOT.write_text(fulcio_ca.pem)
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = action_statement(
            MockFulcio(
                fulcio_ca, certificate_options={"basic_constraints": basic_constraints}
            )
        )
        outputs = sign.submit(client, statement, tmp_path)
        assert (tmp_path / "signed-statement.cose").read_bytes() == statement
        transparent = (tmp_path / "transparent-statement.cose").read_bytes()
        assert Sign1Message.decode(transparent).payload == PAYLOAD
        verify_transparent_statement(transparent, trust_store, statement)
        assert re.fullmatch(r"\d+\.\d+", outputs["transaction-id"])
        assert json.loads((tmp_path / "submission.json").read_text()) == outputs

    @pytest.mark.parametrize("valid_receipt", [False, True])
    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_action_entrypoint(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        tmp_path,
        monkeypatch,
        capsys,
        valid_receipt,
        basic_constraints,
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        (tmp_path / "payload.bin").write_bytes(PAYLOAD)
        (tmp_path / "service-ca.pem").write_text(client.get_service_certificate())
        github_output = tmp_path / "github-output"
        for name, value in {
            "SCITT_WORKSPACE": str(tmp_path),
            "SCITT_FILE": "payload.bin",
            "SCITT_LEDGER_URL": client.url,
            "SCITT_SERVICE_CA": "service-ca.pem",
            "SCITT_OUTPUT_DIR": "output",
            "GITHUB_OUTPUT": str(github_output),
        }.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr("sys.argv", ["sign"])
        real_sign_payload = sign.sign_payload

        def exchange(payload, session, **kwargs):
            with httpx.Client(
                transport=httpx.MockTransport(
                    MockFulcio(
                        fulcio_ca,
                        certificate_options={"basic_constraints": basic_constraints},
                    )
                )
            ) as mock_session:
                return real_sign_payload(
                    payload, mock_session, environment=ENVIRONMENT, **kwargs
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
        "workflow",
        [
            "https://github.com/unexpected/repository/.github/workflows/submit.yml@refs/heads/main",
            "https://github.com/octo/example/.github/workflows/other.yml@refs/heads/main",
            "https://github.com/octo/example/.github/workflows/submit.yml@refs/heads/untrusted",
        ],
    )
    def test_reject_unexpected_workflow(
        self, fulcio_ca, client: Client, configure_service, workflow
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = fulcio_ca.statement(san=workflow)
        with service_error("PolicyFailed:.*Unexpected signing authority or workflow"):
            client.submit_signed_statement_and_wait(statement)

    def test_reject_untrusted_ca(self, fulcio_ca, client: Client, configure_service):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("PolicyFailed:.*Unexpected signing authority"):
            client.submit_signed_statement_and_wait(FulcioCA().statement())

    @pytest.mark.parametrize("untrusted_ca", [False, True])
    def test_cannot_forge_allowed_issuer(
        self, fulcio_ca, client: Client, configure_service, untrusted_ca
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        ca = FulcioCA() if untrusted_ca else fulcio_ca
        with service_error("InvalidInput:.*Failed to resolve did:x509 issuer"):
            client.submit_signed_statement_and_wait(
                ca.statement(
                    san=(
                        WORKFLOW
                        if untrusted_ca
                        else "https://github.com/unexpected/repo/.github/workflows/submit.yml@refs/heads/main"
                    ),
                    issuer=policy.signing_issuer(fulcio_ca.pem, WORKFLOW),
                )
            )

    def test_reject_missing_eku(self, fulcio_ca, client: Client, configure_service):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("InvalidInput:.*Failed to resolve did:x509 issuer"):
            client.submit_signed_statement_and_wait(fulcio_ca.statement(eku=False))

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

    def test_reject_payload_tampering(
        self, fulcio_ca, client: Client, configure_service
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = cbor2.loads(fulcio_ca.statement())
        statement.value[2] = b"tampered"
        with service_error("InvalidInput"):
            client.submit_signed_statement_and_wait(cbor2.dumps(statement))

    @pytest.mark.parametrize("language", ["js", "rego"])
    def test_existing_policy_engine_accepts_action_statement(
        self, fulcio_ca, client: Client, configure_service, language
    ):
        issuer = policy.signing_issuer(fulcio_ca.pem, WORKFLOW)
        registration = policies.DID_X509[language](issuer)
        configure_service({"policy": registration})
        client.submit_signed_statement_and_wait(action_statement(MockFulcio(fulcio_ca)))
        with service_error("PolicyFailed:.*Invalid issuer"):
            client.submit_signed_statement_and_wait(FulcioCA().statement())
