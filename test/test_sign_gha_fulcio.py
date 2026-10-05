# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from importlib import import_module
from pathlib import Path
from unittest.mock import Mock, patch

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

from pyscitt import crypto
from pyscitt.cli import register
from pyscitt.cli import sign_gha_fulcio as sign
from pyscitt.cli.main import main as cli_main
from pyscitt.client import Client, PendingSubmission, Submission
from pyscitt.verify import verify_cose_sign1, verify_transparent_statement

from . import policies
from .infra.assertions import service_error
from .infra.scitt_action import ACTION_DIRECTORY, load_action

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
        oidc_issuer: str | None = sign.GITHUB_ISSUER,
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
                    ObjectIdentifier(sign.GITHUB_ISSUER_OID),
                    sign.der_utf8(oidc_issuer),
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
            issuer=issuer or sign.signing_issuer(self.pem, kwargs.get("san", WORKFLOW)),
            x5c=[
                leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                *self.chain,
            ],
        )
        return crypto.sign_statement(
            signer, payload, "application/octet-stream", cwt=True
        )

    def registration_policy(self) -> dict:
        return policies.DID_X509["js"](sign.signing_issuer(self.pem, WORKFLOW))


@pytest.fixture
def fulcio_ca(tmp_path, monkeypatch):
    ca = FulcioCA()
    root = tmp_path / "fulcio-root.pem"
    root.write_text(ca.pem)
    monkeypatch.setattr(sign, "FULCIO_ROOT", root)
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


def tamper_payload(statement: bytes) -> bytes:
    message = Sign1Message.decode(statement)
    assert message.payload is not None
    message.payload += b"tampered"
    return message.encode(tag=True, sign=False)


class TestSignGhaFulcioOffline:
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
        assert message.phdr[crypto.CWTClaims][crypto.CWT_ISS] == sign.signing_issuer(
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
    @pytest.mark.parametrize("content_type", [None, "application/json"])
    def test_sign_cli(
        self,
        fulcio_ca,
        tmp_path,
        monkeypatch,
        capsys,
        failure,
        basic_constraints,
        content_type,
    ):
        input_path = tmp_path / "payload.bin"
        input_path.write_bytes(PAYLOAD)
        output_path = tmp_path / "output/signed-statement.cose"
        arguments = [
            "sign-gha-fulcio",
            "--statement",
            str(input_path),
            "--out",
            str(output_path),
        ]
        if content_type is not None:
            arguments.extend(["--content-type", content_type])
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

        monkeypatch.setattr(sign.httpx, "Client", create_client)
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
                cli_main(arguments)
            assert error.value.code == 1
            assert not output_path.exists()
            error_output = capsys.readouterr().err
            assert "Error:" in error_output
            assert {
                "fulcio": "400",
                "payload": "COSE payload does not match",
                "signature": "signature is invalid",
            }[failure] in error_output
        else:
            cli_main(arguments)
            statement = output_path.read_bytes()
            message = Sign1Message.decode(statement)
            assert message.payload == PAYLOAD
            assert message.phdr[ContentType] == (
                content_type or "application/octet-stream"
            )
            leaf = crypto.cert_der_to_pem(message.phdr[X5chain][0])
            verify_cose_sign1(statement, crypto.get_cert_public_key(leaf))
            assert b"test-github-jwt" not in statement
            assert b"PRIVATE KEY" not in statement
            output = capsys.readouterr().out
            assert "::add-mask::test-github-jwt\n" in output
            assert f"Writing {output_path}" in output

    @pytest.mark.parametrize("failure", ["oidc", "missing-file", "output-extension"])
    def test_sign_cli_invalid_input(self, tmp_path, monkeypatch, capsys, failure):
        statement_path = tmp_path / "payload"
        if failure != "missing-file":
            statement_path.write_bytes(PAYLOAD)
        output_path = tmp_path / (
            "signed-statement.txt" if failure == "output-extension" else "output.cose"
        )
        for name in ENVIRONMENT:
            monkeypatch.delenv(name, raising=False)
        with pytest.raises(SystemExit) as error:
            cli_main(
                [
                    "sign-gha-fulcio",
                    "--statement",
                    str(statement_path),
                    "--out",
                    str(output_path),
                ]
            )
        assert error.value.code == 1
        assert not output_path.exists()
        assert {
            "oidc": "id-token: write",
            "missing-file": "No such file",
            "output-extension": "--out must end with .cose",
        }[failure] in capsys.readouterr().err

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
        sign.FULCIO_ROOT.write_text(ca.pem)
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
            else ObjectIdentifier(sign.GITHUB_ISSUER_OID)
        )

    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_trusted_root_validation(self, fulcio_ca, basic_constraints):
        with pytest.raises(ValueError, match="exactly one"):
            sign.trusted_root(fulcio_ca.pem * 2)
        leaf = fulcio_ca.certificate(
            ec.generate_private_key(ec.SECP256R1()).public_key(),
            basic_constraints=basic_constraints,
        )
        error = ValueError if basic_constraints else x509.ExtensionNotFound
        with pytest.raises(
            error, match="CA certificate" if basic_constraints else "BasicConstraints"
        ):
            sign.trusted_root(leaf.public_bytes(serialization.Encoding.PEM).decode())

    def test_bundled_public_fulcio_root(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        root = sign.trusted_root(sign.FULCIO_ROOT.read_text())
        assert root.fingerprint(hashes.SHA256()).hex() == (
            "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1"
        )

    @pytest.mark.parametrize("length", [0, 127, 128, 255, 256])
    def test_fulcio_utf8_encoding(self, length):
        value = "a" * length
        encoded = sign.der_utf8(value)
        assert encoded[0] == 12
        if encoded[1] < 128:
            assert encoded[1] == length
            assert encoded[2:] == value.encode()
        else:
            size = encoded[1] & 127
            assert int.from_bytes(encoded[2 : 2 + size]) == length
            assert encoded[2 + size :] == value.encode()

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
                sign.signing_issuer(fulcio_ca.pem, WORKFLOW),
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
            "--ledger-url",
            "--service-ca",
        ],
    )
    def test_removed_options_rejected(self, option, capsys):
        with pytest.raises(SystemExit) as error:
            cli_main(
                [
                    "sign-gha-fulcio",
                    "--statement",
                    "unused",
                    "--out",
                    "unused.cose",
                    option,
                    "unused",
                ]
            )
        assert error.value.code == 2
        assert f"unrecognized arguments: {option}" in capsys.readouterr().err

    def test_archived_public_fulcio_statement(self):
        payloads = Path(__file__).with_name("payloads")
        statement = (payloads / "github-fulcio-20261001.cose").read_bytes()
        provenance = json.loads((payloads / "github-fulcio-20261001.json").read_text())
        assert sha256(statement).hexdigest() == provenance["statement_sha256"]
        message = Sign1Message.decode(statement)
        assert set(message.phdr) == {Algorithm, ContentType, X5chain, crypto.CWTClaims}
        assert message.phdr[Algorithm].identifier == -7
        assert message.phdr[ContentType] == "application/json"
        assert json.loads(message.payload) == {
            "example": "GitHub Actions keyless SCITT submission",
            "version": 1,
        }
        chain = [x509.load_der_x509_certificate(der) for der in message.phdr[X5chain]]
        root_pem = sign.FULCIO_ROOT.read_text()
        root = sign.trusted_root(root_pem)
        assert len(chain) == 3
        assert chain[-1].fingerprint(hashes.SHA256()) == root.fingerprint(
            hashes.SHA256()
        )
        for child, parent in zip(chain, chain[1:]):
            child.verify_directly_issued_by(parent)
        leaf = chain[0]
        assert (
            leaf.not_valid_before_utc.isoformat()
            == provenance["certificate_not_before"]
        )
        assert (
            leaf.not_valid_after_utc.isoformat() == provenance["certificate_not_after"]
        )
        issuer_extension = leaf.extensions.get_extension_for_oid(
            ObjectIdentifier(sign.GITHUB_ISSUER_OID)
        ).value
        assert isinstance(issuer_extension, x509.UnrecognizedExtension)
        assert issuer_extension.value == sign.der_utf8(sign.GITHUB_ISSUER)
        assert (
            ExtendedKeyUsageOID.CODE_SIGNING
            in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        )
        assert leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier) == [
            provenance["workflow"]
        ]
        assert message.phdr[crypto.CWTClaims] == {
            crypto.CWT_ISS: sign.signing_issuer(root_pem, provenance["workflow"])
        }
        sign.verify_statement(statement, message.payload)

    @pytest.mark.parametrize("arguments", [["--verify"], ["--output", "json"]])
    def test_removed_submit_options(self, monkeypatch, capsys, arguments):
        monkeypatch.setattr(
            register,
            "create_client",
            lambda _: pytest.fail("No client should be created"),
        )
        with pytest.raises(SystemExit) as error:
            cli_main(["submit", "statement.cose", *arguments])
        assert error.value.code == 2
        assert "unrecognized arguments" in capsys.readouterr().err

    @pytest.mark.parametrize("flow", ["pending", "async", "sync"])
    def test_submit_preserves_existing_flow(self, tmp_path, monkeypatch, capsys, flow):
        statement_path = tmp_path / "statement.cose"
        statement_path.write_bytes(PAYLOAD)
        transparent_path = tmp_path / "transparent-statement.cose"
        client = Client("https://ledger.example", development=True)
        pending = Mock(return_value=PendingSubmission("1.2"))
        asynchronous = Mock(return_value=Submission("1.2", "1.3", b"transparent", True))
        synchronous = Mock(return_value=Submission("1.2", "1.4", b"receipt", False))
        monkeypatch.setattr(client, "submit_signed_statement", pending)
        monkeypatch.setattr(client, "submit_signed_statement_and_wait", asynchronous)
        monkeypatch.setattr(
            client, "submit_signed_statement_wait_for_commit", synchronous
        )
        monkeypatch.setattr(
            client,
            "get_scitt_keys",
            lambda: pytest.fail("Registration must not fetch verification keys"),
        )
        monkeypatch.setattr(
            client,
            "get_transparent_statement",
            lambda _: pytest.fail(
                "Existing unverified synchronous output is unchanged"
            ),
        )
        monkeypatch.setattr(register, "create_client", lambda _: client)
        arguments = ["submit", str(statement_path)]
        if flow == "pending":
            arguments.append("--skip-confirmation")
        else:
            arguments.extend(["--transparent-statement", str(transparent_path)])
            if flow == "sync":
                arguments.append("--wait-for-commit")
        with client.session:
            cli_main(arguments)
        text = capsys.readouterr().out
        if flow == "pending":
            pending.assert_called_once_with(PAYLOAD)
            asynchronous.assert_not_called()
            synchronous.assert_not_called()
            assert not transparent_path.exists()
            assert f"Submitted {statement_path} as operation 1.2" in text
            assert "Confirmation of submission was skipped" in text
        else:
            pending.assert_not_called()
            expected_tx = "1.4" if flow == "sync" else "1.3"
            if flow == "sync":
                synchronous.assert_called_once_with(PAYLOAD)
                asynchronous.assert_not_called()
            else:
                asynchronous.assert_called_once_with(PAYLOAD)
                synchronous.assert_not_called()
            assert transparent_path.read_bytes() == (
                b"receipt" if flow == "sync" else b"transparent"
            )
            assert f"Registered {statement_path} as transaction {expected_tx}" in text
            assert f"Received {transparent_path}" in text


class TestSignGhaFulcioLedger:
    @pytest.mark.parametrize("basic_constraints", [False, True])
    @pytest.mark.parametrize("failure", ["workflow", "receipt"])
    def test_sign_submit_and_validate_cli_failure(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        tmp_path,
        monkeypatch,
        capsys,
        basic_constraints,
        failure,
    ):
        mock = MockFulcio(
            fulcio_ca,
            certificate_options={
                "basic_constraints": basic_constraints,
                "san": (
                    WORKFLOW
                    if failure != "workflow"
                    else "https://github.com/unexpected/repo/.github/workflows/submit.yml@refs/heads/main"
                ),
            },
        )
        real_sign_payload = sign.sign_payload

        def exchange(payload, session, **kwargs):
            with httpx.Client(transport=httpx.MockTransport(mock)) as mock_session:
                return real_sign_payload(
                    payload, mock_session, environment=ENVIRONMENT, **kwargs
                )

        monkeypatch.setattr(sign, "sign_payload", exchange)
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement_path = tmp_path / "signed-statement.cose"
        payload_path = tmp_path / "payload"
        payload_path.write_bytes(PAYLOAD)
        cli_main(
            [
                "sign-gha-fulcio",
                "--statement",
                str(payload_path),
                "--out",
                str(statement_path),
            ]
        )
        capsys.readouterr()
        service_ca = tmp_path / "service-ca.pem"
        service_ca.write_text(client.get_service_certificate())
        transparent_path = tmp_path / "transparent-statement.cose"
        arguments = [
            "submit",
            str(statement_path),
            "--url",
            client.url,
            "--cacert",
            str(service_ca),
            "--transparent-statement",
            str(transparent_path),
        ]
        if failure == "workflow":
            with service_error("PolicyFailed:.*Invalid issuer"):
                cli_main(arguments)
            assert not transparent_path.exists()
            assert not capsys.readouterr().out
            return

        cli_main(arguments)
        assert transparent_path.exists()
        assert f"Received {transparent_path}" in capsys.readouterr().out
        transparent_path.write_bytes(tamper_payload(transparent_path.read_bytes()))
        trust_directory = tmp_path / "trust-store"
        trust_directory.mkdir()
        (trust_directory / "scitt-keys.cbor").write_bytes(
            cbor2.dumps(client.get_scitt_keys())
        )
        with pytest.raises(SystemExit) as error:
            cli_main(
                [
                    "validate",
                    str(transparent_path),
                    "--service-trust-store",
                    str(trust_directory),
                    "--offline",
                    "--output",
                    "json",
                ]
            )
        assert error.value.code == 1
        report = json.loads(capsys.readouterr().out)
        assert report["transparent"] is False
        assert report["error"]
        assert report["receipts"] == []
        assert transparent_path.exists()

    @pytest.mark.parametrize("intermediate", [False, True])
    @pytest.mark.parametrize("basic_constraints", [False, True])
    def test_sign_submit_and_validate_cli(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        trust_store,
        tmp_path,
        monkeypatch,
        capsys,
        intermediate,
        basic_constraints,
    ):
        if intermediate:
            fulcio_ca = FulcioCA(intermediate=True)
            sign.FULCIO_ROOT.write_text(fulcio_ca.pem)
        configure_service({"policy": fulcio_ca.registration_policy()})
        mock = MockFulcio(
            fulcio_ca, certificate_options={"basic_constraints": basic_constraints}
        )
        real_sign_payload = sign.sign_payload

        def exchange(payload, session, **kwargs):
            with httpx.Client(transport=httpx.MockTransport(mock)) as mock_session:
                return real_sign_payload(
                    payload, mock_session, environment=ENVIRONMENT, **kwargs
                )

        monkeypatch.setattr(sign, "sign_payload", exchange)
        payload_path = tmp_path / "payload.bin"
        payload_path.write_bytes(PAYLOAD)
        statement_path = tmp_path / "signed-statement.cose"
        cli_main(
            [
                "sign-gha-fulcio",
                "--statement",
                str(payload_path),
                "--out",
                str(statement_path),
                "--content-type",
                "application/json",
            ]
        )
        capsys.readouterr()
        service_ca = tmp_path / "service-ca.pem"
        service_ca.write_text(client.get_service_certificate())
        transparent_path = tmp_path / "transparent-statement.cose"
        cli_main(
            [
                "submit",
                str(statement_path),
                "--url",
                client.url,
                "--cacert",
                str(service_ca),
                "--transparent-statement",
                str(transparent_path),
            ]
        )
        registration_output = capsys.readouterr().out
        trust_directory = tmp_path / "trust-store"
        trust_directory.mkdir()
        (trust_directory / "scitt-keys.cbor").write_bytes(
            cbor2.dumps(client.get_scitt_keys())
        )
        cli_main(
            [
                "validate",
                str(transparent_path),
                "--service-trust-store",
                str(trust_directory),
                "--offline",
                "--output",
                "json",
            ]
        )
        report = json.loads(capsys.readouterr().out)
        statement = statement_path.read_bytes()
        transparent = transparent_path.read_bytes()
        message = Sign1Message.decode(statement)
        assert message.payload == PAYLOAD
        assert message.phdr[ContentType] == "application/json"
        assert len(message.phdr[X5chain]) == (3 if intermediate else 2)
        verify_transparent_statement(transparent, trust_store, statement)
        assert report["transparent"] is True
        assert report["statement"] == str(transparent_path)
        assert len(report["receipts"]) == 1
        receipt = report["receipts"][0]
        transaction_id = receipt["registration_txid"]
        assert re.fullmatch(r"\d+\.\d+", transaction_id)
        assert (
            f"Registered {statement_path} as transaction {transaction_id}"
            in registration_output
        )
        entry_url = f"https://{receipt['issuer']}/entries/{transaction_id}"
        assert receipt["urls"] == {
            "receipt": entry_url,
            "transparent_statement": f"{entry_url}/statement",
        }
        assert receipt["verification_key_source"] == "trust_store"

    @pytest.mark.parametrize(
        "failure",
        [None, "workflow", "receipt", "keys", "url", "metadata", "payload", "repeat"],
    )
    def test_composite_action_scripts(
        self,
        fulcio_ca,
        client: Client,
        configure_service,
        trust_store,
        tmp_path,
        failure,
    ):
        configure_service({"policy": fulcio_ca.registration_policy()})
        statement = action_statement(
            MockFulcio(
                fulcio_ca,
                certificate_options={
                    "basic_constraints": False,
                    "san": (
                        WORKFLOW
                        if failure != "workflow"
                        else WORKFLOW.replace(
                            "/octo/example/", "/unexpected/repository/"
                        )
                    ),
                },
            )
        )
        fixture_path = tmp_path / "issued.cose"
        payload_path = tmp_path / "payload with spaces;$(echo injected).bin"
        service_ca = tmp_path / "service ca.pem"
        service_ca.write_text(client.get_service_certificate())
        cli_path = tmp_path / "scitt"
        cli_path.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "from pyscitt.cli import sign_gha_fulcio, validate\n"
            "from pyscitt.cli.main import main\n"
            "if sys.argv[1] == 'sign-gha-fulcio':\n"
            "    sign_gha_fulcio.sign_payload = lambda *a, **kw: "
            "Path(os.environ['SCITT_TEST_STATEMENT']).read_bytes()\n"
            "elif sys.argv[1] == 'validate' and os.environ.get('SCITT_TEST_BAD_METADATA'):\n"
            "    real_validate = validate.validate_transparent_statement\n"
            "    def invalid_metadata(*args):\n"
            "        result = real_validate(*args)\n"
            "        result['receipts'][0]['registration_txid'] = '1.2\\ninjected=value'\n"
            "        return result\n"
            "    validate.validate_transparent_statement = invalid_metadata\n"
            "main(sys.argv[1:])\n"
        )
        cli_path.chmod(0o700)
        output_root = tmp_path / "output with spaces;$(echo injected)"
        runner_temp = tmp_path / "runner temp"
        runner_temp.mkdir()
        environment = os.environ | {
            "SCITT_CLI": str(cli_path),
            "SCITT_PYTHON": sys.executable,
            "SCITT_FILE": str(payload_path),
            "SCITT_LEDGER_URL": (
                client.url if failure != "url" else "http://ledger.example"
            ),
            "SCITT_SERVICE_CA": str(service_ca),
            "SCITT_CONTENT_TYPE": "application/octet-stream",
            "SCITT_OUTPUT_DIR": str(output_root),
            "SCITT_TEST_STATEMENT": str(fixture_path),
            "SCITT_TEST_BAD_METADATA": "1" if failure == "metadata" else "",
            "GITHUB_ACTION_PATH": str(ACTION_DIRECTORY),
            "RUNNER_TEMP": str(runner_temp),
        }
        yaml = import_module("yaml")
        action = yaml.safe_load((ACTION_DIRECTORY / "action.yml").read_text())
        steps = action["runs"]["steps"]
        action_steps = [
            next(step for step in steps if "SCITT_FILE" in step.get("env", {})),
            next(step for step in steps if step.get("id") == "submit"),
            next(step for step in steps if step.get("id") == "verify"),
        ]
        for name, output in action["outputs"].items():
            assert output["value"] == f"${{{{ steps.verify.outputs.{name} }}}}"
        artifacts = []
        for invocation in range(2 if failure == "repeat" else 1):
            payload = PAYLOAD if invocation == 0 else PAYLOAD + b"second invocation"
            if invocation:
                statement = action_statement(MockFulcio(fulcio_ca), payload=payload)
            fixture_path.write_bytes(statement)
            payload_path.write_bytes(payload)
            setup_output = tmp_path / f"setup-output-{invocation}"
            github_output = tmp_path / f"github-output-{invocation}"
            helper = load_action()
            with (
                patch.dict(
                    os.environ,
                    environment
                    | {
                        "SCITT_OUTPUT_DIR": str(output_root),
                        "GITHUB_OUTPUT": str(setup_output),
                    },
                ),
                patch.object(helper.venv, "create"),
                patch.object(helper.subprocess, "run"),
            ):
                helper.setup()
            setup_outputs = dict(
                line.split("=", 1) for line in setup_output.read_text().splitlines()
            )
            output_dir = Path(setup_outputs["output-dir"])
            transparent_path = output_dir / "transparent-statement.cose"
            environment["SCITT_OUTPUT_DIR"] = str(output_dir)
            environment["GITHUB_OUTPUT"] = str(github_output)
            for step in action_steps:
                assert step["shell"] == "python"
                result = subprocess.run(
                    [sys.executable, "-c", step["run"]],
                    cwd=tmp_path,
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                if result.returncode:
                    break
                if step.get("id") != "submit":
                    continue
                assert transparent_path.exists()
                assert not github_output.exists()
                assert not list(output_dir.glob("*.json"))
                if failure == "receipt":
                    message = Sign1Message.decode(transparent_path.read_bytes())
                    receipts = message.uhdr[crypto.SCITTReceipts]
                    receipt = Sign1Message.decode(receipts[0])
                    receipt._signature = (
                        bytes([receipt.signature[0] ^ 1]) + receipt.signature[1:]
                    )
                    receipts[0] = receipt.encode(tag=True, sign=False)
                    transparent_path.write_bytes(message.encode(tag=True, sign=False))
                elif failure == "keys":
                    wrong_ca = tmp_path / "wrong-ca.pem"
                    wrong_ca.write_text(fulcio_ca.pem)
                    environment["SCITT_SERVICE_CA"] = str(wrong_ca)
                elif failure == "payload":
                    unrelated = fulcio_ca.statement(payload=PAYLOAD + b"unrelated")
                    replacement = client.submit_signed_statement_and_wait(unrelated)
                    verify_transparent_statement(
                        replacement.response_bytes, trust_store, unrelated
                    )
                    transparent_path.write_bytes(replacement.response_bytes)
            assert not (tmp_path / "injected").exists()
            assert not list(runner_temp.glob("scitt-trust-*"))
            assert not list(output_dir.glob("*.json"))
            if failure not in (None, "repeat"):
                assert result.returncode != 0
                if failure in ("receipt", "payload"):
                    report = json.loads(result.stdout)
                    assert report["transparent"] is False
                    assert report["error"]
                    assert report["receipts"] == []
                    if failure == "payload":
                        assert "does not match expected payload" in report["error"]
                    else:
                        assert "does not match expected payload" not in report["error"]
                else:
                    assert {
                        "workflow": "PolicyFailed",
                        "keys": "CERTIFICATE_VERIFY_FAILED",
                        "url": "Ledger URL must use HTTPS",
                        "metadata": "Verification output has an invalid registration transaction ID",
                    }[failure] in result.stderr
                assert not github_output.exists()
                assert transparent_path.exists() == (
                    failure in ("receipt", "keys", "metadata", "payload")
                )
            else:
                assert result.returncode == 0, result.stderr
                outputs = dict(
                    line.split("=", 1)
                    for line in github_output.read_text().splitlines()
                )
                assert set(outputs) == {
                    "transaction-id",
                    "signed-statement",
                    "transparent-statement",
                }
                report = json.loads(result.stdout)
                assert report["transparent"] is True
                assert report["statement"] == outputs["transparent-statement"]
                assert len(report["receipts"]) == 1
                receipt = report["receipts"][0]
                assert receipt["registration_txid"] == outputs["transaction-id"]
                entry_url = (
                    f"https://{receipt['issuer']}/entries/{outputs['transaction-id']}"
                )
                assert receipt["urls"] == {
                    "receipt": entry_url,
                    "transparent_statement": f"{entry_url}/statement",
                }
                assert receipt["verification_key_source"] == "trust_store"
                signed_path = Path(outputs["signed-statement"])
                assert signed_path.read_bytes() == statement
                verify_transparent_statement(
                    transparent_path.read_bytes(), trust_store, statement
                )
                artifacts.append(
                    (
                        signed_path,
                        statement,
                        transparent_path,
                        transparent_path.read_bytes(),
                    )
                )
        for signed_path, signed_bytes, transparent_path, transparent_bytes in artifacts:
            assert signed_path.read_bytes() == signed_bytes
            assert transparent_path.read_bytes() == transparent_bytes
        if failure == "repeat":
            assert artifacts[0][0] != artifacts[1][0]
            assert artifacts[0][2] != artifacts[1][2]

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
        with service_error("PolicyFailed:.*Invalid issuer"):
            client.submit_signed_statement_and_wait(statement)

    def test_reject_untrusted_ca(self, fulcio_ca, client: Client, configure_service):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("PolicyFailed:.*Invalid issuer"):
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
                    issuer=sign.signing_issuer(fulcio_ca.pem, WORKFLOW),
                )
            )

    def test_reject_missing_eku(self, fulcio_ca, client: Client, configure_service):
        configure_service({"policy": fulcio_ca.registration_policy()})
        with service_error("InvalidInput:.*Failed to resolve did:x509 issuer"):
            client.submit_signed_statement_and_wait(fulcio_ca.statement(eku=False))

    @pytest.mark.parametrize("offset", [-1200, 300])
    def test_issuer_policy_does_not_require_current_certificate_validity(
        self, fulcio_ca, client: Client, configure_service, offset
    ):
        statement = fulcio_ca.statement(offset=offset)
        configure_service({"policy": fulcio_ca.registration_policy()})
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
        issuer = sign.signing_issuer(fulcio_ca.pem, WORKFLOW)
        registration = policies.DID_X509[language](issuer)
        configure_service({"policy": registration})
        client.submit_signed_statement_and_wait(action_statement(MockFulcio(fulcio_ca)))
        with service_error("PolicyFailed:.*Invalid issuer"):
            client.submit_signed_statement_and_wait(FulcioCA().statement())

    @pytest.mark.parametrize("language", ["js", "rego"])
    def test_archived_fulcio_statement_with_issuer_policy(
        self, client: Client, configure_service, trust_store, language
    ):
        payloads = Path(__file__).with_name("payloads")
        statement = (payloads / "github-fulcio-20261001.cose").read_bytes()
        provenance = json.loads((payloads / "github-fulcio-20261001.json").read_text())
        root_pem = sign.FULCIO_ROOT.read_text()
        issuer = sign.signing_issuer(root_pem, provenance["workflow"])
        configure_service({"policy": policies.DID_X509[language](issuer)})
        result = client.submit_signed_statement_and_wait(statement)
        verify_transparent_statement(result.response_bytes, trust_store, statement)
        unexpected_workflow = provenance["workflow"].replace(
            "/microsoft/scitt-ccf-ledger/", "/unexpected/repository/"
        )
        unexpected_issuer = sign.signing_issuer(root_pem, unexpected_workflow)
        configure_service({"policy": policies.DID_X509[language](unexpected_issuer)})
        with service_error("PolicyFailed:.*Invalid issuer"):
            client.submit_signed_statement_and_wait(statement)
