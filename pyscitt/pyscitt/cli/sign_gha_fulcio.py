# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import base64
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping
from urllib.parse import quote

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from pycose.headers import X5chain
from pycose.messages import Sign1Message

from .. import crypto
from ..verify import verify_cose_sign1

FULCIO_URL = "https://fulcio.sigstore.dev"
FULCIO_AUDIENCE = "sigstore"
FULCIO_ROOT = Path(__file__).with_name("fulcio-root.pem")
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ISSUER_OID = "1.3.6.1.4.1.57264.1.8"
MAX_CERTIFICATE_LIFETIME = 600


def der_utf8(value: str) -> bytes:
    data = value.encode("utf-8")
    length = len(data)
    if length < 128:
        encoded_length = bytes([length])
    else:
        size = (length.bit_length() + 7) // 8
        encoded_length = bytes([128 + size]) + length.to_bytes(size, "big")
    return b"\x0c" + encoded_length + data


def trusted_root(pem: str) -> x509.Certificate:
    certificates = x509.load_pem_x509_certificates(pem.encode("ascii"))
    if len(certificates) != 1:
        raise ValueError("Fulcio root must contain exactly one trusted CA certificate")
    root = certificates[0]
    if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Fulcio root must be a CA certificate")
    try:
        root.verify_directly_issued_by(root)
    except InvalidSignature as error:
        raise ValueError(
            "The trusted Fulcio root is not correctly self-signed"
        ) from error
    return root


def signing_issuer(root_pem: str, workflow_uri: str) -> str:
    trusted_root(root_pem)
    fingerprint = crypto.get_cert_fingerprint_b64url(root_pem)
    encoded_uri = quote(workflow_uri, safe="").replace("~", "%7E")
    return (
        f"did:x509:0:sha256:{fingerprint}"
        f"::eku:1.3.6.1.5.5.7.3.3::san:uri:{encoded_uri}"
    )


def https_url(value: str, name: str) -> httpx.URL:
    url = httpx.URL(value)
    if url.scheme != "https" or not url.host or url.userinfo or url.fragment:
        raise ValueError(f"{name} must be an HTTPS URL without credentials or fragment")
    return url


def workflow_command_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def github_token(session: httpx.Client, environment: Mapping[str, str]) -> str:
    url = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    credential = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not credential:
        raise ValueError(
            "GitHub OIDC is unavailable; run in GitHub Actions with permissions: "
            "id-token: write"
        )
    response = session.get(
        https_url(url, "GitHub OIDC request URL").copy_merge_params(
            {"audience": FULCIO_AUDIENCE}
        ),
        headers={"Authorization": f"Bearer {credential}"},
        follow_redirects=False,
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get("value"), str):
        raise ValueError("GitHub OIDC response must contain a token in 'value'")
    token = data["value"]
    if not token or "\n" in token or "\r" in token:
        raise ValueError("GitHub returned an invalid OIDC token")
    print(f"::add-mask::{workflow_command_escape(token)}", flush=True)
    return token


def sign_payload(
    payload: bytes,
    session: httpx.Client,
    *,
    content_type: str = "application/octet-stream",
    environment: Mapping[str, str] = os.environ,
) -> bytes:
    root_pem = FULCIO_ROOT.read_text()
    root = trusted_root(root_pem)
    token = github_token(session, environment)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    response = session.post(
        f"{FULCIO_URL}/api/v2/signingCert",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "certificateSigningRequest": base64.b64encode(
                csr.public_bytes(serialization.Encoding.PEM)
            ).decode("ascii")
        },
        follow_redirects=False,
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Fulcio returned an invalid certificate response")
    signed = data.get("signedCertificateEmbeddedSct") or data.get(
        "signedCertificateDetachedSct"
    )
    if not isinstance(signed, dict) or not isinstance(signed.get("chain"), dict):
        raise ValueError("Fulcio response is missing its certificate chain")
    pem_chain = signed["chain"].get("certificates")
    if (
        not isinstance(pem_chain, list)
        or not pem_chain
        or not all(isinstance(pem, str) for pem in pem_chain)
    ):
        raise ValueError("Fulcio returned an empty or malformed certificate chain")
    certificates = [
        x509.load_pem_x509_certificate(pem.encode("ascii")) for pem in pem_chain
    ]
    leaf = certificates[0]
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if leaf.public_key().public_bytes(
        serialization.Encoding.DER, public_format
    ) != key.public_key().public_bytes(serialization.Encoding.DER, public_format):
        raise ValueError("Fulcio certificate does not bind the ephemeral signing key")
    now = datetime.now(UTC)
    lifetime = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds()
    if not 0 < lifetime <= MAX_CERTIFICATE_LIFETIME:
        raise ValueError("Fulcio certificate is not short lived")
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise ValueError("Fulcio certificate is expired or not yet valid")
    # RFC 5280 permits end-entity certificates without BasicConstraints.
    if any(
        isinstance(extension.value, x509.BasicConstraints) and extension.value.ca
        for extension in leaf.extensions
    ):
        raise ValueError(
            "Fulcio returned a CA certificate instead of a signing certificate"
        )
    issuer_extension = leaf.extensions.get_extension_for_oid(
        ObjectIdentifier(GITHUB_ISSUER_OID)
    ).value
    if not isinstance(
        issuer_extension, x509.UnrecognizedExtension
    ) or issuer_extension.value != der_utf8(GITHUB_ISSUER):
        raise ValueError(
            "Fulcio certificate was not issued to a GitHub Actions identity"
        )
    usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.CODE_SIGNING not in usages:
        raise ValueError("Fulcio certificate is not a code-signing certificate")
    uris = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or not uris[0].startswith("https://github.com/"):
        raise ValueError("Fulcio certificate must contain one GitHub workflow URI")
    if certificates[-1].fingerprint(hashes.SHA256()) != root.fingerprint(
        hashes.SHA256()
    ):
        certificates.append(root)
    for child, parent in zip(certificates, certificates[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except InvalidSignature as e:
            raise ValueError(
                "Fulcio returned a chain not signed by the configured authority"
            ) from e
    chain = [
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        for cert in certificates
    ]
    signer = crypto.Signer(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
        issuer=signing_issuer(root_pem, uris[0]),
        x5c=chain,
    )
    return crypto.sign_statement(
        signer,
        payload,
        content_type,
        cwt=True,
    )


def verify_statement(statement: bytes, payload: bytes) -> None:
    message = Sign1Message.decode(statement)
    if message.payload != payload:
        raise ValueError("Generated COSE payload does not match the input file")
    leaf = crypto.cert_der_to_pem(message.phdr[X5chain][0])
    verify_cose_sign1(statement, crypto.get_cert_public_key(leaf))


def sign_statement(statement_path: Path, out_path: Path, content_type: str) -> None:
    if out_path.suffix != ".cose":
        raise ValueError("--out must end with .cose")
    payload = statement_path.read_bytes()
    with httpx.Client(timeout=30, follow_redirects=False) as session:
        statement = sign_payload(payload, session, content_type=content_type)
    verify_statement(statement, payload)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(statement)
    print(f"Writing {out_path}")


def cli(fn):
    parser = fn(
        description=(
            "Sign a statement using GitHub Actions OIDC and a short-lived public "
            "Fulcio certificate. Requires permissions: id-token: write."
        )
    )
    parser.add_argument(
        "--statement", type=Path, required=True, help="Path to statement file"
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path for signed statement (.cose)",
    )
    parser.add_argument(
        "--content-type",
        default="application/octet-stream",
        help="Content type of statement (default: application/octet-stream)",
    )

    def cmd(args):
        try:
            sign_statement(args.statement, args.out, args.content_type)
        except (
            OSError,
            ValueError,
            InvalidSignature,
            httpx.HTTPError,
            x509.ExtensionNotFound,
        ) as error:
            parser.exit(1, f"Error: {error}\n")

    parser.set_defaults(func=cmd)
    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
