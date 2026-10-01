# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import base64
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

from pyscitt import crypto
from pyscitt.client import Client, ServiceError
from pyscitt.verify import StaticTrustStore, verify_transparent_statement

from . import policy

FULCIO_URL = "https://fulcio.sigstore.dev"
FULCIO_AUDIENCE = "sigstore"


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
    root_pem = policy.FULCIO_ROOT.read_text()
    root = policy.trusted_root(root_pem)
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
    if not 0 < lifetime <= policy.MAX_CERTIFICATE_LIFETIME:
        raise ValueError("Fulcio certificate is not short lived")
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise ValueError("Fulcio certificate is expired or not yet valid")
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError(
            "Fulcio returned a CA certificate instead of a signing certificate"
        )
    issuer_extension = leaf.extensions.get_extension_for_oid(
        ObjectIdentifier(policy.GITHUB_ISSUER_OID)
    ).value
    if not isinstance(
        issuer_extension, x509.UnrecognizedExtension
    ) or issuer_extension.value != policy.der_utf8(policy.GITHUB_ISSUER):
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
        issuer=policy.signing_issuer(root_pem, uris[0]),
        x5c=chain,
    )
    return crypto.sign_statement(
        signer,
        payload,
        content_type,
        cwt=True,
    )


def submit(client: Client, statement: bytes, output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    statement_path = output_dir / "signed-statement.cose"
    transparent_path = output_dir / "transparent-statement.cose"
    statement_path.write_bytes(statement)
    result = client.submit_signed_statement_and_wait(statement)
    trust_store = StaticTrustStore(cose_keys=client.get_scitt_keys())
    verify_transparent_statement(result.response_bytes, trust_store, statement)
    transparent_path.write_bytes(result.response_bytes)
    outputs = {
        "transaction-id": result.tx,
        "signed-statement": str(statement_path.resolve()),
        "transparent-statement": str(transparent_path.resolve()),
    }
    (output_dir / "submission.json").write_text(json.dumps(outputs, indent=2) + "\n")
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign a file using GitHub OIDC and submit it to a SCITT ledger"
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=os.environ.get("SCITT_WORKSPACE", Path.cwd()),
        help="Base directory for relative input and output paths",
    )
    parser.add_argument("--file", type=Path, default=os.environ.get("SCITT_FILE"))
    parser.add_argument("--ledger-url", default=os.environ.get("SCITT_LEDGER_URL"))
    parser.add_argument(
        "--content-type",
        default=os.environ.get("SCITT_CONTENT_TYPE", "application/octet-stream"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=os.environ.get("SCITT_OUTPUT_DIR", "scitt-output"),
    )
    parser.add_argument(
        "--service-ca", type=Path, default=os.environ.get("SCITT_SERVICE_CA") or None
    )
    args = parser.parse_args()
    if args.file is None or args.ledger_url is None:
        parser.error("--file and --ledger-url are required")
    try:
        https_url(args.ledger_url, "Ledger URL")
        workspace = args.workspace.resolve()
        with httpx.Client(timeout=30, follow_redirects=False) as session:
            statement = sign_payload(
                (workspace / args.file).read_bytes(),
                session,
                content_type=args.content_type,
            )
        client = Client(
            args.ledger_url,
            cacert=str(workspace / args.service_ca) if args.service_ca else None,
        )
        try:
            outputs = submit(client, statement, workspace / args.output_dir)
        finally:
            client.session.close()
        if output_file := os.environ.get("GITHUB_OUTPUT"):
            with open(output_file, "a", encoding="utf-8") as f:
                for name, value in outputs.items():
                    if "\n" in value or "\r" in value:
                        raise ValueError(
                            "Action output paths must not contain newlines"
                        )
                    f.write(f"{name}={value}\n")
        print(json.dumps(outputs, indent=2))
    except (
        OSError,
        ValueError,
        InvalidSignature,
        httpx.HTTPError,
        ServiceError,
        x509.ExtensionNotFound,
    ) as e:
        print(f"::error::{workflow_command_escape(str(e))}", file=sys.stderr)
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
