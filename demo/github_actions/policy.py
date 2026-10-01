# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
import re
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from pyscitt import crypto

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ISSUER_OID = "1.3.6.1.4.1.57264.1.8"
MAX_CERTIFICATE_LIFETIME = 600
FULCIO_ROOT = Path(__file__).with_name("fulcio-root.pem")


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
    except InvalidSignature as e:
        raise ValueError(
            "The configured trusted root is not correctly self-signed"
        ) from e
    return root


def signing_issuer(root_pem: str, workflow_uri: str) -> str:
    trusted_root(root_pem)
    fingerprint = crypto.get_cert_fingerprint_b64url(root_pem)
    encoded_uri = quote(workflow_uri, safe="").replace("~", "%7E")
    return (
        f"did:x509:0:sha256:{fingerprint}"
        f"::eku:1.3.6.1.5.5.7.3.3::san:uri:{encoded_uri}"
    )


def registration_policy(
    root_pem: str,
    *,
    workflow: str,
) -> dict:
    if not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
        r"\.github/workflows/[^?#\s]+@[^?#\s]+",
        workflow,
    ):
        raise ValueError("workflow must be an exact GitHub workflow URI with @ref")
    root = trusted_root(root_pem)
    root_pem = root.public_bytes(serialization.Encoding.PEM).decode("ascii")
    issuer = signing_issuer(root_pem, workflow)
    script = f"""
const issuer = {json.dumps(issuer)};
const root = {json.dumps(root_pem)};

export function apply(phdr) {{
    if (phdr.cwt.iss !== issuer) {{
        return "Unexpected signing authority or workflow";
    }}
    if (!Array.isArray(phdr.x5chain) || phdr.x5chain.length < 2 ||
        !ccf.crypto.isValidX509CertChain(phdr.x5chain.join("\\n"), root)) {{
        return "Signing certificate is expired, not yet valid, or untrusted";
    }}
    return true;
}}
"""
    return {"acceptedAlgorithms": ["ES256"], "policyScript": script}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a ledger registration policy for GitHub keyless signing"
    )
    parser.add_argument("--workflow", required=True)
    parser.add_argument(
        "--configuration",
        type=Path,
        help="Existing service configuration whose other settings should be preserved",
    )
    parser.add_argument(
        "--allow-unauthenticated",
        action="store_true",
        help="Explicitly disable API authentication for the demo; signing policy still applies",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    policy = registration_policy(
        FULCIO_ROOT.read_text(),
        workflow=args.workflow,
    )
    configuration = (
        json.loads(args.configuration.read_text())
        if args.configuration
        else {"authentication": {"allowUnauthenticated": False}}
    )
    if not isinstance(configuration, dict):
        parser.error("--configuration must contain a JSON configuration object")
    configuration["policy"] = policy
    if args.allow_unauthenticated:
        configuration["authentication"] = {"allowUnauthenticated": True}
    args.out.write_text(json.dumps(configuration, indent=2) + "\n")


if __name__ == "__main__":
    main()
