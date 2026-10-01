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
MAX_CERTIFICATE_LIFETIME = 600
FULCIO_OIDS = {
    "issuer": "1.3.6.1.4.1.57264.1.8",
    "workflow": "1.3.6.1.4.1.57264.1.9",
    "workflow_digest": "1.3.6.1.4.1.57264.1.10",
    "runner": "1.3.6.1.4.1.57264.1.11",
    "repository": "1.3.6.1.4.1.57264.1.12",
    "ref": "1.3.6.1.4.1.57264.1.14",
    "repository_id": "1.3.6.1.4.1.57264.1.15",
    "owner_id": "1.3.6.1.4.1.57264.1.17",
    "event": "1.3.6.1.4.1.57264.1.20",
}


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
        raise ValueError("fulcio-root must contain exactly one trusted CA certificate")
    root = certificates[0]
    if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("fulcio-root must be a CA certificate")
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
    repository: str,
    repository_id: str,
    owner_id: str,
    workflow: str,
    ref: str = "refs/heads/main",
    event: str = "workflow_dispatch",
    runner: str = "github-hosted",
    workflow_digest: str | None = None,
) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("repository must be an owner/repository name")
    for name, value in [("repository-id", repository_id), ("owner-id", owner_id)]:
        if not re.fullmatch(r"[1-9][0-9]*", value):
            raise ValueError(f"{name} must be a positive immutable GitHub ID")
    if not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
        r"\.github/workflows/[^?#\s]+@[^?#\s]+",
        workflow,
    ):
        raise ValueError("workflow must be an exact GitHub workflow URI with @ref")
    if not ref.startswith(("refs/heads/", "refs/tags/")):
        raise ValueError("ref must be a fully qualified branch or tag reference")
    if not event or runner not in ("github-hosted", "self-hosted"):
        raise ValueError("event must be set and runner must identify a GitHub runner")
    if workflow_digest is not None and not re.fullmatch(
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})", workflow_digest
    ):
        raise ValueError("workflow-digest must be a full lowercase Git commit digest")

    root = trusted_root(root_pem)
    root_pem = root.public_bytes(serialization.Encoding.PEM).decode("ascii")
    expected = {
        FULCIO_OIDS[name]: der_utf8(value).hex()
        for name, value in {
            "issuer": GITHUB_ISSUER,
            "workflow": workflow,
            "runner": runner,
            "repository": f"https://github.com/{repository}",
            "ref": ref,
            "repository_id": repository_id,
            "owner_id": owner_id,
            "event": event,
        }.items()
    }
    if workflow_digest is not None:
        expected[FULCIO_OIDS["workflow_digest"]] = der_utf8(workflow_digest).hex()
    issuer = signing_issuer(root_pem, workflow)
    script = f"""
const issuer = {json.dumps(issuer)};
const root = {json.dumps(root_pem)};
const expected = {json.dumps(expected)};

export function apply(phdr) {{
    if (phdr.cwt.iss !== issuer) {{
        return "Unexpected signing authority or workflow";
    }}
    if (!phdr.x509 || !phdr.x509.extensions) {{
        return "Missing authenticated certificate metadata";
    }}
    for (const [oid, value] of Object.entries(expected)) {{
        const actual = phdr.x509.extensions[oid];
        if (!Array.isArray(actual) || actual.length !== 1 || actual[0] !== value) {{
            return "Unexpected GitHub identity claim: " + oid;
        }}
    }}
    if (phdr.x509.validitySeconds <= 0 ||
        phdr.x509.validitySeconds > {MAX_CERTIFICATE_LIFETIME}) {{
        return "Signing certificate is not short lived";
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
    parser.add_argument("--fulcio-root", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--ref", default="refs/heads/main")
    parser.add_argument("--event", default="workflow_dispatch")
    parser.add_argument("--runner", default="github-hosted")
    parser.add_argument("--workflow-digest")
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
        args.fulcio_root.read_text(),
        repository=args.repository,
        repository_id=args.repository_id,
        owner_id=args.owner_id,
        workflow=args.workflow,
        ref=args.ref,
        event=args.event,
        runner=args.runner,
        workflow_digest=args.workflow_digest,
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
