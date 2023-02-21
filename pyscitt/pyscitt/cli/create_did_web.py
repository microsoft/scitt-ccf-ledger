# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .. import crypto, did
from ..did import did_web_document_url, format_did_web

DID_FILENAME = "did.json"


def write_file(path: Path, contents: str):
    print(f"Writing {path}")
    path.write_text(contents)


def create_did_web(
    base_url: str,
    out_dir: Path,
    ssh_key_path: Optional[Path],
    kty: str,
    alg: Optional[str],
):
    parsed = urlsplit(base_url)
    assert parsed.hostname
    identifier = format_did_web(
        host=parsed.hostname, port=parsed.port, path=parsed.path.lstrip("/")
    )

    did_doc_url = did_web_document_url(identifier)
    print(f"did:web document URL: {did_doc_url}")

    out_path = out_dir / DID_FILENAME
    if out_path.exists():
        return

    out_dir.mkdir(parents=True, exist_ok=True)

    if ssh_key_path:
        ssh_key = ssh_key_path.read_text()
        public_key_pem = crypto.ssh_public_key_to_pem(ssh_key)
    else:
        public_key_pem_path = out_dir / "key_pub.pem"
        private_key_pem_path = out_dir / "key.pem"
        if not public_key_pem_path.exists():
            private_key_pem, public_key_pem = crypto.generate_keypair(kty)
            write_file(private_key_pem_path, private_key_pem)
            write_file(public_key_pem_path, public_key_pem)
        else:
            public_key_pem = public_key_pem_path.read_text()

    method = did.create_assertion_method(
        did=identifier, public_key=public_key_pem, alg=alg
    )
    doc = did.create_document(did=identifier, assertion_methods=[method])
    write_file(out_path, json.dumps(doc, indent=2))


def cli(fn):
    parser = fn(description="Create a DID document and keys for a did:web identity")
    parser.add_argument("--url", required=True, help="Base URL")
    parser.add_argument(
        "--ssh-key",
        type=Path,
        help="Path to existing SSH public key instead of generating a new key pair",
    )
    parser.add_argument("--kty", choices=["ec", "rsa"], default="ec", help="Key type")
    parser.add_argument(
        "--alg", help="Signing algorithm the key is intended to be used with."
    )
    parser.add_argument(
        "--out-dir", required=True, type=Path, help="Path to store output files"
    )

    def cmd(args):
        create_did_web(args.url, args.out_dir, args.ssh_key, args.kty, args.alg)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
