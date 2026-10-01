# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import sys
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from pycose.headers import X5chain
from pycose.messages import Sign1Message

from pyscitt import crypto
from pyscitt.verify import verify_cose_sign1

from . import sign


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Probe live GitHub OIDC/Fulcio signing without a ledger"
    )
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        payload = args.file.read_bytes()
        with httpx.Client(timeout=30, follow_redirects=False) as session:
            statement = sign.sign_payload(
                payload, session, content_type="application/json"
            )
        message = Sign1Message.decode(statement)
        if message.payload != payload:
            raise ValueError("Generated COSE payload does not match the input file")
        leaf = crypto.cert_der_to_pem(message.phdr[X5chain][0])
        verify_cose_sign1(statement, crypto.get_cert_public_key(leaf))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(statement)
        print(
            f"Created and verified Fulcio-backed COSE signature: {len(statement)} bytes"
        )
    except (
        OSError,
        ValueError,
        InvalidSignature,
        httpx.HTTPError,
        x509.ExtensionNotFound,
    ) as e:
        print(f"::error::{sign.workflow_command_escape(str(e))}", file=sys.stderr)
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
