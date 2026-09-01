# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pycose.messages import Sign1Message

from ..verify import (
    DynamicTrustStore,
    StaticTrustStore,
    TrustStore,
    verify_transparent_statement,
)


def strip_uhdr(cose: bytes) -> bytes:
    """
    Strip the uhdr from a COSE message.
    """
    msg = Sign1Message.decode(cose)
    msg.uhdr = {}
    return msg.encode(tag=True, sign=False)


def validate_transparent_statement(
    statement: Path,
    service_trust_store_path: Optional[Path] = None,
    service_key: Optional[Path] = None,
):
    transparent_statment_bytes = statement.read_bytes()
    signed_statement = strip_uhdr(transparent_statment_bytes)

    if service_trust_store_path is not None and service_key is not None:
        raise ValueError("service trust store and service key are mutually exclusive")

    service_trust_store: TrustStore
    if service_key is not None:
        key = load_pem_public_key(service_key.read_bytes())
        service_trust_store = StaticTrustStore(key=key)
    elif service_trust_store_path is not None:
        service_trust_store = StaticTrustStore.load(service_trust_store_path)
    else:
        service_trust_store = DynamicTrustStore()

    receipt_details = verify_transparent_statement(
        transparent_statment_bytes, service_trust_store, signed_statement
    )
    for detail in receipt_details:
        issuer = detail.get("iss")
        iat = detail.get("iat")
        sigtxid = detail["sigtxid"]
        regtxid = detail["regtxid"]
        timestamp = (
            datetime.fromtimestamp(iat, tz=timezone.utc).isoformat()
            if iat
            else "unknown time"
        )
        if issuer:
            url = f"https://{issuer}/entries/{regtxid}"
            print(
                f"Verified receipt from issuer {issuer}, registered at {regtxid}, signed at {sigtxid} ({timestamp}): {url}"
            )
    print(f"Statement is transparent: {statement}")


def cli(fn):
    parser = fn(description="Validate a Transparent Statement")
    parser.add_argument("statement", type=Path, help="Path to transparent statement")
    trust_options = parser.add_mutually_exclusive_group()
    trust_options.add_argument(
        "--service-trust-store",
        type=Path,
        help="""Optional folder containing JSON parameter files of SCITT services to trust""",
    )
    trust_options.add_argument(
        "--service-key",
        type=Path,
        help="Trusted PEM service public key",
    )

    def cmd(args):
        validate_transparent_statement(
            args.statement,
            args.service_trust_store,
            args.service_key,
        )

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
