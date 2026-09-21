# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import json
from pathlib import Path
from typing import Optional

from pycose.messages import Sign1Message

from ..receipt import summarise_receipt_details
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


def build_validation_result(statement: Path, receipt_details: list) -> dict:
    """
    Build a structured description of what was verified in a transparent statement.
    """
    return {
        "statement": str(statement),
        "transparent": True,
        "receipts": [summarise_receipt_details(detail) for detail in receipt_details],
    }


def validate_transparent_statement(
    statement: Path,
    service_trust_store_path: Optional[Path] = None,
) -> dict:
    transparent_statment_bytes = statement.read_bytes()
    signed_statement = strip_uhdr(transparent_statment_bytes)
    service_trust_store: TrustStore
    if service_trust_store_path is not None:
        service_trust_store = StaticTrustStore.load(service_trust_store_path)
    else:
        service_trust_store = DynamicTrustStore()

    receipt_details = verify_transparent_statement(
        transparent_statment_bytes, service_trust_store, signed_statement
    )
    return build_validation_result(statement, receipt_details)


def format_validation_result(result: dict, output: str) -> str:
    if output == "json":
        return json.dumps(result, indent=2)

    lines = []
    for receipt in result["receipts"]:
        issuer = receipt["issuer"]
        if not issuer:
            continue
        timestamp = receipt["issued_at_utc"] or "unknown time"
        lines.append(
            f"Verified receipt from issuer {issuer}, "
            f"registered at {receipt['registration_txid']}, "
            f"signed at {receipt['signature_txid']} ({timestamp})"
        )
        lines.append(f"  Receipt URL: {receipt['urls']['receipt']}")
        lines.append(
            f"  Transparent statement URL: {receipt['urls']['transparent_statement']}"
        )
    lines.append(f"Statement is transparent: {result['statement']}")
    return "\n".join(lines)


def cli(fn):
    parser = fn(description="Validate a Transparent Statement")
    parser.add_argument("statement", type=Path, help="Path to transparent statement")
    parser.add_argument(
        "--service-trust-store",
        type=Path,
        help="""Optional folder containing JSON parameter files of SCITT services to trust""",
    )
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="json",
        help="Format used to report what was verified (default: json)",
    )

    def cmd(args):
        result = validate_transparent_statement(
            args.statement,
            args.service_trust_store,
        )
        print(format_validation_result(result, args.output))

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
