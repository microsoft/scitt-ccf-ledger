# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from pycose.messages import Sign1Message

from ..receipt import summarise_receipt_details
from ..verify import (
    DEFAULT_AUTHORIZED_DOMAINS,
    DynamicTrustStore,
    FallbackTrustStore,
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


def build_error_result(statement: Path, error: Exception) -> dict:
    """
    Report a statement which could not be shown to be transparent in the same
    shape as a successful validation.
    """
    return {
        "statement": str(statement),
        "transparent": False,
        "error": str(error) or error.__class__.__name__,
        "receipts": [],
    }


def build_trust_store(
    service_trust_store_path: Optional[Path] = None,
    authorized_domains: Optional[List[str]] = None,
    offline: bool = False,
) -> TrustStore:
    """
    Build the trust store used for verification.

    Keys held locally are always preferred. Unless `offline` is set, keys that
    are not available locally are downloaded from the issuing service, provided
    its issuer matches one of `authorized_domains`, which defaults to
    *.confidential-ledger.azure.com.
    """
    if authorized_domains is None:
        authorized_domains = DEFAULT_AUTHORIZED_DOMAINS

    local = (
        StaticTrustStore.load(service_trust_store_path)
        if service_trust_store_path is not None
        else None
    )

    if offline:
        if local is None:
            raise ValueError(
                "--offline requires --service-trust-store to provide the service keys"
            )
        return local

    remote = DynamicTrustStore(authorized_domains=authorized_domains)
    if local is None:
        return remote
    return FallbackTrustStore(local, remote)


def validate_transparent_statement(
    statement: Path,
    service_trust_store_path: Optional[Path] = None,
    authorized_domains: Optional[List[str]] = None,
    offline: bool = False,
) -> dict:
    transparent_statment_bytes = statement.read_bytes()
    signed_statement = strip_uhdr(transparent_statment_bytes)
    service_trust_store = build_trust_store(
        service_trust_store_path, authorized_domains, offline
    )

    receipt_details = verify_transparent_statement(
        transparent_statment_bytes, service_trust_store, signed_statement
    )
    result = build_validation_result(statement, receipt_details)

    verification_key_sources = getattr(
        service_trust_store, "verification_key_sources", None
    )
    if verification_key_sources is None:
        default_source = "trust_store" if offline else "downloaded"
        verification_key_sources = [default_source] * len(result["receipts"])
    for receipt, source in zip(result["receipts"], verification_key_sources):
        receipt["verification_key_source"] = source

    return result


def format_validation_result(result: dict, output: str) -> str:
    if output == "json":
        return json.dumps(result, indent=2)

    if not result["transparent"]:
        return f"Statement is not transparent: {result['statement']}\n{result['error']}"

    lines = []
    for receipt in result["receipts"]:
        issuer = receipt["issuer"] or "unknown issuer"
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
        lines.append(
            f"  Verification key source: {receipt.get('verification_key_source')}"
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
        "--authorized-domain",
        action="append",
        dest="authorized_domains",
        metavar="DOMAIN",
        help=f"""Issuer whose keys may be downloaded during verification, e.g.
        myledger.confidential-ledger.azure.com. Wildcards are supported and the
        option may be repeated. Defaults to
        {" ".join(DEFAULT_AUTHORIZED_DOMAINS)}. Pass '*' to allow any issuer,
        which downloads keys from whichever host a receipt names.""",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="""Never download keys, only use those in --service-trust-store""",
    )
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="json",
        help="Format used to report what was verified (default: json)",
    )

    def cmd(args):
        if args.offline and args.service_trust_store is None:
            parser.error("--offline requires --service-trust-store")

        try:
            result = validate_transparent_statement(
                args.statement,
                args.service_trust_store,
                args.authorized_domains,
                args.offline,
            )
        except Exception as error:
            result = build_error_result(args.statement, error)

        if args.service_trust_store is not None and any(
            receipt.get("verification_key_source") == "downloaded"
            for receipt in result["receipts"]
        ):
            print(
                "Warning: a verification key was downloaded because it was not "
                "in the trust store; pass --offline to require local keys.",
                file=sys.stderr,
            )

        print(format_validation_result(result, args.output))
        if not result["transparent"]:
            raise SystemExit(1)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
