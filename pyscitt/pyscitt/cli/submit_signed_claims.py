# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
from pathlib import Path
from typing import Optional

from ..client import Client, ReceiptType
from .client_arguments import add_client_arguments, create_client


def submit_signed_claimset(
    client: Client,
    path: Path,
    receipt_path: Optional[Path],
    receipt_type: str,
    skip_confirmation: bool,
):
    if path.suffix != ".cose":
        raise ValueError("unsupported file extension, must end with .cose")

    if receipt_type == ReceiptType.RAW.value:
        r_type = ReceiptType.RAW
    elif receipt_type == ReceiptType.EMBEDDED.value:
        r_type = ReceiptType.EMBEDDED
    else:
        raise ValueError(f"unsupported receipt type {receipt_type}")

    with open(path, "rb") as f:
        signed_claimset = f.read()

    with open(path, "rb") as f:
        signed_claimset = f.read()

    if skip_confirmation:
        pending = client.submit_claim(signed_claimset)
        print(f"Submitted {path} as operation {pending.operation_tx}")
        print(
            """Confirmation of submission was skipped!
              There is a small chance the claim may not be registered. 
              Receipt will not be downloaded and saved."""
        )
        return

    submission = client.submit_claim_and_confirm(signed_claimset, receipt_type=r_type)
    print(f"Submitted {path} as transaction {submission.tx}")

    if receipt_path:
        with open(receipt_path, "wb") as f:
            f.write(submission.receipt_bytes)
        print(f"Received {receipt_path}")


def cli(fn):
    parser = fn(
        description="Submit signed claimset (COSE) to a SCITT CCF Ledger and retrieve receipt"
    )
    add_client_arguments(parser, with_auth_token=True)
    parser.add_argument("path", type=Path, help="Path to signed claimset file (COSE)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--receipt", type=Path, help="Output path to receipt file")
    group.add_argument(
        "--skip-confirmation",
        action="store_true",
        help="Don't wait for confirmation or a receipt",
    )
    parser.add_argument(
        "--receipt-type",
        choices=[e.value for e in ReceiptType],
        default=ReceiptType.RAW.value,  # default to raw for backwards compatibility
        help="""
        Downloads the receipt of a given type where raw means a countersignature (CBOR) binary 
        and embedded means the original claimset (COSE) with the raw receipt added to the unprotected header
        """,
    )

    def cmd(args):
        client = create_client(args)
        submit_signed_claimset(
            client,
            args.path,
            args.receipt,
            args.receipt_type,
            args.skip_confirmation,
        )

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
