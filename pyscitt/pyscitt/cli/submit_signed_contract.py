# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
from pathlib import Path
from typing import Optional

from ..client import Client
from ..verify import StaticTrustStore, verify_receipt
from .client_arguments import add_client_arguments, create_client


def submit_signed_contract(
    client: Client,
    path: Path,
    receipt_path: Optional[Path],
    service_trust_store_path: Optional[Path],
    skip_confirmation: bool,
):
    if path.suffix != ".cose":
        raise ValueError("unsupported file extension")

    with open(path, "rb") as f:
        signed_claimset = f.read()

    if skip_confirmation:
        pending = client.submit_claim(signed_claimset, skip_confirmation=True)
        print(f"Submitted {path} as operation {pending.operation_tx}")
        print("Confirmation of submission was skipped! Claim may not be registered.")
        return

    submission = client.submit_claim(signed_claimset)
    print(f"Submitted {path} as transaction {submission.tx}")

    if receipt_path:
        with open(receipt_path, "wb") as f:
            f.write(submission.raw_receipt)
        print(f"Received {receipt_path}")

    if service_trust_store_path:
        service_trust_store = StaticTrustStore.load(service_trust_store_path)
        verify_receipt(
            signed_claimset,
            receipt=submission.receipt,
            service_trust_store=service_trust_store,
        )


def cli(fn):
    parser = fn(
        description="Submit signed claimset to a SCITT CCF Ledger and retrieve receipt"
    )
    add_client_arguments(parser, with_auth_token=True)
    parser.add_argument("path", type=Path, help="Path to signed claimset file")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--receipt", type=Path, help="Output path to receipt file")
    group.add_argument(
        "--skip-confirmation",
        action="store_true",
        help="Don't wait for confirmation or a receipt",
    )
    parser.add_argument(
        "--service-trust-store",
        type=Path,
        help="Folder containing JSON parameter files of SCITT services to trust, used to verify the claim",
    )

    def cmd(args):
        client = create_client(args)
        submit_signed_contract(
            client,
            args.path,
            args.receipt,
            args.service_trust_store,
            args.skip_confirmation,
        )

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
