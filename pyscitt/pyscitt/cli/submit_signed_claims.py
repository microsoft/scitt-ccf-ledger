# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
from pathlib import Path
from typing import Optional

from ..client import Client
from .client_arguments import add_client_arguments, create_client


def submit_signed_statement(
    client: Client,
    path: Path,
    receipt_path: Optional[Path],
    skip_confirmation: bool,
):
    if path.suffix != ".cose":
        raise ValueError("unsupported file extension, must end with .cose")

    with open(path, "rb") as f:
        signed_statement = f.read()

    if skip_confirmation:
        pending = client.submit_signed_statement(signed_statement)
        print(f"Submitted {path} as operation {pending.operation_tx}")
        print(
            """Confirmation of submission was skipped, the signed
              statement may not be registered on the ledger. 
              A transparent statement will not be downloaded nor saved."""
        )
        return

    submission = client.register_signed_statement(signed_statement)
    print(f"Submitted {path} as transaction {submission.tx}")

    if receipt_path:
        with open(receipt_path, "wb") as f:
            f.write(submission.response_bytes)
        print(f"Received {receipt_path}")


def cli(fn):
    parser = fn(
        description="Submit signed statement (COSE) to a SCITT CCF Ledger and retrieve transparent statement"
    )
    add_client_arguments(parser, with_auth_token=True)
    parser.add_argument("path", type=Path, help="Path to signed statement file (COSE)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--transparent-statement", type=Path, help="Output path to receipt file"
    )
    group.add_argument(
        "--skip-confirmation",
        action="store_true",
        help="Don't wait for confirmation or the transparent statement",
    )

    def cmd(args):
        client = create_client(args)
        submit_signed_statement(
            client,
            args.path,
            args.transparent_statement,
            args.skip_confirmation,
        )

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
