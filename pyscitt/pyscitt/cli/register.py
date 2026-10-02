# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
from pathlib import Path
from typing import Optional

from ..client import Client
from ..verify import StaticTrustStore, verify_transparent_statement
from .client_arguments import add_client_arguments, create_client


def register_signed_statement(
    client: Client,
    path: Path,
    transparent_statement_path: Optional[Path],
    skip_confirmation: bool,
    wait_for_commit: bool,
    verify: bool = False,
    output: str = "text",
):
    if verify and skip_confirmation:
        raise ValueError("--verify cannot be used with --skip-confirmation")
    if path.suffix != ".cose":
        raise ValueError("unsupported file extension, must end with .cose")

    with open(path, "rb") as f:
        signed_statement = f.read()

    if skip_confirmation:
        pending = client.submit_signed_statement(signed_statement)
        if output == "json":
            print(
                json.dumps(
                    {
                        "operation-id": pending.operation_tx,
                        "signed-statement": str(path.resolve()),
                    },
                    indent=2,
                )
            )
        else:
            print(f"Submitted {path} as operation {pending.operation_tx}")
            print("""Confirmation of submission was skipped, the signed
                  statement may not be registered on the ledger.
                  A transparent statement will not be downloaded nor saved.""")
        return

    if wait_for_commit:
        submission = client.submit_signed_statement_wait_for_commit(signed_statement)
    else:
        submission = client.submit_signed_statement_and_wait(signed_statement)

    response_bytes = submission.response_bytes
    if verify:
        if wait_for_commit:
            response_bytes = client.get_transparent_statement(submission.tx)
        trust_store = StaticTrustStore(cose_keys=client.get_scitt_keys())
        verify_transparent_statement(response_bytes, trust_store, signed_statement)

    result = {
        "transaction-id": submission.tx,
        "signed-statement": str(path.resolve()),
    }

    if transparent_statement_path:
        transparent_statement_path.write_bytes(response_bytes)
        result["transparent-statement"] = str(transparent_statement_path.resolve())

    if output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Registered {path} as transaction {submission.tx}")
        if transparent_statement_path:
            print(f"Received {transparent_statement_path}")


def cli(fn):
    parser = fn(
        description="Register signed statement (COSE) to a SCITT CCF Ledger and retrieve transparent statement"
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
    parser.add_argument(
        "--wait-for-commit",
        action="store_true",
        help="Use synchronous flow: block until commit and return receipt directly",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Fetch the transparent statement and verify its receipt using service keys from the configured TLS connection before saving it",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Format used to report the submission (default: text)",
    )

    def cmd(args):
        if args.verify and args.skip_confirmation:
            parser.error("--verify cannot be used with --skip-confirmation")
        client = create_client(args)
        try:
            register_signed_statement(
                client,
                args.path,
                args.transparent_statement,
                args.skip_confirmation,
                args.wait_for_commit,
                args.verify,
                args.output,
            )
        finally:
            client.session.close()

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
