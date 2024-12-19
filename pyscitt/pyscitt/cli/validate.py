# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
from pathlib import Path
from typing import Optional

from pycose.messages import Sign1Message

from ..verify import StaticTrustStore, verify_transparent_statement


def strip_uhdr(cose: bytes) -> bytes:
    """
    Strip the uhdr from a COSE message.
    """
    msg = Sign1Message.decode(cose)
    msg.uhdr = {}
    return msg.encode(tag=True, sign=False)


def validate_transparent_statement(
    statement: Path,
    service_trust_store_path: Path,
):
    transparent_statment_bytes = statement.read_bytes()
    signed_statement = strip_uhdr(transparent_statment_bytes)
    service_trust_store = StaticTrustStore.load(service_trust_store_path)

    verify_transparent_statement(
        transparent_statment_bytes, service_trust_store, signed_statement
    )
    print(f"Statment is transparent: {statement}")


def cli(fn):
    parser = fn(description="Validate a Transparent Statement")
    parser.add_argument("statement", type=Path, help="Path to transparent statement")
    parser.add_argument(
        "--service-trust-store",
        type=Path,
        help="""Optional folder containing JSON parameter files of SCITT services to trust""",
    )

    def cmd(args):
        validate_transparent_statement(
            args.statement,
            args.service_trust_store,
        )

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
