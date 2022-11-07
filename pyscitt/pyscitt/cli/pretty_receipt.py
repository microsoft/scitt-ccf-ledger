# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import json
from pathlib import Path

from ..receipt import Receipt


def prettyprint_receipt(receipt_path: Path):
    with open(receipt_path, "rb") as f:
        receipt = f.read()
    parsed = Receipt.decode(receipt)
    print(json.dumps(parsed.as_dict(), indent=2))


def cli(fn):
    parser = fn(description="Pretty-print a SCITT receipt")
    parser.add_argument("receipt", type=Path, help="Path to SCITT receipt file")

    def cmd(args):
        prettyprint_receipt(args.receipt)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
