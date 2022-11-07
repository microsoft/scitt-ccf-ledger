# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
from pathlib import Path
from typing import Optional

from .. import crypto


def embed_receipt_in_cose(
    cose_path: Path, receipt_path: Path, out_path: Optional[Path]
):
    with open(cose_path, "rb") as f:
        cose = f.read()
    with open(receipt_path, "rb") as f:
        receipt = f.read()
    cose = crypto.embed_receipt_in_cose(cose, receipt)
    if out_path is None:
        out_path = cose_path
    with open(out_path, "wb") as f:
        f.write(cose)
    print(f"Receipt embedded: {out_path}")


def cli(fn):
    parser = fn(description="Embed a receipt into a COSE_Sign1 document")
    parser.add_argument("cose", type=Path, help="Path to COSE file")
    parser.add_argument("--receipt", required=True, type=Path, help="Path to receipt")
    parser.add_argument(
        "--out", type=Path, help="Optional output path, otherwise input file"
    )

    def cmd(args):
        embed_receipt_in_cose(args.cose, args.receipt, args.out)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
