# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import base64
from pathlib import Path
from typing import Optional

from pycose.messages import Sign1Message


def split_payload(cose_path: Path, output: Optional[Path] = None):
    """Extract the payload from a COSE file and write it to a file or print it to stdout."""
    cose = cose_path.read_bytes()
    decoded = Sign1Message.decode(cose)
    if not decoded.payload:
        raise ValueError("COSE object does not contain a payload")
    if not output:
        print(base64.b64encode(decoded.payload).decode("ascii"))
    else:
        output.write_bytes(decoded.payload)


def cli(fn):
    parser = fn(description="Extract payload from a COSE file")
    parser.add_argument("cose", type=Path, help="Path to a COSE file")
    parser.add_argument(
        "--out",
        type=Path,
        help="Output path, e.g. payload.txt. If not provided, the base64 encoded payload will be printed to stdout.",
    )

    def cmd(args):
        split_payload(args.cose, args.out)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
