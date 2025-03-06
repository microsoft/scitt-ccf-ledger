# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import base64
import json
from pathlib import Path
from typing import Union

import cbor2
from pycose.messages import Sign1Message

from ..receipt import Receipt, cbor_to_printable


def prettyprint_receipt(receipt_path: Path):
    """
    Pretty-print a receipt which could be a standalone cose file or a transparent statement.
    """
    with open(receipt_path, "rb") as f:
        buffer = f.read()

    parsed = Sign1Message.decode(buffer)
    unprotected = parsed.uhdr
    if 396 in unprotected:
        inclusion_vdps = unprotected[396][-1]
        unprotected[396][-1] = [cbor2.loads(vdp) for vdp in inclusion_vdps]
    output_dict = {
        "protected": cbor_to_printable(parsed.phdr),
        "unprotected": cbor_to_printable(unprotected),
        "payload": (
            base64.b64encode(parsed.payload).decode("ascii") if parsed.payload else None
        ),
    }

    fallback_serialization = lambda o: f"<<non-serializable: {type(o).__qualname__}>>"
    return json.dumps(output_dict, default=fallback_serialization, indent=2)


def cli(fn):
    parser = fn(description=prettyprint_receipt.__doc__)
    parser.add_argument("receipt", type=Path, help="Path to COSE receipt file")

    def cmd(args):
        print(prettyprint_receipt(args.receipt))

    parser.set_defaults(func=cmd)
    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
