# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import base64
import json
from pathlib import Path
from typing import Union

import cbor2
from pycose.messages import Sign1Message

from ..receipt import Receipt, cbor_as_dict


def prettyprint_receipt(receipt_path: Path):
    """Pretty-print a SCITT receipt file and detect both embedded COSE_Sign1 and standalone receipt formats"""
    with open(receipt_path, "rb") as f:
        receipt = f.read()

    parsed: Union[Sign1Message, Receipt]
    cbor_obj = cbor2.loads(receipt)
    if hasattr(cbor_obj, "tag"):
        assert cbor_obj.tag == 18  # COSE_Sign1
        parsed = Sign1Message.from_cose_obj(cbor_obj.value, True)
        output_dict = {
            "protected": cbor_as_dict(parsed.phdr),
            "unprotected": cbor_as_dict(parsed.uhdr),
            "payload": (
                base64.b64encode(parsed.payload).decode("ascii")
                if parsed.payload
                else None
            ),
        }
    else:
        parsed = Receipt.decode(receipt)
        output_dict = parsed.as_dict()

    print(json.dumps(output_dict, indent=2))


def cli(fn):
    parser = fn(description="Pretty-print a SCITT receipt")
    parser.add_argument(
        "receipt", type=Path, help="Path to SCITT receipt file (embedded or standalone)"
    )

    def cmd(args):
        prettyprint_receipt(args.receipt)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
