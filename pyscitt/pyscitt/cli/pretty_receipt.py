# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import datetime
import json
from pathlib import Path
from typing import Any
import base64

import cbor2
from cbor2 import CBORError
from pycose.messages import Sign1Message
from ..receipt import Receipt, hdr_as_dict, display_cbor_val
from ..crypto import COSE_HEADER_PARAM_SCITT_RECEIPTS


def cbor_as_dict(cbor_obj: Any) -> dict:

    # if is a list, return a list of pretty-printed items
    if isinstance(cbor_obj, list):
        return [cbor_as_dict(item) for item in cbor_obj]

    # if is dict, return a dict of pretty-printed items
    if isinstance(cbor_obj, dict):
        return {display_cbor_val(k): cbor_as_dict(v) for k, v in cbor_obj.items()}
    
    # attempt to decode as a list
    if type(cbor_obj) is bytes:
        try:
            decoded = cbor2.loads(cbor_obj)
            print(f"Decoded {decoded} from {cbor_obj.hex()}")
            return cbor_as_dict(decoded)
        except (CBORError, UnicodeDecodeError):
            print(f"Error decoding {cbor_obj.hex()}")
            pass

    # otherwise return as is
    return display_cbor_val(cbor_obj)


def prettyprint_receipt(receipt_path: Path):
    with open(receipt_path, "rb") as f:
        receipt = f.read()

    cbor_obj = cbor2.loads(receipt)
    if hasattr(cbor_obj, "tag"):
        assert cbor_obj.tag == 18  # COSE_Sign1
        parsed = Sign1Message.from_cose_obj(cbor_obj.value, True)
        uhdr = cbor_as_dict(parsed.uhdr)
        # 394 header contains receipts so decode them in a pretty way
        if COSE_HEADER_PARAM_SCITT_RECEIPTS in parsed.uhdr:
            uhdr[COSE_HEADER_PARAM_SCITT_RECEIPTS] = []
            # for item in parsed.uhdr[COSE_HEADER_PARAM_SCITT_RECEIPTS]:
            #     if type(item) is bytes:
            #         header_receipt = Receipt.decode(item)
            #     else:
            #         header_receipt = Receipt.from_cose_obj(item)
            #     print(f"Item: {item} {type(item)}")
            #     uhdr[COSE_HEADER_PARAM_SCITT_RECEIPTS].append(header_receipt.as_dict())
        output_dict = {
            "protected": hdr_as_dict(parsed.phdr), 
            "unprotected": uhdr,
            "payload": base64.b64encode(parsed.payload).decode("ascii"),
        }
    else:
        parsed = Receipt.decode(receipt)
        output_dict = parsed.as_dict()

    print(output_dict)

    print(json.dumps(output_dict, indent=2))


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
