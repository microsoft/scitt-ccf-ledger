# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import base64
import json
from pathlib import Path
from typing import Union

from pycose.messages import Sign1Message

from .. import crypto
from ..receipt import (
    Receipt,
    cbor_to_printable,
    decode_inclusion_proofs,
    is_receipt,
    receipt_summary,
    summarise_encoded_receipt,
)


def receipt_summaries(parsed: Sign1Message) -> list:
    """
    Summarise every receipt carried by a COSE message: each embedded receipt
    when it is a transparent statement, or the message itself when it is a
    standalone receipt.

    A signed statement which carries no receipt yields nothing.
    """
    embedded = parsed.uhdr.get(crypto.SCITTReceipts)
    if not embedded:
        return [receipt_summary(parsed)] if is_receipt(parsed) else []

    return [
        summarise_encoded_receipt(item) for item in embedded if isinstance(item, bytes)
    ]


def cose_kind(parsed: Sign1Message) -> str:
    """
    What the COSE message is, as far as SCITT is concerned.
    """
    if parsed.uhdr.get(crypto.SCITTReceipts):
        return "transparent statement"
    if is_receipt(parsed):
        return "receipt"
    return "signed statement"


def extract_metadata(parsed: Sign1Message) -> dict:
    """
    Metadata derived from a COSE message, as opposed to the headers which are
    present in the file itself. Receipts are only reported when there are any.
    """
    metadata: dict = {"kind": cose_kind(parsed)}
    summaries = receipt_summaries(parsed)
    if summaries:
        metadata["receipts"] = summaries
    return metadata


def prettyprint_receipt(receipt_path: Path):
    """
    Pretty-print a receipt which could be a standalone cose file or a transparent statement.
    """
    with open(receipt_path, "rb") as f:
        buffer = f.read()

    parsed = Sign1Message.decode(buffer)
    metadata = extract_metadata(parsed)
    unprotected = decode_inclusion_proofs(parsed.uhdr)
    output_dict: dict = {
        "extracted_metadata": metadata,
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
