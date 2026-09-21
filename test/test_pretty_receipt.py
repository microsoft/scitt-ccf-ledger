# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path

import pytest
from pycose.messages import Sign1Message

from pyscitt import crypto
from pyscitt.cli.pretty_receipt import prettyprint_receipt

GOLDEN_STATEMENT = Path(__file__).parent / "transparent_statements" / "uvm_0.2.10.cose"

EXPECTED_SUMMARY = {
    "issuer": "esrp-cts-db.confidential-ledger.azure.com",
    "registration_txid": "458.12440",
    "signature_txid": "458.12441",
    "issued_at": 1766437888,
    "issued_at_utc": "2025-12-22T21:11:28+00:00",
    "urls": {
        "receipt": "https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440",
        "transparent_statement": "https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440/statement",
    },
}


@pytest.fixture
def standalone_receipt(tmp_path: Path) -> Path:
    """The receipt embedded in the golden transparent statement, on its own."""
    statement = Sign1Message.decode(GOLDEN_STATEMENT.read_bytes())
    receipt = statement.uhdr[crypto.SCITTReceipts][0]
    path = tmp_path / "receipt.cose"
    path.write_bytes(receipt)
    return path


def test_transparent_statement_summarises_receipts():
    output = json.loads(prettyprint_receipt(GOLDEN_STATEMENT))

    assert output["receipts"] == [EXPECTED_SUMMARY]

    # The inclusion proof of the embedded receipt must be decoded rather than
    # printed as an opaque byte string, so the registration txid is visible.
    receipt = output["unprotected"]["SCITTReceipts"][0]
    leaf = receipt["unprotected"]["396"]["-1"]["-1_0"]["1"]
    assert leaf["1_1"].startswith("ce:458.12440:")


def test_standalone_receipt_summarises_itself(standalone_receipt: Path):
    output = json.loads(prettyprint_receipt(standalone_receipt))

    assert output["receipts"] == [EXPECTED_SUMMARY]
    leaf = output["unprotected"]["396"]["-1"]["-1_0"]["1"]
    assert leaf["1_1"].startswith("ce:458.12440:")
