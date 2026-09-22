# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path

import pytest
from pycose.messages import Sign1Message

from pyscitt import crypto
from pyscitt.cli.pretty_receipt import prettyprint_receipt
from pyscitt.receipt import entry_urls, issuer_host

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

    assert output["extracted_metadata"]["kind"] == "transparent_statement"
    assert output["extracted_metadata"]["receipts"] == [EXPECTED_SUMMARY]

    # The inclusion proof of the embedded receipt must be decoded rather than
    # printed as an opaque byte string, so the registration txid is visible.
    receipt = output["unprotected"]["SCITTReceipts"][0]
    leaf = receipt["unprotected"]["396"]["-1"]["-1_0"]["1"]
    assert leaf["1_1"].startswith("ce:458.12440:")


def test_standalone_receipt_summarises_itself(standalone_receipt: Path):
    output = json.loads(prettyprint_receipt(standalone_receipt))

    assert output["extracted_metadata"]["kind"] == "receipt"
    assert output["extracted_metadata"]["receipts"] == [EXPECTED_SUMMARY]
    leaf = output["unprotected"]["396"]["-1"]["-1_0"]["1"]
    assert leaf["1_1"].startswith("ce:458.12440:")


def test_signed_statement_has_no_receipts():
    """A statement which was never registered carries no receipt to report."""
    signed_statement = (
        Path(__file__).parent / "payloads" / "cosesign1tool-scitt-a3be7e5.cose"
    )

    output = json.loads(prettyprint_receipt(signed_statement))

    assert output["extracted_metadata"] == {"kind": "signed_statement"}
    assert "396" not in output["unprotected"]
    # The headers of the statement itself are still printed.
    assert output["protected"]["CWTClaims"]["sub"] == "unknown.intent"


def test_legacy_ccf_receipt_is_summarised():
    """Legacy receipts are untagged and are not COSE_Sign1, but still parse."""
    statement = Path(__file__).parent / "payloads" / "cts-hashv-cwtclaims-b64url.cose"

    output = json.loads(prettyprint_receipt(statement))

    assert output["extracted_metadata"]["receipts"] == [
        {
            "issuer": "did:web:cts-poc.confidential-ledger.azure.com",
            "registration_txid": "225.3563",
            "signature_txid": None,
            "issued_at": 1724186281,
            "issued_at_utc": "2024-08-20T20:38:01+00:00",
            "urls": {
                "receipt": "https://cts-poc.confidential-ledger.azure.com/entries/225.3563",
                "transparent_statement": "https://cts-poc.confidential-ledger.azure.com/entries/225.3563/statement",
            },
        }
    ]

    # The receipt contents are printed rather than reported as unparseable.
    receipt = output["unprotected"]["SCITTReceipts"][0]
    assert "error" not in receipt
    assert receipt["protected"]["tree_alg"] == "CCF"


@pytest.mark.parametrize(
    "issuer,expected",
    [
        (
            "ledger.confidential-ledger.azure.com",
            "ledger.confidential-ledger.azure.com",
        ),
        (
            "did:web:cts-poc.confidential-ledger.azure.com",
            "cts-poc.confidential-ledger.azure.com",
        ),
        ("did:web:example.com:path:to:service", "example.com"),
        ("did:web:example.com%3A8443", "example.com:8443"),
        # did:x509 does not address a service, so no URL can be built.
        ("did:x509:0:sha256:abc::subject:CN:test", None),
        (None, None),
    ],
)
def test_issuer_host(issuer, expected):
    assert issuer_host(issuer) == expected
    urls = entry_urls(issuer, "1.2")
    assert urls["receipt"] == (f"https://{expected}/entries/1.2" if expected else None)


@pytest.mark.parametrize(
    "issuer",
    [
        "evil.com/x.confidential-ledger.azure.com",
        "evil.com#.confidential-ledger.azure.com",
        "user@evil.com",
        "https://example.com",
        "did:web:evil.com%2Fpath",
    ],
)
def test_no_url_for_issuers_which_are_not_hostnames(issuer):
    """A URL is never built from an issuer which could address another host."""
    assert issuer_host(issuer) is None
    assert entry_urls(issuer, "1.2") == {"receipt": None, "transparent_statement": None}


@pytest.mark.parametrize("regtxid", ["", None, "1.2/../../evil", "not-a-txid"])
def test_no_url_for_invalid_registration_txid(regtxid):
    assert entry_urls("ledger.example.com", regtxid) == {
        "receipt": None,
        "transparent_statement": None,
    }
