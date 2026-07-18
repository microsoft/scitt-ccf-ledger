# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import copy
import hashlib
from pathlib import Path
from unittest.mock import patch

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from pyscitt.cli.validate import strip_uhdr, validate_transparent_statement
from pyscitt.verify import (
    COSE_HEADER_PARAM_VDS,
    StaticTrustStore,
    verify_receipt,
    verify_transparent_statement,
)

# The statement, receipt, and log key were published by ietf-wg-scitt/examples
# at commit 727ee03d86fa2c2ca8c534584b870235a1b252df. The transparent statement
# is derived by embedding that receipt at header label 394.
VECTOR_DIR = (
    Path(__file__).parent / "test_vectors" / "scitt-cose" / "v1" / "valid-es256"
)
STATEMENT = VECTOR_DIR / "statement.cose"
RECEIPT = VECTOR_DIR / "receipt.cose"
TRANSPARENT_STATEMENT = VECTOR_DIR / "transparent-statement.cose"
LOG_KEY = VECTOR_DIR / "log-key.pub"


def test_rfc9942_vectors_are_pinned():
    expected = {
        "statement.cose": "3ffa392b06d19b1532464da32e36aa7e2c8b555e0dda3e18154a481bfa2679c7",
        "receipt.cose": "d4b7d3ad1c6c486bc8550e937699637ea6c4586e215833fd0d874c6fa814c486",
        "log-key.pub": "ec7f30fff175a19956ac74c86624d0f394cf7d8cbc06d5d083c26d9f99bd43e6",
        "transparent-statement.cose": "87a17467e4d1051e916716eed892abaade30b0536c297e3c5e6aff011d32fad4",
    }
    assert {
        name: hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest()
        for name in expected
    } == expected


def test_verify_rfc9942_transparent_statement():
    transparent_statement = TRANSPARENT_STATEMENT.read_bytes()
    signed_statement = strip_uhdr(transparent_statement)
    decoded = cbor2.loads(transparent_statement)

    assert decoded.value[1] == {394: [RECEIPT.read_bytes()]}
    assert signed_statement == STATEMENT.read_bytes()

    trust_store = StaticTrustStore(key=load_pem_public_key(LOG_KEY.read_bytes()))
    assert verify_transparent_statement(
        transparent_statement, trust_store, signed_statement
    ) == [{"iss": None, "iat": None, "sigtxid": None, "regtxid": None}]


def test_validate_rfc9942_transparent_statement(capsys):
    validate_transparent_statement(
        TRANSPARENT_STATEMENT,
        service_key=LOG_KEY,
    )
    assert capsys.readouterr().out.strip() == (
        f"Statement is transparent: {TRANSPARENT_STATEMENT}"
    )


def _receipt_parts():
    return copy.deepcopy(cbor2.loads(RECEIPT.read_bytes()).value)


def _encode_receipt(parts):
    return cbor2.dumps(cbor2.CBORTag(18, parts))


def _set_vds(parts, vds):
    protected = cbor2.loads(parts[0])
    if vds is None:
        del protected[COSE_HEADER_PARAM_VDS]
    else:
        protected[COSE_HEADER_PARAM_VDS] = vds
    parts[0] = cbor2.dumps(protected)


@patch("pyscitt.verify.ccf.cose.verify_receipt")
def test_ccf_dispatch_requires_vds2(mock_ccf_verify):
    statement = STATEMENT.read_bytes()
    log_key = load_pem_public_key(LOG_KEY.read_bytes())

    missing_vds = _receipt_parts()
    _set_vds(missing_vds, None)
    with pytest.raises(ValueError, match="unsupported receipt vds: None"):
        verify_receipt(_encode_receipt(missing_vds), log_key, statement)
    mock_ccf_verify.assert_not_called()

    vds2 = _receipt_parts()
    _set_vds(vds2, 2)
    encoded_receipt = _encode_receipt(vds2)
    verify_receipt(encoded_receipt, log_key, statement)
    mock_ccf_verify.assert_called_once_with(
        encoded_receipt, log_key, hashlib.sha256(statement).digest()
    )


def test_rejects_tampered_inclusion_path():
    parts = _receipt_parts()
    proof = cbor2.loads(parts[1][396][-1][0])
    proof[2][0] = bytes([proof[2][0][0] ^ 1]) + proof[2][0][1:]
    parts[1][396][-1][0] = cbor2.dumps(proof)

    with pytest.raises(ValueError, match="receipt signature is invalid"):
        verify_receipt(
            _encode_receipt(parts),
            load_pem_public_key(LOG_KEY.read_bytes()),
            STATEMENT.read_bytes(),
        )
