# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from hashlib import sha256
from http import HTTPStatus

import cbor2
import ccf.cose
from loguru import logger as LOG
from pycose.messages import CoseMessage

from pyscitt import crypto
from pyscitt.client import Client


def test_blocking_entries(
    client: Client, cert_authority, trust_store, configure_service
):
    """
    Submit a signed statement via POST /entries?waitForCommit=true and
    inspect the response.

    The request blocks until the transaction is globally committed and
    returns the COSE receipt directly.
    """
    identity = cert_authority.create_identity(
        alg="ES256", kty="ec", ec_curve="P-256", add_eku="2.999"
    )
    configure_service(
        {
            "policy": {
                "policyScript": f'export function apply(phdr) {{ return phdr.cwt.iss === "{identity.issuer}"; }}'
            }
        }
    )

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"}, cwt=True)

    submission = client.submit_signed_statement_wait_for_commit(signed_statement)

    LOG.info("=== Blocking /entries?waitForCommit=true response ===")
    LOG.info(f"Transaction ID: {submission.tx}")
    LOG.info(f"Response bytes length: {len(submission.response_bytes)}")
    LOG.info(
        f"Response bytes (hex, first 128): {submission.response_bytes[:128].hex()}"
    )

    # Decode via pycose to show the raw COSE structure
    cose_msg = CoseMessage.decode(submission.response_bytes)
    LOG.info(f"COSE message type: {type(cose_msg).__name__}")
    LOG.info(f"COSE protected headers: {cose_msg.phdr}")
    LOG.info(f"COSE unprotected headers: {cose_msg.uhdr}")
    LOG.info(f"COSE payload length: {len(cose_msg.payload) if cose_msg.payload else 0}")

    # Decode the raw CBOR to inspect the full structure
    raw = cbor2.loads(submission.response_bytes)
    if isinstance(raw, cbor2.CBORTag):
        LOG.info(f"CBOR tag: {raw.tag}")
        raw = raw.value
    LOG.info(f"COSE_Sign1 array length: {len(raw)}")
    # raw[0] = protected headers, raw[1] = unprotected headers, raw[2] = payload, raw[3] = signature
    uhdr = raw[1] if len(raw) > 1 else {}
    LOG.info(
        f"Unprotected headers keys: {list(uhdr.keys()) if isinstance(uhdr, dict) else type(uhdr)}"
    )
    LOG.info(f"Unprotected headers: {uhdr}")

    # Verify the receipt against the signed statement using ccf.cose directly.
    service_key = trust_store.get_key(submission.response_bytes)
    ccf.cose.verify_receipt(
        submission.response_bytes,
        service_key,
        sha256(signed_statement).digest(),
    )

    deadline = time.monotonic() + 3
    regular_receipt = client.session.get(
        "/node/receipt", params={"transaction_id": submission.tx}
    )
    while (
        regular_receipt.status_code == HTTPStatus.ACCEPTED
        and time.monotonic() < deadline
    ):
        time.sleep(0.1)
        regular_receipt = client.session.get(
            "/node/receipt", params={"transaction_id": submission.tx}
        )

    assert regular_receipt.status_code == HTTPStatus.INTERNAL_SERVER_ERROR, (
        "Traditional receipt should be unavailable with COSE-only ledger "
        f"signatures, got {regular_receipt.status_code}"
    )
    LOG.info("Receipt verification: PASSED")
