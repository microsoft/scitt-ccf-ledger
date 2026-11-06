# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Tests for SCRAPI v09 registration flow (sections 2.3-2.5).

These tests verify the HTTP-level behavior of the SCRAPI v09 registration
endpoints, including status codes, Location headers, and polling behavior,
as well as the legacy flow used by clients that don't send the api-version.
"""

import re
from http import HTTPStatus

import cbor2
import pytest
from loguru import logger as LOG

from pyscitt import crypto
from pyscitt.client import (
    CBOR_ERR_DETAIL_TAG,
    CBOR_ERR_TITLE_TAG,
    SCITT_API_VERSION_2026_03_26,
    Client,
    ServiceError,
)

CT_APPLICATION_CBOR = "application/cbor"
CT_APPLICATION_COSE = "application/cose"
CT_SCITT_RECEIPT = "application/scitt-receipt+cose"
CT_SCITT_STATEMENT = "application/scitt-statement+cose"


@pytest.fixture(scope="class")
def scrapi_client(client: Client) -> Client:
    """Client configured with the SCRAPI v09 api-version."""
    return client.replace(api_version=SCITT_API_VERSION_2026_03_26)


def test_async_registration_returns_303(
    scrapi_client: Client, cert_authority, configure_service
):
    """
    POST /entries returns 303 See Other with a Location header pointing
    to /entries/{txid} per SCRAPI v09 section 2.3.2.
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

    # Bypasses the client's high-level submit logic so that the actual HTTP
    # response can be inspected. Redirect following is disabled so that the 303
    # is returned rather than followed, while a 307 sending the write from a
    # backup to the primary is still followed transparently.
    resp = scrapi_client.request(
        "POST",
        "/entries",
        headers={"Content-Type": CT_APPLICATION_COSE},
        content=signed_statement,
        follow_redirects=False,
    )

    LOG.info(f"POST /entries status: {resp.status_code}")
    LOG.info(f"POST /entries headers: {dict(resp.headers)}")

    assert (
        resp.status_code == HTTPStatus.SEE_OTHER
    ), f"Expected 303 See Other, got {resp.status_code}"

    # Verify Location header exists and points to /entries/{txid}
    location = resp.headers.get("location")
    assert location is not None, "303 response must include Location header"
    assert (
        "/entries/" in location
    ), f"Location header must point to /entries/{{txid}}, got: {location}"

    # Verify the Location contains a valid transaction ID (view.seqno format)
    tx_match = re.search(r"/entries/(\d+\.\d+)", location)
    assert (
        tx_match is not None
    ), f"Location must contain a txid in view.seqno format, got: {location}"
    tx_id = tx_match.group(1)
    LOG.info(f"Transaction ID from Location: {tx_id}")

    # Verify x-ms-ccf-transaction-id header is present
    ccf_tx_id = resp.headers.get("x-ms-ccf-transaction-id")
    assert (
        ccf_tx_id is not None
    ), "303 response must include x-ms-ccf-transaction-id header"
    assert (
        ccf_tx_id == tx_id
    ), f"Transaction ID mismatch: Location has {tx_id}, header has {ccf_tx_id}"

    # Verify body is empty (SCRAPI v09 2.3.2: empty body on 303)
    assert (
        len(resp.content) == 0
    ), f"303 response body must be empty, got {len(resp.content)} bytes"


def test_legacy_registration_returns_202_then_operation_succeeds(
    client: Client, cert_authority, configure_service
):
    """
    Without the api-version, POST /entries returns 202 Accepted with a CBOR
    operation body and a Location header pointing to /operations/{txid}.
    GET /operations/{txid} then returns 202 while the transaction is pending,
    and 200 with the entry ID once it is committed.
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

    legacy_client = client.replace(api_version=None)
    resp = legacy_client.request(
        "POST",
        "/entries",
        headers={"Content-Type": CT_APPLICATION_COSE},
        content=signed_statement,
        follow_redirects=False,
    )

    LOG.info(f"POST /entries status: {resp.status_code}")
    LOG.info(f"POST /entries headers: {dict(resp.headers)}")

    assert (
        resp.status_code == HTTPStatus.ACCEPTED
    ), f"Expected 202 Accepted, got {resp.status_code}"
    assert resp.headers.get("content-type") == CT_APPLICATION_CBOR

    operation = cbor2.loads(resp.content)
    tx = operation.get("OperationId")
    assert operation == {"OperationId": tx, "Status": "running"}
    assert re.fullmatch(r"\d+\.\d+", tx), f"Invalid operation ID: {tx}"
    assert resp.headers.get("x-ms-ccf-transaction-id") == tx

    location = resp.headers.get("location")
    assert location is not None and location.endswith(
        f"/operations/{tx}"
    ), f"Location header must point to /operations/{{txid}}, got: {location}"

    # Poll the operation, as legacy clients do, until it is no longer running.
    resp = legacy_client.get(f"/operations/{tx}", retry_on=[HTTPStatus.ACCEPTED])
    LOG.info(f"GET /operations/{tx} headers: {dict(resp.headers)}")

    assert resp.status_code == HTTPStatus.OK
    assert resp.headers.get("content-type") == CT_APPLICATION_CBOR
    assert cbor2.loads(resp.content) == {
        "OperationId": tx,
        "Status": "succeeded",
        "EntryId": tx,
    }

    location = resp.headers.get("location")
    assert location is not None and location.endswith(
        f"/entries/{tx}"
    ), f"Location header must point to /entries/{{txid}}, got: {location}"

    # Reads are answered by whichever node serves the request, so give the
    # whole network a chance to apply the transaction before reading it.
    client.wait_for_confirmation_on_all_nodes(tx)

    # The entry is readable without the api-version too.
    assert legacy_client.get_historical(f"/entries/{tx}").status_code == HTTPStatus.OK
    assert (
        legacy_client.get_historical(f"/entries/{tx}/statement").status_code
        == HTTPStatus.OK
    )


def test_operation_status_follows_transaction_status(
    scrapi_client: Client, cert_authority, configure_service
):
    """
    GET /operations/{txid} is answered from the status of the transaction:
    succeeded once it is committed, failed if it can't be committed, and
    running while it isn't known yet. A malformed operation ID is rejected.
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

    tx = scrapi_client.submit_signed_statement_wait_for_commit(signed_statement).tx
    scrapi_client.wait_for_confirmation_on_all_nodes(tx)

    resp = scrapi_client.get(f"/operations/{tx}")
    assert resp.status_code == HTTPStatus.OK
    assert cbor2.loads(resp.content) == {
        "OperationId": tx,
        "Status": "succeeded",
        "EntryId": tx,
    }

    # A view that doesn't match the one the seqno was committed in makes the
    # transaction ID invalid.
    view, seqno = tx.split(".")
    invalid_tx = f"{int(view) + 1}.{seqno}"
    resp = scrapi_client.get(f"/operations/{invalid_tx}")
    LOG.info(f"GET /operations/{invalid_tx} headers: {dict(resp.headers)}")

    assert resp.status_code == HTTPStatus.OK
    assert cbor2.loads(resp.content) == {
        "OperationId": invalid_tx,
        "Status": "failed",
        "Error": {
            CBOR_ERR_TITLE_TAG: "TransactionInvalid",
            CBOR_ERR_DETAIL_TAG: "Transaction is invalid",
        },
    }
    assert "location" not in resp.headers

    # A transaction ID the service doesn't know yet is still running.
    resp = scrapi_client.get(f"/operations/{view}.{int(seqno) + 1000000}")
    assert resp.status_code == HTTPStatus.ACCEPTED

    with pytest.raises(ServiceError) as excinfo:
        scrapi_client.get("/operations/not-a-txid")
    assert excinfo.value.code == "InvalidInput"
    assert "Invalid Operation ID" in excinfo.value.message


def test_entry_polling_returns_302_then_200(
    scrapi_client: Client, cert_authority, trust_store, configure_service
):
    """
    GET /entries/{txid} returns 302 Found while pending and 200 OK with
    the receipt when committed, per SCRAPI v09 sections 2.4.1 and 2.4.2.
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

    # Submit and get the transaction ID
    submission = scrapi_client.submit_signed_statement(signed_statement)
    tx = submission.operation_tx
    LOG.info(f"Submitted, tx={tx}")

    # Poll GET /entries/{txid} - first request may return 302 or 200
    # depending on timing. We verify that:
    # 1. If 302, it has Location header
    # 2. Eventually it returns 200 with the receipt
    first_resp = scrapi_client.session.request("GET", f"/entries/{tx}")
    LOG.info(f"First GET /entries/{tx} status: {first_resp.status_code}")
    LOG.info(f"First GET /entries/{tx} headers: {dict(first_resp.headers)}")

    if first_resp.status_code == HTTPStatus.FOUND:
        # Verify 302 response has required headers per SCRAPI v09 2.4.1
        location = first_resp.headers.get("location")
        assert location is not None, "302 response must include Location header"
        assert (
            f"/entries/{tx}" in location
        ), f"302 Location must point to /entries/{{txid}}, got: {location}"
        LOG.info(f"302 Location: {location}")

    # Now use the client's polling method to wait for the final 200
    receipt = scrapi_client.wait_for_entry(tx)
    assert len(receipt) > 0, "200 response must contain the COSE receipt"
    LOG.info(f"Got receipt, {len(receipt)} bytes")


def test_sync_registration_returns_201_with_location(
    scrapi_client: Client, cert_authority, configure_service
):
    """
    POST /entries?waitForCommit=true returns 201 Created with Location header
    and the COSE receipt in the response body.
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

    submission = scrapi_client.submit_signed_statement_wait_for_commit(signed_statement)

    assert submission.tx is not None
    assert (
        len(submission.response_bytes) > 0
    ), "Sync mode must return the COSE receipt in the response body"
    LOG.info(
        f"Sync submit tx={submission.tx}, receipt={len(submission.response_bytes)} bytes"
    )


def test_submit_and_wait_scrapi_flow(
    scrapi_client: Client, cert_authority, trust_store, configure_service
):
    """
    End-to-end test of the SCRAPI v09 registration flow using the
    high-level client methods: submit → poll → get transparent statement.

    Verifies that submit_signed_statement_and_wait() works correctly
    with the 303 → 302/200 polling flow.
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

    # Use the high-level method that exercises the full SCRAPI v09 flow:
    # POST /entries → 303 → parse Location → poll GET /entries/{txid} → 200
    submission = scrapi_client.submit_signed_statement_and_wait(signed_statement)

    assert submission.tx is not None
    assert len(submission.response_bytes) > 0
    LOG.info(
        f"submit_and_wait tx={submission.tx}, response={len(submission.response_bytes)} bytes"
    )


def test_submit_and_wait_for_receipt_scrapi_flow(
    scrapi_client: Client, cert_authority, trust_store, configure_service
):
    """
    End-to-end test using submit_signed_statement_and_wait_for_receipt(),
    which exercises the SCRAPI v09 303 → polling → receipt flow.
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

    submission = scrapi_client.submit_signed_statement_and_wait_for_receipt(
        signed_statement
    )

    assert submission.tx is not None
    assert len(submission.response_bytes) > 0
    LOG.info(
        f"submit_and_wait_for_receipt tx={submission.tx}, receipt={len(submission.response_bytes)} bytes"
    )


def test_receipt_content_type(scrapi_client: Client, cert_authority, configure_service):
    """
    GET /entries/{txid} returns Content-Type: application/scitt-receipt+cose
    per IANA-registered SCITT media types.
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
    submission = scrapi_client.submit_signed_statement(signed_statement)
    tx = submission.operation_tx

    # Wait for entry and check the content type on the raw response
    receipt = scrapi_client.wait_for_entry(tx)
    assert len(receipt) > 0

    # Make a direct request to verify Content-Type header
    resp = scrapi_client.get_historical(f"/entries/{tx}")
    content_type = resp.headers.get("content-type")
    LOG.info(f"GET /entries/{tx} Content-Type: {content_type}")
    assert (
        content_type == CT_SCITT_RECEIPT
    ), f"Expected Content-Type {CT_SCITT_RECEIPT}, got {content_type}"


def test_sync_receipt_content_type(
    scrapi_client: Client, cert_authority, configure_service
):
    """
    POST /entries?waitForCommit=true returns Content-Type: application/scitt-receipt+cose.
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

    resp = scrapi_client.post(
        "/entries",
        params={"waitForCommit": "true"},
        headers={"Content-Type": CT_APPLICATION_COSE},
        content=signed_statement,
    )
    resp.raise_for_status()

    content_type = resp.headers.get("content-type")
    LOG.info(f"POST /entries?waitForCommit=true Content-Type: {content_type}")
    assert (
        content_type == CT_SCITT_RECEIPT
    ), f"Expected Content-Type {CT_SCITT_RECEIPT}, got {content_type}"


def test_transparent_statement_content_type(
    scrapi_client: Client, cert_authority, configure_service
):
    """
    GET /entries/{txid}/statement returns Content-Type: application/scitt-statement+cose.
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
    submission = scrapi_client.submit_signed_statement_and_wait(signed_statement)
    tx = submission.tx

    resp = scrapi_client.get_historical(f"/entries/{tx}/statement")
    content_type = resp.headers.get("content-type")
    LOG.info(f"GET /entries/{tx}/statement Content-Type: {content_type}")
    assert (
        content_type == CT_SCITT_STATEMENT
    ), f"Expected Content-Type {CT_SCITT_STATEMENT}, got {content_type}"
