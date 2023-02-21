# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time

import pytest

from pyscitt import crypto, did
from pyscitt.client import Client
from pyscitt.verify import TrustStore, verify_receipt

from . import constants
from .infra.assertions import service_error
from .infra.did_web_server import DIDWebServer


def test_cache_resolution(
    client: Client,
    did_web: DIDWebServer,
    trust_store: TrustStore,
):
    """
    Submit two claims signed with the same key, sequentially.

    The ledger should only perform DID resolution once, reusing the cached DID
    document on the second submission.
    """
    identity = did_web.create_identity()

    with did_web.monitor() as metrics:
        claim1 = crypto.sign_json_claimset(identity, "Hello")
        receipt1 = client.submit_claim(claim1).receipt

        claim2 = crypto.sign_json_claimset(identity, "World")
        receipt2 = client.submit_claim(claim2, allow_retries=False).receipt

    assert metrics.request_count == 1
    verify_receipt(claim1, trust_store, receipt1)
    verify_receipt(claim2, trust_store, receipt2)


@pytest.mark.isolated_test(enable_faketime=True)
def test_key_expiry(client, did_web, cchost):
    """
    When a key is rotated, after a while, the ledger should remove the old one
    from its cache and reject claims signed with it.
    """

    identity = did_web.create_identity()
    claim = crypto.sign_json_claimset(identity, "Hello")
    client.submit_claim(claim)

    # Rotate the key
    did_web.create_identity(identifier=identity.issuer)

    # The ledger still has the DID document cached, so will accept a claim
    # signed with the old key.
    client.submit_claim(claim, allow_retries=False)

    # Time travel, enough for the cached document to expire.
    cchost.advance_time(seconds=constants.DID_RESOLUTION_CACHE_EXPIRY_SECONDS)

    # The cached document can't be used anymore since it has expired. The
    # ledger has to re-fetch it, but will eventually fail since the document
    # now contains a new key.
    #
    # TODO: make the assertion on the error more precise. We should really
    # check that the second resolution fails because of a wrong key ID.
    with service_error("DIDResolutionInProgressRetryLater"):
        client.submit_claim(claim, allow_retries=False)

    # TODO: exiting while a resolution is in progress causes libuv to fail with
    # EBUSY, since the external process is still running. Once we have a better
    # way of monitoring the status of DID resolution we can be a bit smarter
    # about this.
    time.sleep(5)


def test_multiple_keys(
    client: Client,
    did_web: DIDWebServer,
    trust_store: TrustStore,
):
    """
    If a DID document contains multiple public keys, claims signed by either key
    should be accepted by the ledger.
    """

    private_key1, public_key1 = crypto.generate_keypair(kty="ec")
    private_key2, public_key2 = crypto.generate_keypair(kty="ec")

    # Create a DID document with multiple keys, each with their own KID.
    issuer = did_web.generate_identifier()
    document = did.create_document(
        did=issuer,
        assertion_methods=[
            did.create_assertion_method(
                did=issuer, public_key=public_key1, kid="#key-1"
            ),
            did.create_assertion_method(
                did=issuer, public_key=public_key2, kid="#key-2"
            ),
        ],
    )
    did_web.write_did_document(document)

    def submit(private_key, kid, payload):
        identity = crypto.Signer(private_key, issuer=issuer, kid=kid)
        claim = crypto.sign_json_claimset(identity, payload)
        receipt = client.submit_claim(claim).receipt
        verify_receipt(claim, trust_store, receipt)

    # We can submit claims with either key, using a single DID document.
    submit(private_key1, "#key-1", "Hello")
    submit(private_key2, "#key-2", "World")


def test_claim_without_kid(
    client: Client,
    did_web: DIDWebServer,
    trust_store: TrustStore,
):
    """
    If a DID document contains only one public key, the server should accept
    claims that don't include any KID.
    """
    private_key, public_key = crypto.generate_keypair(kty="ec")
    issuer = did_web.generate_identifier()
    did_web.write_did_document(did.create_document(did=issuer, public_key=public_key))

    identity = crypto.Signer(issuer=issuer, private_key=private_key)
    claim = crypto.sign_json_claimset(identity, "Payload")

    receipt = client.submit_claim(claim).receipt
    verify_receipt(claim, trust_store, receipt)


def test_consistent_kid(
    client: Client,
    did_web: DIDWebServer,
    trust_store: TrustStore,
):
    """
    Submit a claim with a known kid and check that it is consistent
    with the claim header and DID document.
    """
    kid = "#key-1"
    identity = did_web.create_identity(kid=kid)
    assert identity.issuer is not None

    # Sign a dummy claim using our new identity.
    claim = crypto.sign_json_claimset(identity, {"foo": "bar"})

    # Check that the COSE header contains the expected kid.
    header, _ = crypto.parse_cose_sign1(claim)
    assert header["kid"] == kid

    # Submit the claim and verify the resulting receipt.
    receipt = client.submit_claim(claim).receipt
    verify_receipt(claim, trust_store, receipt)

    # Check that the resolved DID document contains the expected assertion
    # method id.
    did_doc = client.get_did_document(identity.issuer)
    assert did_doc["assertionMethod"][0]["id"] == f"{identity.issuer}{kid}"
