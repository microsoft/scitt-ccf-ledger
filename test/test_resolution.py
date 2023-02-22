# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
from pathlib import Path
from typing import Callable, List

import pytest

from pyscitt import crypto, did
from pyscitt.client import Client
from pyscitt.verify import TrustStore, verify_receipt

from . import constants
from .infra.assertions import service_error
from .infra.did_web_server import DIDWebServer


@pytest.fixture
def submit_concurrently(
    client: Client,
    did_web: DIDWebServer,
):
    """
    A fixture which allows multiple claims to be submitted concurrently.

    This is achieved by suspending the DID web server, submitting all the
    claims, then finally resuming the server.

    Returns the list of operation IDs.
    """

    def f(claims: List[bytes]) -> List[str]:
        with did_web.suspend():
            operations = [
                client.submit_claim(c, skip_confirmation=True).operation_tx
                for c in claims
            ]

            # Give the ledger a second to kick off the requests before we
            # unblock the DID server.
            time.sleep(1)

        return operations

    return f


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
        receipt2 = client.submit_claim(claim2).receipt

    assert metrics.request_count == 1
    verify_receipt(claim1, trust_store, receipt1)
    verify_receipt(claim2, trust_store, receipt2)


def test_concurrent_resolution(
    client: Client,
    did_web: DIDWebServer,
    trust_store: TrustStore,
    submit_concurrently: Callable[[List[bytes]], List[str]],
):
    """
    Submit two claims signed with the same key, concurrently.

    The ledger should aggregate the two resolutions into a single HTTP request
    to the same server.
    """
    identity = did_web.create_identity()
    claim1 = crypto.sign_json_claimset(identity, "Hello")
    claim2 = crypto.sign_json_claimset(identity, "World")

    with did_web.monitor() as metrics:
        [tx1, tx2] = submit_concurrently([claim1, claim2])
        receipt1 = client.get_receipt(tx1, operation=True)
        receipt2 = client.get_receipt(tx2, operation=True)

    assert metrics.request_count == 1
    verify_receipt(claim1, trust_store, receipt1)
    verify_receipt(claim2, trust_store, receipt2)


def test_key_rotation(
    client: Client,
    did_web: DIDWebServer,
    trust_store: TrustStore,
):
    """
    When rotating the key found in a DID document, the ledger doesn't use the
    cached document but instead fetches the document again.
    """

    with did_web.monitor() as metrics:
        identity1 = did_web.create_identity()
        claim1 = crypto.sign_json_claimset(identity1, "Hello")
        receipt1 = client.submit_claim(claim1).receipt

        identity2 = did_web.create_identity(identifier=identity1.issuer)
        claim2 = crypto.sign_json_claimset(identity2, "World")
        receipt2 = client.submit_claim(claim2).receipt

    assert identity1.issuer == identity2.issuer
    assert identity1.kid != identity2.kid
    assert metrics.request_count == 2
    verify_receipt(claim1, trust_store, receipt1)
    verify_receipt(claim2, trust_store, receipt2)

    # The old claim can't be submitted anymore, since it uses the old key.
    with service_error("Missing assertion method in DID document"):
        client.submit_claim(claim1)


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
    client.submit_claim(claim)

    # Time travel, enough for the cached document to expire.
    cchost.advance_time(seconds=constants.DID_RESOLUTION_CACHE_EXPIRY_SECONDS)

    # The cached document can't be used anymore since it has expired. The
    # ledger has to re-fetch it, but will eventually fail since the document
    # now contains a new key. When it does, the document won't contain the old
    # key anymore and resolution will fail.
    with service_error("Missing assertion method in DID document"):
        client.submit_claim(claim)


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

    # If we don't specify a KID when signing the claim, it becomes ambigous
    # which key we wanted to use and the server rejects the claim.
    with service_error(
        "DID document must have exactly one assertion method if no assertion method id is provided"
    ):
        submit(private_key1, None, "World")


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


class TestDIDMismatch:
    """
    Test DID resolution with an inconsistent DID document.

    The "id" field of the document does not match the expected value.

    This error scenario isn't particularly interesting in itself, but it is an
    easy way to test the ledger's handling of errors during resolution.
    """

    def write_invalid_document(self, did_web: DIDWebServer, identity: crypto.Signer):
        """
        Write a DID document at the location which would be resolved for `identity`,
        but write a random identifier into it which does not correspond to the location
        of the document nor the issuer we use in claims.
        """
        document = did.create_document(
            did=did_web.generate_identifier(),
            public_key=crypto.private_key_to_public(identity.private_key),
        )

        assert document["id"] != identity.issuer

        did_web.write_did_document(document, identifier=identity.issuer)

    def test_submit(self, client: Client, did_web: DIDWebServer):
        identity = did_web.create_identity()
        self.write_invalid_document(did_web, identity)

        claim = crypto.sign_json_claimset(identity, "Payload")

        with service_error("DID document ID does not match expected value"):
            client.submit_claim(claim)

    def test_submit_concurrently(
        self,
        client: Client,
        did_web: DIDWebServer,
        submit_concurrently: Callable[[List[bytes]], List[str]],
    ):
        """
        Submit two claims signed with the same key, sequentially.

        The server should aggregate the resolutions into a single request, yet
        correctly report the resolution error on both operations.
        """
        identity = did_web.create_identity()
        self.write_invalid_document(did_web, identity)

        claim1 = crypto.sign_json_claimset(identity, "Hello")
        claim2 = crypto.sign_json_claimset(identity, "World")

        with did_web.monitor() as metrics:
            [tx1, tx2] = submit_concurrently([claim1, claim2])

            with service_error("DID document ID does not match expected value"):
                client.wait_for_operation(tx1)

            with service_error("DID document ID does not match expected value"):
                client.wait_for_operation(tx2)

        assert metrics.request_count == 1

    def test_dont_cache_error(
        self,
        client: Client,
        did_web: DIDWebServer,
        trust_store: TrustStore,
    ):
        """
        Test that the ledger does not cache failed resolutions.

        After fixing the cause of the error, the server should immediately be
        able to resolve the DID again.
        """
        identity = did_web.create_identity()
        self.write_invalid_document(did_web, identity)

        assert identity.issuer is not None

        claim = crypto.sign_json_claimset(identity, "Payload")

        # Submit the claim a first time, with the invalid document
        with service_error("DID document ID does not match expected value"):
            client.submit_claim(claim)

        # Update the published document. This time it uses the correct DID.
        document = did.create_document(
            did=identity.issuer,
            public_key=crypto.private_key_to_public(identity.private_key),
        )
        did_web.write_did_document(document)

        # Submitting the same claim now works just fine.
        receipt = client.submit_claim(claim).receipt
        verify_receipt(claim, trust_store, receipt)


def test_fetch_not_found(
    client: Client,
    did_web: DIDWebServer,
):
    """
    Test that the ledger returns an error message for failed attested fetch resolutions.
    """
    private_key, _ = crypto.generate_keypair(kty="ec")
    issuer = did_web.generate_identifier()

    identity = crypto.Signer(issuer=issuer, private_key=private_key)
    claim = crypto.sign_json_claimset(identity, "Payload")

    with service_error("DID Resolution failed with status code: 404"):
        client.submit_claim(claim)


def test_untrusted_server(
    client: Client,
    tmp_path: Path,
):
    """
    Submit a claim with a DID document hosted with an untrusted TLS certificate.
    """

    private_key, _ = crypto.generate_keypair(kty="ec")

    # Create a distinct DID web server, whose certificate is never added to
    # the ledger's CA root store.
    with DIDWebServer(tmp_path) as untrusted_did_web:
        identity = untrusted_did_web.create_identity(kty="ec")
        claim = crypto.sign_json_claimset(identity, "Payload")

        with service_error("DIDResolutionError: Certificate chain is invalid"):
            client.submit_claim(claim)


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
