# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from cryptography.exceptions import InvalidSignature

from pyscitt import crypto
from pyscitt.client import ServiceError


@pytest.mark.needs_prefix_tree
def test_prefix_tree(did_web, client):
    feed = "hello"
    identity = did_web.create_identity()
    service_parameters = client.get_parameters()

    first_claims = crypto.sign_json_claimset(identity, {"value": "first"}, feed=feed)
    first_submit = client.submit_claim(first_claims)

    pt = client.prefix_tree

    # Until we flush the prefix tree, the claim does not appear
    with pytest.raises(ServiceError, match="UnknownFeed"):
        pt.get_read_receipt(identity.issuer, feed)

    pt.flush()

    # Now we've flushed the PT, we can actually get a read receipt that
    # matches our submission.
    receipt = pt.get_read_receipt(identity.issuer, feed)
    receipt.verify(first_claims, service_parameters)
    assert first_submit.seqno == receipt.leaf_headers["claim_seqno"]
    assert first_submit.seqno < receipt.tree_headers["upper_bound_seqno"]

    # Submit a new claim to the same feed. The sequence numbers reflect the submission
    # ordering.
    second_claims = crypto.sign_json_claimset(identity, {"value": "second"}, feed=feed)
    second_submit = client.submit_claim(second_claims)
    assert second_submit.seqno > first_submit.seqno

    # Get a read receipt again - this will still reference the first claim,
    # since the PT hasn't been flushed.
    receipt = pt.get_read_receipt(identity.issuer, feed)
    assert first_submit.seqno == receipt.leaf_headers["claim_seqno"]
    receipt.verify(first_claims, service_parameters)
    with pytest.raises(InvalidSignature):
        receipt.verify(second_claims, service_parameters)

    pt.flush()

    # Now the read receipt matches the second claim
    receipt = pt.get_read_receipt(identity.issuer, feed)
    assert second_submit.seqno == receipt.leaf_headers["claim_seqno"]
    assert second_submit.seqno < receipt.tree_headers["upper_bound_seqno"]
    receipt.verify(second_claims, service_parameters)
    with pytest.raises(InvalidSignature):
        receipt.verify(first_claims, service_parameters)

    # We submit a final claim, but to a different feed.
    # This should not affect read receipts for the original feed.
    third_claims = crypto.sign_json_claimset(identity, {"value": "third"}, feed="other")
    third_submit = client.submit_claim(third_claims)
    pt.flush()

    receipt = pt.get_read_receipt(identity.issuer, feed)
    assert second_submit.seqno == receipt.leaf_headers["claim_seqno"]
    # Note that the tree headers must still account for the submission to the other feed
    assert third_submit.seqno < receipt.tree_headers["upper_bound_seqno"]
    receipt.verify(second_claims, service_parameters)
    with pytest.raises(InvalidSignature):
        receipt.verify(first_claims, service_parameters)


# This test only works on an isolated cchost instance, since we require the service to be blank.
@pytest.mark.isolated_test
@pytest.mark.needs_cchost
@pytest.mark.needs_prefix_tree
def test_empty_prefix_tree(client):
    """Before any flush has been committed, fetching the prefix tree receipt returns a graceful error."""

    with pytest.raises(ServiceError, match="NoPrefixTree"):
        client.get_historical("/prefix_tree")

    client.prefix_tree.flush()

    # Now we're okay since we have at least one PT root committed.
    client.get_historical("/prefix_tree")
