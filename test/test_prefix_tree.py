# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from infra.fixtures import SCITTFixture
from pyscitt import crypto
from pyscitt.client import ServiceError


@pytest.mark.prefix_tree
def test_prefix_tree(tmp_path: Path):
    with SCITTFixture(tmp_path) as fixture:
        feed = "hello"
        identity = fixture.did_web_server.create_identity()
        first_claims = crypto.sign_json_claimset(
            identity, {"value": "first"}, feed=feed
        )
        first_submit = fixture.client.submit_claim(first_claims)

        pt = fixture.client.prefix_tree

        # Until we flush the prefix tree, the claim does not appear
        with pytest.raises(
            ServiceError, match="UnknownFeed: No claim found for given issuer and feed"
        ):
            pt.get_read_receipt(identity.issuer, feed)

        pt.flush()

        # Now we've flushed the PT, we can actually get a read receipt that
        # matches our submission.
        receipt = pt.get_read_receipt(identity.issuer, feed)
        receipt.verify(first_claims, fixture.service_parameters)
        assert first_submit.seqno == receipt.leaf_headers["claim_seqno"]
        assert first_submit.seqno < receipt.tree_headers["upper_bound_seqno"]

        # Submit a new claim to the same feed. The sequence numbers reflect the submission
        # ordering.
        second_claims = crypto.sign_json_claimset(
            identity, {"value": "second"}, feed=feed
        )
        second_submit = fixture.client.submit_claim(second_claims)
        assert second_submit.seqno > first_submit.seqno

        # Get a read receipt again - this will still reference the first claim,
        # since the PT hasn't been flushed.
        receipt = pt.get_read_receipt(identity.issuer, feed)
        assert first_submit.seqno == receipt.leaf_headers["claim_seqno"]
        receipt.verify(first_claims, fixture.service_parameters)
        with pytest.raises(InvalidSignature):
            receipt.verify(second_claims, fixture.service_parameters)

        pt.flush()

        # Now the read receipt matches the second claim
        receipt = pt.get_read_receipt(identity.issuer, feed)
        assert second_submit.seqno == receipt.leaf_headers["claim_seqno"]
        assert second_submit.seqno < receipt.tree_headers["upper_bound_seqno"]
        receipt.verify(second_claims, fixture.service_parameters)
        with pytest.raises(InvalidSignature):
            receipt.verify(first_claims, fixture.service_parameters)

        # We submit a final claim, but to a different feed.
        # This should not affect read receipts for the original feed.
        third_claims = crypto.sign_json_claimset(
            identity, {"value": "third"}, feed="other"
        )
        third_submit = fixture.client.submit_claim(third_claims)
        pt.flush()

        receipt = pt.get_read_receipt(identity.issuer, feed)
        assert second_submit.seqno == receipt.leaf_headers["claim_seqno"]
        # Note that the tree headers must still account for the submission to the other feed
        assert third_submit.seqno < receipt.tree_headers["upper_bound_seqno"]
        receipt.verify(second_claims, fixture.service_parameters)
        with pytest.raises(InvalidSignature):
            receipt.verify(first_claims, fixture.service_parameters)
