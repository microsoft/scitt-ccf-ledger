# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from types import SimpleNamespace

import pytest

from pyscitt import crypto


class TestHistorical:
    @pytest.fixture(scope="class")
    def submissions(self, did_web, client):
        COUNT = 5
        identity = did_web.create_identity()
        result = []
        for i in range(COUNT):
            claim = crypto.sign_json_claimset(identity, {"value": i})
            submission = client.submit_claim(claim, decode=False)
            result.append(
                SimpleNamespace(
                    claim=claim, tx=submission.tx, receipt=submission.receipt
                )
            )
        return result

    def test_enumerate_claims(self, client, submissions):
        txs = list(
            client.enumerate_claims(start=submissions[0].tx, end=submissions[-1].tx)
        )

        # This works because we don't run tests concurrently on a single server.
        # If we did, we'd have to check for a sub-list instead.
        assert [s.tx for s in submissions] == txs

    def test_get_receipt(self, client, trust_store, submissions):
        for s in submissions:
            receipt = client.get_receipt(s.tx, decode=False)
            crypto.verify_cose_with_receipt(s.claim, trust_store, receipt)

    def test_get_claim(self, client, trust_store, submissions):
        for s in submissions:
            claim = client.get_claim(s.tx)
            crypto.verify_cose_with_receipt(claim, trust_store, s.receipt)

    def test_get_claim_with_receipt(self, client, trust_store, submissions):
        for s in submissions:
            claim = client.get_claim(s.tx, embed_receipt=True)
            crypto.verify_cose_with_receipt(claim, trust_store)

            # The original receipt can still be used on the claim, even after
            # the ledger has embedded a new copy of it.
            crypto.verify_cose_with_receipt(claim, trust_store, s.receipt)
