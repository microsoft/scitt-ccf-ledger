# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from types import SimpleNamespace

import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import verify_receipt


class TestHistorical:
    @pytest.fixture(scope="class")
    def submissions(self, client: Client, trusted_ca):
        COUNT = 5
        identity = trusted_ca.create_identity(alg="ES256", kty="ec")
        result = []
        for i in range(COUNT):
            claim = crypto.sign_json_claimset(identity, {"value": i})
            submission = client.submit_claim_and_confirm(claim)
            result.append(
                SimpleNamespace(
                    claim=claim,
                    tx=submission.tx,
                    seqno=submission.seqno,
                    receipt=submission.receipt,
                )
            )
        return result

    def test_enumerate_claims(self, client: Client, submissions):
        seqnos = list(
            client.enumerate_claims(
                start=submissions[0].seqno, end=submissions[-1].seqno
            )
        )

        # This works because we don't run tests concurrently on a shared server.
        # If we did, we'd have to check for a sub-list instead.
        assert [s.tx for s in submissions] == seqnos

    def test_get_receipt(self, client: Client, trust_store, submissions):
        for s in submissions:
            receipt = client.get_receipt(s.tx, decode=False)
            verify_receipt(s.claim, trust_store, receipt)

    def test_get_claim(self, client: Client, trust_store, submissions):
        for s in submissions:
            claim = client.get_claim(s.tx)
            verify_receipt(claim, trust_store, s.receipt)

    def test_get_claim_with_embedded_receipt(
        self, client: Client, trust_store, submissions
    ):
        for s in submissions:
            claim = client.get_claim(s.tx, embed_receipt=True)
            verify_receipt(claim, trust_store)

            # The original receipt can still be used on the claim, even after
            # the ledger has embedded a new copy of it.
            verify_receipt(claim, trust_store, s.receipt)
