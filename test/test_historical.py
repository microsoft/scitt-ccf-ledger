# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from types import SimpleNamespace

import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import verify_transparent_statement


class TestHistorical:
    @pytest.fixture(scope="class")
    def submissions(self, client: Client, trusted_ca):
        COUNT = 5
        identity = trusted_ca.create_identity(alg="ES256", kty="ec")
        result = []
        for i in range(COUNT):
            signed_statement = crypto.sign_json_statement(identity, {"value": i})
            submission = client.submit_signed_statement_and_wait(signed_statement)
            result.append(
                SimpleNamespace(
                    signed_statement=signed_statement,
                    tx=submission.tx,
                    seqno=submission.seqno,
                    receipt=submission.response_bytes,
                )
            )
        return result

    def test_enumerate_statements(self, client: Client, submissions):
        seqnos = list(
            client.enumerate_statements(
                start=submissions[0].seqno, end=submissions[-1].seqno
            )
        )

        # This works because we don't run tests concurrently on a shared server.
        # If we did, we'd have to check for a sub-list instead.
        assert [s.tx for s in submissions] == seqnos

    def test_get_receipt(self, client: Client, trust_store, submissions):
        for s in submissions:
            receipt = client.get_transparent_statement(s.tx)
            verify_transparent_statement(receipt, trust_store, s.signed_statement)

