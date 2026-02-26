# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from types import SimpleNamespace

import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import verify_transparent_statement


class TestHistorical:
    @pytest.fixture(scope="class")
    def submissions(self, client: Client, cert_authority, configure_service):
        COUNT = 5
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku="2.999"
        )
        configure_service(
            {
                "policy": {
                    "policyScript": f'export function apply(phdr) {{ return phdr.cwt.iss === "{identity.issuer}"; }}'
                }
            }
        )

        result = []
        for i in range(COUNT):
            signed_statement = crypto.sign_json_statement(
                identity, {"value": i}, cwt=True
            )
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

    def test_get_receipt(self, client: Client, trust_store, submissions):
        for s in submissions:
            receipt = client.get_transparent_statement(s.tx)
            verify_transparent_statement(receipt, trust_store, s.signed_statement)
