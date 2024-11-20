# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import verify_receipt, verify_transparent_statement


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256"},
        {"alg": "ES384", "kty": "ec", "ec_curve": "P-384"},
        {"alg": "ES512", "kty": "ec", "ec_curve": "P-521"},
        {"alg": "PS256", "kty": "rsa"},
        {"alg": "PS384", "kty": "rsa"},
        {"alg": "PS512", "kty": "rsa"}
    ],
)
def test_submit_claim(client: Client, trusted_ca, trust_store, params):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts.

    Test is parametrized over different signing parameters.
    """
    identity = trusted_ca.create_identity(**params)

    # Sign and submit a dummy claim using our new identity
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    statement = client.submit_and_confirm(claims).receipt_bytes
    verify_transparent_statement(statement, trust_store, claims)


@pytest.mark.isolated_test
def test_recovery(client, trusted_ca, restart_service):
    identity = trusted_ca.create_identity(alg="PS384", kty="rsa")
    client.submit_claim_and_confirm(crypto.sign_json_claimset(identity, {"foo": "bar"}))

    old_network = client.get("/node/network").json()
    assert old_network["recovery_count"] == 0

    restart_service()

    new_network = client.get("/node/network").json()
    assert new_network["recovery_count"] == 1
    assert new_network["service_certificate"] != old_network["service_certificate"]

    # Check that the service is still operating correctly
    client.submit_claim_and_confirm(
        crypto.sign_json_claimset(identity, {"foo": "hello"})
    )
