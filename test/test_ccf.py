# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import os
from pathlib import Path

import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import StaticTrustStore, verify_transparent_statement


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256"},
        {"alg": "ES384", "kty": "ec", "ec_curve": "P-384"},
        {"alg": "ES512", "kty": "ec", "ec_curve": "P-521"},
        {"alg": "PS256", "kty": "rsa"},
        {"alg": "PS384", "kty": "rsa"},
        {"alg": "PS512", "kty": "rsa"},
    ],
)
def test_make_signed_statement_transparent(
    client: Client, trusted_ca, trust_store, params
):
    """
    Register a signed statement in the SCITT CCF ledger and verify the resulting transparent statement.
    """
    identity = trusted_ca.create_identity(**params)

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})
    transparent_statement = client.register_signed_statement(
        signed_statement
    ).response_bytes
    verify_transparent_statement(transparent_statement, trust_store, signed_statement)


@pytest.mark.isolated_test
def test_recovery(client, trusted_ca, trust_store, restart_service, tmp_path):
    identity = trusted_ca.create_identity(alg="PS384", kty="rsa")

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})

    transparent_statement = client.register_signed_statement(
        signed_statement
    ).response_bytes
    verify_transparent_statement(transparent_statement, trust_store, signed_statement)

    old_network = client.get("/node/network").json()
    assert old_network["recovery_count"] == 0

    restart_service()

    new_network = client.get("/node/network").json()
    assert new_network["recovery_count"] == 1
    assert new_network["service_certificate"] != old_network["service_certificate"]

    with open(tmp_path / "params.json", "w") as f:
        f.write(client.get("/parameters").text)
    new_trust_store = StaticTrustStore.load(tmp_path)

    signed_statement = crypto.sign_json_statement(identity, {"foo": "baz"})

    transparent_statement = client.register_signed_statement(
        signed_statement
    ).response_bytes
    verify_transparent_statement(
        transparent_statement, new_trust_store, signed_statement
    )
