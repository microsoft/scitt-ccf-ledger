# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from pathlib import Path

import pytest

from infra.fixtures import SCITTFixture
from infra.x5chain_certificate_authority import X5ChainCertificateAuthority
from pyscitt import crypto
from pyscitt.client import ServiceError


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256"},
        {"alg": "ES384", "kty": "ec", "ec_curve": "P-384"},
        {"alg": "ES512", "kty": "ec", "ec_curve": "P-521"},
        {"alg": "PS256", "kty": "rsa"},
        {"alg": "PS384", "kty": "rsa"},
        {"alg": "PS512", "kty": "rsa"},
        {"alg": "EdDSA", "kty": "ed25519"},
    ],
)
def test_submit_claim(tmp_path: Path, params: dict):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts.

    Test is parametrized over different signing parameters.
    """
    with SCITTFixture(tmp_path) as fixture:
        identity = fixture.did_web_server.create_identity(**params)

        # Sign and submit a dummy claim using our new identity
        claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
        receipt = fixture.client.submit_claim(claims, decode=False).receipt

        crypto.verify_cose_with_receipt(claims, fixture.trust_store, receipt)

        embedded = crypto.embed_receipt_in_cose(claims, receipt)
        crypto.verify_cose_with_receipt(embedded, fixture.trust_store, None)


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "PS384", "kty": "rsa", "x5c_len": 1},
        {"alg": "PS384", "kty": "rsa", "x5c_len": 2},
        {"alg": "PS384", "kty": "rsa", "x5c_len": 3},
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256", "x5c_len": 1},
    ],
)
def test_submit_claim_x5c(tmp_path: Path, params: dict):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts for x5c.

    Test is parametrized over different signing parameters.
    """

    def not_allowed(f):
        with pytest.raises(ServiceError, match="Signature verification failed"):
            f()

    x5c_len = params.pop("x5c_len")
    x5c_ca = X5ChainCertificateAuthority(**params)
    x5c_identity = x5c_ca.create_identity(x5c_len, **params)

    with SCITTFixture(tmp_path, x5c_ca=x5c_ca) as fixture:
        # Sign and submit a dummy claim using our new identity
        claims = crypto.sign_json_claimset(x5c_identity, {"foo": "bar"})
        receipt = fixture.client.submit_claim(claims, decode=False).receipt
        crypto.verify_cose_with_receipt(claims, fixture.trust_store, receipt)

        # x5c chain missing cert
        if x5c_len > 1:
            x5c_identity.x5c = x5c_identity.x5c[1:]
            claims = crypto.sign_json_claimset(x5c_identity, {"foo": "bar"})
            not_allowed(
                lambda: fixture.client.submit_claim(claims, decode=False).receipt
            )


def test_default_did_port(tmp_path: Path):
    """
    Submit a claim using a DID web server running on the default port 443.

    This test may require elevated priviledges to run, either as root or with
    CAP_NET_BIND_SERVICE. Unless the SCITT_CI environment variable is set, the
    test will be skipped if the port could not be bound.
    """

    try:
        fixture = SCITTFixture(tmp_path, use_default_did_port=True)
    except PermissionError:
        if os.environ.get("SCITT_CI"):
            raise
        else:
            pytest.skip("Could not bind priviledged port")

    with fixture:
        identity = fixture.did_web_server.create_identity()

        # Sign and submit a dummy claim using our new identity
        claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
        receipt = fixture.client.submit_claim(claims, decode=False).receipt
        crypto.verify_cose_with_receipt(claims, fixture.trust_store, receipt)
