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


def test_accepted_algorithms(tmp_path: Path):
    def not_allowed(f):
        with pytest.raises(ServiceError, match="InvalidInput: Unsupported algorithm"):
            f()

    with SCITTFixture(tmp_path) as fixture:

        def submit(**kwargs):
            """Sign and submit the claims with a new identity"""
            identity = fixture.did_web_server.create_identity(**kwargs)
            claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
            fixture.client.submit_claim(claims)

        # Start with a configuration with no accepted algorithms.
        # The service should reject anything we submit to it.
        fixture.configure_service({"policy": {"accepted_algorithms": []}})
        not_allowed(lambda: submit(alg="ES256", kty="ec", ec_curve="P-256"))
        not_allowed(lambda: submit(alg="ES384", kty="ec", ec_curve="P-384"))
        not_allowed(lambda: submit(alg="PS256", kty="rsa"))

        # Add just one algorithm to the policy. Claims signed with this
        # algorithm are accepted but not the others.
        fixture.configure_service({"policy": {"accepted_algorithms": ["ES256"]}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        not_allowed(lambda: submit(alg="ES384", kty="ec", ec_curve="P-384"))
        not_allowed(lambda: submit(alg="PS256", kty="rsa"))

        # If no accepted_algorithms are defined in the policy, any algorithm
        # is accepted.
        fixture.configure_service({"policy": {}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        submit(alg="ES384", kty="ec", ec_curve="P-384")
        submit(alg="PS256", kty="rsa")


def test_accepted_did_issuers(tmp_path: Path):
    def not_allowed(f):
        with pytest.raises(ServiceError, match="InvalidInput: Unsupported did issuer in protected header"):
            f()

    with SCITTFixture(tmp_path) as fixture:

        def submit(**kwargs):
            """Sign and submit the claims with a new identity"""
            identity = fixture.did_web_server.create_identity(**kwargs)
            claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
            fixture.client.submit_claim(claims)

        # Start with a configuration with no accepted issuers.
        # The service should reject anything we submit to it.
        fixture.configure_service({"policy": {"accepted_did_issuers": []}})
        not_allowed(lambda: submit(alg="ES256", kty="ec", ec_curve="P-256"))

        # Add just one issuer to the policy. Claims signed with this
        # issuers are accepted.
        identity = fixture.did_web_server.create_identity(alg="ES256", kty="ec", ec_curve="P-256")
        claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
        fixture.configure_service({"policy": {"accepted_did_issuers": [identity.issuer]}})
        fixture.client.submit_claim(claims)

        # Add just one issuers to the policy. Claims signed not with this
        # issuers are rejected.
        fixture.configure_service({"policy": {"accepted_did_issuers": ["else"]}})
        not_allowed(lambda: submit(alg="ES256", kty="ec", ec_curve="P-256"))

        # If no accepted_issuers are defined in the policy, any issuers
        # is accepted.
        fixture.configure_service({"policy": {}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
