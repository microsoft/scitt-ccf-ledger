# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pathlib import Path

import pytest

from infra.fixtures import SCITTFixture
from pyscitt import crypto
from pyscitt.client import ServiceError

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

        """Sign and submit the claims with a new identity"""
        identity = fixture.did_web_server.create_identity()
        claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

        # Start with a configuration with no accepted issuers.
        # The service should reject anything we submit to it.
        fixture.configure_service({"policy": {"accepted_did_issuer": []}})
        not_allowed(lambda: fixture.client.submit_claim(claims))

        # Add just one issuer to the policy. Claims signed not with this
        # issuer are rejected.
        fixture.configure_service({"policy": {"accepted_did_issuer": ["else"]}})
        not_allowed(lambda: fixture.client.submit_claim(claims))

        # If no accepted_issuers are defined in the policy, any issuers
        # are accepted.
        fixture.configure_service({"policy": {}})
        fixture.client.submit_claim(claims)

        # Add just one issuer to the policy. Claims signed with this
        # issuer are accepted.
        fixture.configure_service({"policy": {"accepted_did_issuer": [identity.issuer]}})
        fixture.client.submit_claim(claims)

        # Add multiple issuers to the policy. Claims signed with this
        # issuer are accepted.
        fixture.configure_service({"policy": {"accepted_did_issuer": [identity.issuer, "else"]}})
        fixture.client.submit_claim(claims)