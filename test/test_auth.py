# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.jwt_issuer import JwtIssuer


class TestAuthentication:
    @pytest.fixture(scope="class")
    def claim(self, trusted_ca):
        identity = trusted_ca.create_identity(alg="PS384", kty="rsa")
        return crypto.sign_json_statement(identity, {"foo": "bar"})

    @pytest.fixture(scope="class")
    def valid_issuer(self, client):
        issuer = JwtIssuer()
        client.governance.propose(issuer.create_proposal(), must_pass=True)
        return issuer

    @pytest.fixture(scope="class")
    def invalid_issuer(self):
        return JwtIssuer()

    @pytest.fixture
    def setup(self, configure_service):
        def f(*, allow_unauthenticated: bool, required_claims=None):
            configure_service(
                {
                    "authentication": {
                        "allow_unauthenticated": allow_unauthenticated,
                        "jwt": {"required_claims": required_claims},
                    }
                }
            )

        return f

    @pytest.fixture
    def submit(self, client: Client, claim: bytes):
        def f(**kwargs):
            client.replace(**kwargs).submit_claim_and_confirm(claim)

        return f

    def test_closed_off_service(self, setup, submit, valid_issuer, invalid_issuer):
        # Start off with a fully closed off service.
        setup(allow_unauthenticated=False)

        with service_error("InvalidAuthenticationInfo"):
            submit()

        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=valid_issuer.create_token())

        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=invalid_issuer.create_token())

    def test_no_required_jwt_claims(self, setup, submit, valid_issuer, invalid_issuer):
        # Enable JWT with no required claims.
        setup(allow_unauthenticated=False, required_claims={})

        submit(auth_token=valid_issuer.create_token())

        with service_error("InvalidAuthenticationInfo"):
            submit()

        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=invalid_issuer.create_token())

    def test_require_jwt_claims(self, setup, submit, valid_issuer, invalid_issuer):
        # Enable JWT with a required "aud" claims.
        setup(allow_unauthenticated=False, required_claims={"aud": "foo"})

        submit(auth_token=valid_issuer.create_token({"aud": "foo"}))
        submit(auth_token=valid_issuer.create_token({"aud": "foo", "iat": 1234567}))

        with service_error("InvalidAuthenticationInfo"):
            submit()

        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=valid_issuer.create_token())

        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=valid_issuer.create_token({"aud": "bar"}))

        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=invalid_issuer.create_token({"aud": "foo"}))

    def test_allow_anything(self, setup, submit, valid_issuer, invalid_issuer):
        # Allow anything
        setup(allow_unauthenticated=True)

        submit()
        submit(auth_token=valid_issuer.create_token())
        submit(auth_token=invalid_issuer.create_token())
