# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pathlib import Path

import pytest

from pyscitt import crypto
from pyscitt.client import Client, ServiceError

from .infra.jwt_issuer import JwtIssuer


class TestAuthentication:
    def not_allowed(self, f):
        with pytest.raises(ServiceError, match="InvalidAuthenticationInfo"):
            f()

    @pytest.fixture(scope="class")
    def claims(self, did_web):
        identity = did_web.create_identity()
        return crypto.sign_json_claimset(identity, {"foo": "bar"})

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
    def submit(self, client: Client, claims):
        def f(**kwargs):
            client.replace(**kwargs).submit_claim(claims)

        return f

    def test_closed_off_service(self, setup, submit, valid_issuer, invalid_issuer):
        # Start off with a fully closed off service.
        setup(allow_unauthenticated=False)

        self.not_allowed(lambda: submit())
        self.not_allowed(lambda: submit(auth_token=valid_issuer.create_token()))
        self.not_allowed(lambda: submit(auth_token=invalid_issuer.create_token()))

    def test_no_required_jwt_claims(self, setup, submit, valid_issuer, invalid_issuer):
        # Enable JWT with no required claims.
        setup(allow_unauthenticated=False, required_claims={})

        submit(auth_token=valid_issuer.create_token())
        self.not_allowed(lambda: submit())
        self.not_allowed(lambda: submit(auth_token=invalid_issuer.create_token()))

    def test_require_jwt_claims(self, setup, submit, valid_issuer, invalid_issuer):
        # Enable JWT with a required "aud" claims.
        setup(allow_unauthenticated=False, required_claims={"aud": "foo"})

        submit(auth_token=valid_issuer.create_token({"aud": "foo"}))
        submit(auth_token=valid_issuer.create_token({"aud": "foo", "iat": 1234567}))
        self.not_allowed(lambda: submit())
        self.not_allowed(lambda: submit(auth_token=valid_issuer.create_token()))
        self.not_allowed(
            lambda: submit(auth_token=valid_issuer.create_token({"aud": "bar"}))
        )
        self.not_allowed(
            lambda: submit(auth_token=invalid_issuer.create_token({"aud": "foo"}))
        )

    def test_allow_anything(self, setup, submit, valid_issuer, invalid_issuer):
        # Allow anything
        setup(allow_unauthenticated=True)

        submit()
        submit(auth_token=valid_issuer.create_token())
        submit(auth_token=invalid_issuer.create_token())
