# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pathlib import Path

import pytest

from infra.fixtures import SCITTFixture
from infra.jwt_issuer import JwtIssuer
from pyscitt import crypto
from pyscitt.client import ServiceError


def test_authentication(tmp_path: Path):
    with SCITTFixture(tmp_path) as fixture:
        identity = fixture.did_web_server.create_identity()
        claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

        def setup(*, allow_unauthenticated, required_claims=None):
            fixture.configure_service(
                {
                    "authentication": {
                        "allow_unauthenticated": allow_unauthenticated,
                        "jwt": {"required_claims": required_claims},
                    }
                }
            )

        def submit(**kwargs):
            fixture.client.replace(**kwargs).submit_claim(claims)

        def not_allowed(f):
            with pytest.raises(ServiceError, match="InvalidAuthenticationInfo"):
                f()

        # We create 2 JWT issuers. One is recognized by the service, the other
        # is not.
        valid_issuer = JwtIssuer()
        invalid_issuer = JwtIssuer()
        fixture.client.governance.propose(
            valid_issuer.create_proposal(), must_pass=True
        )

        # Start off with a fully closed off service.
        setup(allow_unauthenticated=False)
        not_allowed(lambda: submit())
        not_allowed(lambda: submit(auth_token=valid_issuer.create_token()))

        # Enable JWT with no required claims.
        setup(allow_unauthenticated=False, required_claims={})
        submit(auth_token=valid_issuer.create_token())
        not_allowed(lambda: submit())
        not_allowed(lambda: submit(auth_token=invalid_issuer.create_token()))

        # Enable JWT with a required "aud" claims.
        setup(allow_unauthenticated=False, required_claims={"aud": "foo"})
        submit(auth_token=valid_issuer.create_token({"aud": "foo"}))
        submit(auth_token=valid_issuer.create_token({"aud": "foo", "iat": 1234567}))
        not_allowed(lambda: submit())
        not_allowed(lambda: submit(auth_token=valid_issuer.create_token()))
        not_allowed(
            lambda: submit(auth_token=valid_issuer.create_token({"aud": "bar"}))
        )
        not_allowed(
            lambda: submit(auth_token=invalid_issuer.create_token({"aud": "foo"}))
        )

        # Allow anything
        setup(allow_unauthenticated=True)
        submit()
        submit(auth_token=valid_issuer.create_token())
        submit(auth_token=invalid_issuer.create_token())
