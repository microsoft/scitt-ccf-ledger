# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.jwt_issuer import JwtIssuer


class TestAuthentication:
    @pytest.fixture(scope="class")
    def signed_statement(self, cert_authority):
        identity = cert_authority.create_identity(
            alg="PS384", kty="rsa", add_eku="2.999"
        )
        return crypto.sign_json_statement(identity, {"foo": "bar"}, cwt=True)

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
        def f(
            *,
            allow_unauthenticated: bool,
            required_claims=None,
            allow_unauthenticated_reads=None,
        ):
            auth_config = {
                "allowUnauthenticated": allow_unauthenticated,
                "jwt": {"requiredClaims": required_claims},
            }
            if allow_unauthenticated_reads is not None:
                auth_config["allowUnauthenticatedReads"] = allow_unauthenticated_reads
            configure_service(
                {
                    "authentication": auth_config,
                    "policy": {
                        "policyScript": "export function apply(phdr) { return true; }"
                    },
                }
            )

        return f

    @pytest.fixture
    def submit(self, client: Client, signed_statement: bytes):
        def f(**kwargs):
            client.replace(**kwargs).submit_signed_statement_and_wait(signed_statement)

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


class TestPerEndpointAuthentication:
    """
    Tests for the allowUnauthenticatedReads configuration option, which
    enables a split auth model where writes require JWT while reads are open.
    """

    @pytest.fixture(scope="class")
    def signed_statement(self, cert_authority):
        identity = cert_authority.create_identity(
            alg="PS384", kty="rsa", add_eku="2.999"
        )
        return crypto.sign_json_statement(identity, {"foo": "bar"}, cwt=True)

    @pytest.fixture(scope="class")
    def valid_issuer(self, client):
        issuer = JwtIssuer()
        client.governance.propose(issuer.create_proposal(), must_pass=True)
        return issuer

    @pytest.fixture
    def setup(self, configure_service):
        def f(
            *,
            allow_unauthenticated: bool,
            required_claims=None,
            allow_unauthenticated_reads=None,
        ):
            auth_config = {
                "allowUnauthenticated": allow_unauthenticated,
                "jwt": {"requiredClaims": required_claims},
            }
            if allow_unauthenticated_reads is not None:
                auth_config["allowUnauthenticatedReads"] = allow_unauthenticated_reads
            configure_service(
                {
                    "authentication": auth_config,
                    "policy": {
                        "policyScript": "export function apply(phdr) { return true; }"
                    },
                }
            )

        return f

    def test_default_inherits_allow_unauthenticated(
        self, setup, client: Client, signed_statement, valid_issuer
    ):
        """
        When allowUnauthenticatedReads is not set, reads should inherit
        the value of allowUnauthenticated (ie. existing behavior).
        """
        # With JWT required and no allowUnauthenticatedReads set,
        # both reads and writes should require JWT.
        setup(allow_unauthenticated=False, required_claims={})

        # Write without JWT should fail
        with service_error("InvalidAuthenticationInfo"):
            client.submit_signed_statement_and_wait(signed_statement)

        # Write with JWT should succeed
        tx = (
            client.replace(
                auth_token=valid_issuer.create_token()
            ).submit_signed_statement_and_wait(signed_statement)
        ).tx

        # Read without JWT should also fail (inherits allowUnauthenticated=false)
        with service_error("InvalidAuthenticationInfo"):
            client.get_receipt(tx)

        # Read with JWT should succeed
        client.replace(auth_token=valid_issuer.create_token()).get_receipt(tx)

    def test_unauthenticated_reads_with_jwt_writes(
        self, setup, client: Client, signed_statement, valid_issuer
    ):
        """
        When allowUnauthenticatedReads is true and JWT is configured,
        writes require JWT but reads are open.
        """
        setup(
            allow_unauthenticated=False,
            required_claims={},
            allow_unauthenticated_reads=True,
        )

        # Write without JWT should fail
        with service_error("InvalidAuthenticationInfo"):
            client.submit_signed_statement_and_wait(signed_statement)

        # Write with JWT should succeed
        tx = (
            client.replace(
                auth_token=valid_issuer.create_token()
            ).submit_signed_statement_and_wait(signed_statement)
        ).tx

        # Read without JWT should succeed (allowUnauthenticatedReads=true)
        client.get_receipt(tx)

    def test_all_endpoints_require_jwt(
        self, setup, client: Client, signed_statement, valid_issuer
    ):
        """
        When both allowUnauthenticated and allowUnauthenticatedReads are false,
        all endpoints require JWT.
        """
        setup(
            allow_unauthenticated=False,
            required_claims={},
            allow_unauthenticated_reads=False,
        )

        # Write without JWT should fail
        with service_error("InvalidAuthenticationInfo"):
            client.submit_signed_statement_and_wait(signed_statement)

        # Write with JWT should succeed
        tx = (
            client.replace(
                auth_token=valid_issuer.create_token()
            ).submit_signed_statement_and_wait(signed_statement)
        ).tx

        # Read without JWT should fail
        with service_error("InvalidAuthenticationInfo"):
            client.get_receipt(tx)

        # Read with JWT should succeed
        client.replace(auth_token=valid_issuer.create_token()).get_receipt(tx)

    def test_allow_unauthenticated_overrides_reads(
        self, setup, client: Client, signed_statement
    ):
        """
        When allowUnauthenticated is true, everything is open regardless
        of allowUnauthenticatedReads.
        """
        setup(
            allow_unauthenticated=True,
            allow_unauthenticated_reads=False,
        )

        # Both write and read should succeed without JWT
        tx = client.submit_signed_statement_and_wait(signed_statement).tx
        client.get_receipt(tx)

    def test_backward_compatibility_no_new_field(
        self, setup, client: Client, signed_statement, valid_issuer
    ):
        """
        When allowUnauthenticatedReads is not set at all in the config,
        behavior should be identical to pre-change: if allowUnauthenticated
        is false, both reads and writes are gated.
        """
        setup(allow_unauthenticated=False, required_claims={"aud": "compat"})

        # Write without correct JWT should fail
        with service_error("InvalidAuthenticationInfo"):
            client.submit_signed_statement_and_wait(signed_statement)

        # Write with correct JWT should succeed
        tx = (
            client.replace(
                auth_token=valid_issuer.create_token({"aud": "compat"})
            ).submit_signed_statement_and_wait(signed_statement)
        ).tx

        # Read without JWT should also fail (backward compat)
        with service_error("InvalidAuthenticationInfo"):
            client.get_receipt(tx)
