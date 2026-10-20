# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from pyscitt import crypto
from pyscitt.client import Client

from .constants import MAX_UNAUTHENTICATED_ENTRY_SIZE_BYTES
from .infra.assertions import service_error
from .infra.jwt_issuer import JwtIssuer


def configure_authentication(
    configure_service,
    *,
    allow_unauthenticated: bool,
    required_claims=None,
    jwt_schema=None,
    allow_unauthenticated_reads=None,
):
    jwt_config = (
        jwt_schema if jwt_schema is not None else {"requiredClaims": required_claims}
    )
    auth_config = {
        "allowUnauthenticated": allow_unauthenticated,
        "jwt": jwt_config,
    }
    if allow_unauthenticated_reads is not None:
        auth_config["allowUnauthenticatedReads"] = allow_unauthenticated_reads
    configure_service(
        {
            "authentication": auth_config,
            "policy": {"policyScript": "export function apply(phdr) { return true; }"},
        }
    )


def claims_schema(required_claims, alternatives):
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {key: {"const": value} for key, value in required_claims.items()},
        "required": list(required_claims),
    }
    if alternatives is not None:
        schema["anyOf"] = [
            {
                "properties": {key: {"const": value} for key, value in claims.items()},
                "required": list(claims),
            }
            for claims in alternatives
        ]
    return schema


def application_read_requests(client: Client, tx: str):
    return {
        "entry receipt": lambda: client.get_receipt(tx),
        "transparent statement": lambda: client.get_transparent_statement(tx),
        "transaction ID enumeration": lambda: client.get("/entries/txIds"),
        "operation status": lambda: client.get(f"/operations/{tx}"),
    }


def assert_application_reads_succeed(client: Client, tx: str):
    for request in application_read_requests(client, tx).values():
        request()


def assert_application_reads_require_authentication(client: Client, tx: str):
    for request in application_read_requests(client, tx).values():
        with service_error("InvalidAuthenticationInfo"):
            request()


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
        def f(**kwargs):
            configure_authentication(configure_service, **kwargs)

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

    def test_schema_jwt_claims(self, setup, submit, valid_issuer, invalid_issuer):
        setup(
            allow_unauthenticated=False,
            jwt_schema=claims_schema(
                {"aud": "scitt", "iss": valid_issuer.name},
                [
                    {"appid": "identity-a", "tid": "tenant-a"},
                    {"appid": "identity-b", "tid": "tenant-b"},
                ],
            ),
        )

        for appid, tid in (("identity-a", "tenant-a"), ("identity-b", "tenant-b")):
            submit(
                auth_token=valid_issuer.create_token(
                    {"aud": "scitt", "appid": appid, "tid": tid}
                )
            )

        for claims in (
            {"aud": "scitt"},
            {"aud": "scitt", "appid": "identity-a"},
            {"aud": "scitt", "appid": "identity-a", "tid": "tenant-b"},
            {"aud": "scitt", "appid": "identity-b", "tid": "tenant-a"},
            {"aud": "scitt", "appid": "identity-c", "tid": "tenant-a"},
            {"aud": "other", "appid": "identity-a", "tid": "tenant-a"},
        ):
            with service_error("InvalidAuthenticationInfo"):
                submit(auth_token=valid_issuer.create_token(claims))

        with service_error("InvalidAuthenticationInfo"):
            submit(
                auth_token=invalid_issuer.create_token(
                    {"aud": "scitt", "appid": "identity-a", "tid": "tenant-a"}
                )
            )

        setup(
            allow_unauthenticated=False,
            jwt_schema=claims_schema(
                {"aud": "scitt"}, [{"appid": "identity-a"}, {"tid": "tenant-a"}]
            ),
        )
        submit(
            auth_token=valid_issuer.create_token(
                {"aud": "scitt", "appid": "identity-a", "tid": "tenant-a"}
            )
        )

    def test_schema_with_multiple_issuers(
        self, setup, client: Client, signed_statement, valid_issuer
    ):
        issuer_a = JwtIssuer("https://tenant-a.example.com")
        issuer_b = JwtIssuer("https://tenant-b.example.com")
        for issuer in (issuer_a, issuer_b):
            client.governance.propose(issuer.create_proposal(), must_pass=True)

        setup(
            allow_unauthenticated=False,
            jwt_schema=claims_schema(
                {"aud": "scitt"},
                [
                    {"iss": issuer_a.name, "azp": "identity-a", "tid": "tenant-a"},
                    {"iss": issuer_b.name, "azp": "identity-b", "tid": "tenant-b"},
                ],
            ),
        )

        for issuer, azp, tid in (
            (issuer_a, "identity-a", "tenant-a"),
            (issuer_b, "identity-b", "tenant-b"),
        ):
            token = issuer.create_token({"aud": "scitt", "azp": azp, "tid": tid})
            authenticated_client = client.replace(auth_token=token)
            tx = authenticated_client.submit_signed_statement_and_wait(
                signed_statement
            ).tx
            assert_application_reads_succeed(authenticated_client, tx)
            assert_application_reads_require_authentication(client, tx)

        for issuer, azp, tid in (
            (issuer_a, "identity-b", "tenant-b"),
            (issuer_b, "identity-a", "tenant-a"),
            (valid_issuer, "identity-a", "tenant-a"),
        ):
            token = issuer.create_token({"aud": "scitt", "azp": azp, "tid": tid})
            with service_error("InvalidAuthenticationInfo"):
                client.replace(auth_token=token).submit_signed_statement_and_wait(
                    signed_statement
                )
            assert_application_reads_require_authentication(
                client.replace(auth_token=token), tx
            )

    def test_schema_switch_preserves_existing_claim_checks(
        self, setup, submit, valid_issuer
    ):
        token_a = valid_issuer.create_token({"aud": "scitt", "azp": "identity-a"})
        token_b = valid_issuer.create_token({"aud": "scitt", "azp": "identity-b"})
        setup(allow_unauthenticated=False, required_claims={"aud": "scitt"})
        submit(auth_token=token_a)
        submit(auth_token=token_b)

        setup(
            allow_unauthenticated=False,
            jwt_schema=claims_schema({"aud": "scitt", "azp": "identity-a"}, None),
        )
        submit(auth_token=token_a)
        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=token_b)

        setup(
            allow_unauthenticated=False,
            jwt_schema=claims_schema({"aud": "scitt", "azp": "identity-b"}, None),
        )
        submit(auth_token=token_b)
        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=token_a)

        setup(allow_unauthenticated=False, required_claims={"aud": "scitt"})
        submit(auth_token=token_a)
        submit(auth_token=token_b)

    @pytest.mark.parametrize(
        "invalid_schema",
        [
            claims_schema({"aud": "scitt"}, []),
            claims_schema({}, [{}]),
            claims_schema({}, None),
            {**claims_schema({"aud": "scitt"}, None), "type": "array"},
            {**claims_schema({"aud": "scitt"}, None), "patternProperties": {}},
            {**claims_schema({"aud": "scitt"}, None), "required": []},
            {**claims_schema({"aud": "scitt"}, None), "required": ["missing"]},
            {
                **claims_schema({"aud": "scitt"}, None),
                "required": ["aud", "aud"],
            },
            {
                **claims_schema({"aud": "scitt"}, None),
                "properties": {"aud": {"type": "string"}},
            },
            {
                **claims_schema({"aud": "scitt"}, None),
                "properties": {"aud": {"const": "scitt", "type": "string"}},
            },
            {
                **claims_schema({"aud": "scitt"}, None),
                "anyOf": [True],
            },
            {
                **claims_schema({"aud": "scitt"}, None),
                "$schema": "https://json-schema.org/draft/2020-12/schema",
            },
            {**claims_schema({"aud": "scitt"}, None), "requiredClaims": {}},
        ],
    )
    def test_reject_invalid_schema(self, setup, submit, valid_issuer, invalid_schema):
        setup(allow_unauthenticated=False, required_claims={"aud": "scitt"})
        with service_error("configuration.authentication.jwt"):
            setup(
                allow_unauthenticated=False,
                jwt_schema=invalid_schema,
            )
        submit(auth_token=valid_issuer.create_token({"aud": "scitt"}))
        with service_error("InvalidAuthenticationInfo"):
            submit(auth_token=valid_issuer.create_token({"aud": "other"}))

    def test_reject_schema_without_dialect(self, configure_service):
        with service_error(r"\$schema"):
            configure_service(
                {
                    "authentication": {
                        "jwt": {
                            "requiredClaims": {},
                            "anyOf": [
                                {
                                    "properties": {"aud": {"const": "scitt"}},
                                    "required": ["aud"],
                                }
                            ],
                        }
                    }
                }
            )

    def test_reject_retired_any_of_claims(self, configure_service):
        with service_error("anyOfClaims"):
            configure_service(
                {
                    "authentication": {
                        "jwt": {
                            "requiredClaims": {},
                            "anyOfClaims": [{"appid": "identity-a"}],
                        }
                    }
                }
            )

    def test_allow_anything(self, setup, submit, valid_issuer, invalid_issuer):
        # Allow anything
        setup(allow_unauthenticated=True)

        submit()
        submit(auth_token=valid_issuer.create_token())
        submit(auth_token=invalid_issuer.create_token())

    @pytest.mark.parametrize(
        "body_size, supply_token, expected_error",
        [
            (MAX_UNAUTHENTICATED_ENTRY_SIZE_BYTES, False, "InvalidInput"),
            (MAX_UNAUTHENTICATED_ENTRY_SIZE_BYTES + 1, False, "PayloadTooLarge"),
            (MAX_UNAUTHENTICATED_ENTRY_SIZE_BYTES + 1, True, "PayloadTooLarge"),
        ],
    )
    def test_unauthenticated_statement_size_limit(
        self,
        setup,
        client: Client,
        valid_issuer,
        body_size,
        supply_token,
        expected_error,
    ):
        setup(allow_unauthenticated=True, required_claims={})
        if supply_token:
            client = client.replace(auth_token=valid_issuer.create_token())

        with service_error(expected_error):
            client.submit_signed_statement(b"\x00" * body_size)


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
        def f(**kwargs):
            configure_authentication(configure_service, **kwargs)

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

        # Reads without JWT should also fail (inherits allowUnauthenticated=false)
        assert_application_reads_require_authentication(client, tx)

        # Reads with JWT should succeed
        assert_application_reads_succeed(
            client.replace(auth_token=valid_issuer.create_token()), tx
        )

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

        # Selected reads should succeed without JWT.
        assert_application_reads_succeed(client, tx)

    def test_application_endpoints_require_jwt(
        self, setup, client: Client, signed_statement, valid_issuer
    ):
        """
        When both allowUnauthenticated and allowUnauthenticatedReads are false,
        statement registration and selected retrieval endpoints require JWT.
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

        # Reads without JWT should fail
        assert_application_reads_require_authentication(client, tx)

        # Reads with JWT should succeed
        assert_application_reads_succeed(
            client.replace(auth_token=valid_issuer.create_token()), tx
        )

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

        # Both writes and selected reads should succeed without JWT.
        tx = client.submit_signed_statement_and_wait(signed_statement).tx
        assert_application_reads_succeed(client, tx)

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

        # Reads without JWT should also fail (backward compat)
        assert_application_reads_require_authentication(client, tx)

        # Reads with the configured JWT should succeed.
        assert_application_reads_succeed(
            client.replace(auth_token=valid_issuer.create_token({"aud": "compat"})),
            tx,
        )
