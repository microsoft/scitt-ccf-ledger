# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pathlib import Path

import pycose
import pytest

from infra.did_web_server import DIDWebServer
from pyscitt import crypto
from pyscitt.client import ServiceError


class TestAcceptedAlgorithms:
    def not_allowed(self, f):
        with pytest.raises(ServiceError, match="InvalidInput: Unsupported algorithm"):
            f()

    @pytest.fixture
    def submit(self, client, did_web: DIDWebServer):
        def f(**kwargs):
            """Sign and submit the claims with a new identity"""
            identity = did_web.create_identity(**kwargs)
            claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
            client.submit_claim(claims)

        return f

    def test_reject_everything(self, configure_service, submit):
        # Configure the service with no accepted algorithms.
        # The service should reject anything we submit to it.
        configure_service({"policy": {"accepted_algorithms": []}})
        self.not_allowed(lambda: submit(alg="ES256", kty="ec", ec_curve="P-256"))
        self.not_allowed(lambda: submit(alg="ES384", kty="ec", ec_curve="P-384"))
        self.not_allowed(lambda: submit(alg="PS256", kty="rsa"))

    def test_allow_select_algorithm(self, configure_service, submit):
        # Add just one algorithm to the policy. Claims signed with this
        # algorithm are accepted but not the others.
        configure_service({"policy": {"accepted_algorithms": ["ES256"]}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        self.not_allowed(lambda: submit(alg="ES384", kty="ec", ec_curve="P-384"))
        self.not_allowed(lambda: submit(alg="PS256", kty="rsa"))

    def test_default_allows_anything(self, configure_service, submit):
        # If no accepted_algorithms are defined in the policy, any algorithm
        # is accepted.
        configure_service({"policy": {}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        submit(alg="ES384", kty="ec", ec_curve="P-384")
        submit(alg="PS256", kty="rsa")


class TestAcceptedDIDIssuers:
    def not_allowed(self, f):
        with pytest.raises(
            ServiceError,
            match="InvalidInput: Unsupported DID issuer in protected header",
        ):
            f()

    @pytest.fixture(scope="class")
    def identity(self, did_web):
        return did_web.create_identity()

    @pytest.fixture(scope="class")
    def claims(self, identity):
        return crypto.sign_json_claimset(identity, {"foo": "bar"})

    def test_reject_all_issuers(self, client, configure_service, claims):
        # Start with a configuration with no accepted issuers.
        # The service should reject anything we submit to it.
        configure_service({"policy": {"accepted_did_issuers": []}})
        self.not_allowed(lambda: client.submit_claim(claims))

    def test_wrong_accepted_issuer(self, client, configure_service, claims):
        # Add just one issuer to the policy. Claims signed not with this
        # issuer are rejected.
        configure_service({"policy": {"accepted_did_issuers": ["else"]}})
        self.not_allowed(lambda: client.submit_claim(claims))

    def test_allow_any_issuer(self, client, configure_service, claims):
        # If no accepted_issuers are defined in the policy, any issuers
        # are accepted.
        configure_service({"policy": {}})
        client.submit_claim(claims)

    def test_valid_issuer(self, client, configure_service, identity, claims):
        # Add just one issuer to the policy. Claims signed with this
        # issuer are accepted.
        configure_service({"policy": {"accepted_did_issuers": [identity.issuer]}})
        client.submit_claim(claims)

    def test_multiple_accepted_issuers(
        self, client, configure_service, identity, claims
    ):
        # Add multiple issuers to the policy. Claims signed with this
        # issuer are accepted.
        configure_service(
            {"policy": {"accepted_did_issuers": [identity.issuer, "else"]}}
        )
        client.submit_claim(claims)


class TestServiceIdentifier:
    @pytest.fixture
    def claim(self, did_web):
        identity = did_web.create_identity()
        return crypto.sign_json_claimset(identity, {"foo": "bar"})

    def test_without_identifier(self, client, configure_service, claim):
        configure_service({})

        # By default, the service runs without a configured identity.
        # The receipts it returns have no issuer or kid.
        receipt = client.submit_claim(claim).receipt
        assert crypto.COSE_HEADER_PARAM_ISSUER not in receipt.phdr
        assert pycose.headers.KID not in receipt.phdr

    def test_with_identifier(self, client, configure_service, claim):
        parameters = client.get_parameters()
        service_identifier = "did:web:ledger.example.com"
        configure_service({"service_identifier": service_identifier})

        # If a service identifier is configured, issued receipts include an issuer
        # and kid.
        # Somewhat confusingly, what the old `/parameters` endpoint calls the
        # "service identity" is used as a KID in the receipts.
        receipt = client.submit_claim(claim).receipt
        assert receipt.phdr[crypto.COSE_HEADER_PARAM_ISSUER] == service_identifier
        assert (
            receipt.phdr[pycose.headers.KID].decode("ascii") == parameters["serviceId"]
        )
