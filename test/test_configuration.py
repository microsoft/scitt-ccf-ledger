# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64

import httpx
import pycose
import pytest

from infra.did_web_server import DIDWebServer
from pyscitt import crypto
from pyscitt.client import Client, ServiceError
from pyscitt.did import Resolver, did_web_document_url
from pyscitt.receipt import Receipt
from pyscitt.verify import DIDResolverTrustStore, verify_receipt


class TestAcceptedAlgorithms:
    def not_allowed(self, f):
        with pytest.raises(ServiceError, match="InvalidInput: Unsupported algorithm"):
            f()

    @pytest.fixture
    def submit(self, client: Client, did_web: DIDWebServer):
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

    def test_reject_all_issuers(self, client: Client, configure_service, claims):
        # Start with a configuration with no accepted issuers.
        # The service should reject anything we submit to it.
        configure_service({"policy": {"accepted_did_issuers": []}})
        self.not_allowed(lambda: client.submit_claim(claims))

    def test_wrong_accepted_issuer(self, client: Client, configure_service, claims):
        # Add just one issuer to the policy. Claims signed not with this
        # issuer are rejected.
        configure_service({"policy": {"accepted_did_issuers": ["else"]}})
        self.not_allowed(lambda: client.submit_claim(claims))

    def test_allow_any_issuer(self, client: Client, configure_service, claims):
        # If no accepted_issuers are defined in the policy, any issuers
        # are accepted.
        configure_service({"policy": {}})
        client.submit_claim(claims)

    def test_valid_issuer(self, client: Client, configure_service, identity, claims):
        # Add just one issuer to the policy. Claims signed with this
        # issuer are accepted.
        configure_service({"policy": {"accepted_did_issuers": [identity.issuer]}})
        client.submit_claim(claims)

    def test_multiple_accepted_issuers(
        self, client: Client, configure_service, identity, claims
    ):
        # Add multiple issuers to the policy. Claims signed with this
        # issuer are accepted.
        configure_service(
            {"policy": {"accepted_did_issuers": [identity.issuer, "else"]}}
        )
        client.submit_claim(claims)


def test_service_identifier(
    client: Client,
    service_identifier: str,
    did_web: DIDWebServer,
):
    identity = did_web.create_identity()
    claim = crypto.sign_json_claimset(identity, {"foo": "bar"})

    # Receipts include an issuer and kid.
    receipt = client.submit_claim(claim).receipt
    assert receipt.phdr[crypto.COSE_HEADER_PARAM_ISSUER] == service_identifier
    assert pycose.headers.KID in receipt.phdr

    trust_store = DIDResolverTrustStore(Resolver(verify=False))
    verify_receipt(claim, trust_store, receipt)


def test_without_service_identifier(
    client: Client,
    configure_service,
    service_identifier: str,
    did_web: DIDWebServer,
):
    identity = did_web.create_identity()
    claim = crypto.sign_json_claimset(identity, {"foo": "bar"})

    # The test framework automatically configures the service with a DID.
    # Reconfigure the service to disable it.
    configure_service({"service_identifier": None})

    url = did_web_document_url(service_identifier)
    assert httpx.get(url, verify=False).status_code == 404

    # The receipts it returns have no issuer or kid.
    receipt = client.submit_claim(claim).receipt
    assert crypto.COSE_HEADER_PARAM_ISSUER not in receipt.phdr
    assert pycose.headers.KID not in receipt.phdr


def test_consistent_jwk(client, service_identifier):
    doc = Resolver(verify=False).resolve(service_identifier)
    assert len(doc["assertionMethod"]) > 0

    # Each assertionMethod contains both a bare public key, and an X509
    # certificate, which should contain the same public key. This checks that
    # the two keys are actually the same.
    for method in doc["assertionMethod"]:
        jwk = method["publicKeyJwk"]
        key = crypto.convert_jwk_to_pem(jwk)

        assert len(jwk["x5c"]) == 1
        certificate = crypto.cert_der_to_pem(base64.b64decode(jwk["x5c"][0]))
        cert_key = crypto.get_cert_public_key(certificate)

        assert crypto.pub_key_pem_to_der(key) == crypto.pub_key_pem_to_der(cert_key)


@pytest.mark.needs_cchost
@pytest.mark.isolated_test
def test_did_multiple_service_keys(
    client: Client,
    did_web: DIDWebServer,
    restart_service,
    service_identifier: str,
):
    resolver = Resolver(verify=False)
    trust_store = DIDResolverTrustStore(resolver)

    # Initially the DID document only has a single assertion method
    did_doc = resolver.resolve(service_identifier)
    assert len(did_doc["assertionMethod"]) == 1
    old_assertion_method = did_doc["assertionMethod"][0]

    # Create a claim and get a receipt before the service is restarted.
    identity = did_web.create_identity()
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    receipt = client.submit_claim(claims).receipt
    verify_receipt(claims, trust_store, receipt)

    restart_service()

    did_doc = resolver.resolve(service_identifier)
    assert len(did_doc["assertionMethod"]) == 2
    assert old_assertion_method in did_doc["assertionMethod"]

    # Thanks to the DID document containing all past service identities, the
    # old receipt can still be verified even though the current identity has
    # changed.
    verify_receipt(claims, trust_store, receipt)

    # We can also get new receipts, which will use the new identity, and these
    # can also be verified.
    new_receipt = client.submit_claim(claims).receipt
    verify_receipt(claims, trust_store, new_receipt)
