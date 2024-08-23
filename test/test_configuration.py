# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64

import httpx
import pycose
import pytest

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.did import Resolver, did_web_document_url
from pyscitt.verify import DIDResolverTrustStore, verify_receipt

from .infra.assertions import service_error
from .infra.did_web_server import DIDWebServer
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


class TestAcceptedAlgorithms:
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

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES256", kty="ec", ec_curve="P-256")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES384", kty="ec", ec_curve="P-384")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="PS256", kty="rsa")

    def test_allow_select_algorithm(self, configure_service, submit):
        # Add just one algorithm to the policy. Claims signed with this
        # algorithm are accepted but not the others.
        configure_service({"policy": {"accepted_algorithms": ["ES256"]}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES384", kty="ec", ec_curve="P-384")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="PS256", kty="rsa")

    def test_default_allows_anything(self, configure_service, submit):
        # If no accepted_algorithms are defined in the policy, any algorithm
        # is accepted.
        configure_service({"policy": {}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        submit(alg="ES384", kty="ec", ec_curve="P-384")
        submit(alg="PS256", kty="rsa")


class TestAcceptedDIDIssuers:
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

        with service_error("InvalidInput: Unsupported DID issuer in protected header"):
            client.submit_claim(claims)

    def test_wrong_accepted_issuer(self, client: Client, configure_service, claims):
        # Add just one issuer to the policy. Claims signed not with this
        # issuer are rejected.
        configure_service({"policy": {"accepted_did_issuers": ["else"]}})

        with service_error("InvalidInput: Unsupported DID issuer in protected header"):
            client.submit_claim(claims)

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


class TestPolicyEngine:
    @pytest.fixture(scope="class")
    def signed_claimset(self, trusted_ca: X5ChainCertificateAuthority):
        identity = trusted_ca.create_identity(alg="ES256", kty="ec")
        return crypto.sign_json_claimset(identity, {"foo": "bar"})

    def test_ietf_didx509_policy(
        self,
        client: Client,
        configure_service,
        trusted_ca: X5ChainCertificateAuthority,
        untrusted_ca: X5ChainCertificateAuthority,
        did_web,
    ):
        example_eku = "2.999"

        # We will apply a policy that only allows issuers endorsed by a specific trusted CA
        # and containing a specific EKU to be registered.
        identities = [
            untrusted_ca.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            trusted_ca.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            trusted_ca.create_identity(alg="ES256", kty="ec"),
            trusted_ca.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            trusted_ca.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            trusted_ca.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            trusted_ca.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
        ]

        def didx509_issuer(ca):
            root_cert = ca.cert_bundle
            root_fingerprint = crypto.get_cert_fingerprint_b64url(root_cert)
            return f"did:x509:0:sha256:{root_fingerprint}::eku:{example_eku}"

        identities[0].issuer = didx509_issuer(untrusted_ca)
        identities[1].issuer = didx509_issuer(trusted_ca)
        identities[2].issuer = didx509_issuer(trusted_ca)

        identities[3].issuer = didx509_issuer(trusted_ca).strip(
            example_eku
        )  # No EKU bits
        identities[4].issuer = didx509_issuer(trusted_ca).strip(
            f"::eku:{example_eku}"
        )  # No query
        identities[5].issuer = "did:x509:"  # Malformed
        identities[6].issuer = "not did"  # Not did

        feed = "SomeFeed"
        # SBOMs
        claims = {"foo": "bar"}

        permitted_signed_claims = [
            crypto.sign_json_claimset(identities[1], claims, feed=feed, cwt=True),
        ]

        profile_error = "This policy only accepts IETF did:x509 claims"
        invalid_issuer = "Invalid issuer"
        eku_not_found = "EKU not found"
        openssl_error = "OpenSSL error"
        invalid_did = "invalid DID string"
        not_supported = "Payloads with CWT_Claims must have a did:x509 iss and x5chain"

        # Keyed by expected error, values are lists of claimsets which should trigger this error
        refused_signed_claims = {
            # Well-constructed, but not a valid issuer
            invalid_issuer: [
                crypto.sign_json_claimset(identities[0], claims, feed=feed, cwt=True),
            ],
            eku_not_found: [
                crypto.sign_json_claimset(identities[2], claims, feed=feed, cwt=True),
            ],
            openssl_error: [
                crypto.sign_json_claimset(identities[3], claims, feed=feed, cwt=True),
            ],
            invalid_did: [
                crypto.sign_json_claimset(identities[4], claims, feed=feed, cwt=True),
                crypto.sign_json_claimset(identities[5], claims, feed=feed, cwt=True),
            ],
            not_supported: [
                crypto.sign_json_claimset(identities[6], claims, feed=feed, cwt=True),
            ],
        }

        policy_script = f"""
export function apply(profile, phdr) {{
    if (profile !== "IETF") {{ return "{profile_error}"; }}

    // Check exact issuer 
    if (phdr.cwt.iss !== "{didx509_issuer(trusted_ca)}") {{ return "Invalid issuer"; }}

    return true;
}}"""

        configure_service({"policy": {"policy_script": policy_script}})

        for signed_claimset in permitted_signed_claims:
            client.submit_claim(signed_claimset)

        for err, signed_claimsets in refused_signed_claims.items():
            for signed_claimset in signed_claimsets:
                with service_error(err):
                    client.submit_claim(signed_claimset)

    def test_svn_policy(
        self,
        client: Client,
        configure_service,
        trusted_ca: X5ChainCertificateAuthority,
        did_web,
    ):
        example_eku = "2.999"

        identity = trusted_ca.create_identity(
            alg="ES256", kty="ec", add_eku=example_eku
        )

        def didx509_issuer(ca):
            root_cert = ca.cert_bundle
            root_fingerprint = crypto.get_cert_fingerprint_b64url(root_cert)
            return f"did:x509:0:sha256:{root_fingerprint}::eku:{example_eku}"

        identity.issuer = didx509_issuer(trusted_ca)
        feed = "SomeFeed"
        # SBOMs
        claims = {"foo": "bar"}

        permitted_signed_claims = [
            crypto.sign_json_claimset(identity, claims, feed=feed, svn=1, cwt=True),
        ]

        profile_error = "This policy only accepts IETF did:x509 claims"
        invalid_svn = "Invalid SVN"

        # Keyed by expected error, values are lists of claimsets which should trigger this error
        refused_signed_claims = {
            # Well-constructed, but not a valid issuer
            invalid_svn: [
                crypto.sign_json_claimset(identity, claims, feed=feed, cwt=True),
                crypto.sign_json_claimset(
                    identity, claims, feed=feed, svn=-11, cwt=True
                ),
            ],
        }

        policy_script = f"""
export function apply(profile, phdr) {{
    if (profile !== "IETF") {{ return "{profile_error}"; }}

    // Check exact issuer 
    if (phdr.cwt.iss !== "{didx509_issuer(trusted_ca)}") {{ return "Invalid issuer"; }}
    if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}

    return true;
}}"""

        configure_service({"policy": {"policy_script": policy_script}})

        for signed_claimset in permitted_signed_claims:
            client.submit_claim(signed_claimset)

        for err, signed_claimsets in refused_signed_claims.items():
            for signed_claimset in signed_claimsets:
                with service_error(err):
                    client.submit_claim(signed_claimset)

    def test_trivial_pass_policy(
        self, client: Client, configure_service, signed_claimset
    ):
        configure_service(
            {"policy": {"policy_script": "export function apply() { return true }"}}
        )

        client.submit_claim(signed_claimset)

    def test_trivial_fail_policy(
        self, client: Client, configure_service, signed_claimset
    ):
        configure_service(
            {
                "policy": {
                    "policy_script": "export function apply() { return `All entries are refused`; }"
                }
            }
        )

        with service_error("Policy was not met"):
            client.submit_claim(signed_claimset)

    def test_exceptional_policy(
        self, client: Client, configure_service, signed_claimset
    ):
        configure_service(
            {
                "policy": {
                    "policy_script": 'export function apply() { throw new Error("Boom"); }'
                }
            }
        )

        with service_error("Error while applying policy"):
            client.submit_claim(signed_claimset)

    @pytest.mark.parametrize(
        "script",
        [
            "",
            "return true",
            "function apply() {}",
            "function apply() { not valid javascript }",
        ],
    )
    def test_invalid_policy(
        self, client: Client, configure_service, signed_claimset, script
    ):
        configure_service({"policy": {"policy_script": script}})

        with service_error("Invalid policy module"):
            client.submit_claim(signed_claimset)

    def test_cts_hashv_cwtclaims_payload_with_policy(
        self,
        client: Client,
        configure_service,
        trusted_ca: X5ChainCertificateAuthority,
        untrusted_ca: X5ChainCertificateAuthority,
        did_web,
    ):

        policy_script = f"""
export function apply(profile, phdr) {{
if (profile !== "IETF") {{ return "This policy only accepts IETF did:x509 claims"; }}

// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat < (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

return true;
}}"""

        configure_service({"policy": {"policy_script": policy_script}})

        with open("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rb") as f:
            cts_hashv_cwtclaims = f.read()

        client.submit_claim(cts_hashv_cwtclaims)


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
