# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pycose
import pytest

from pyscitt import crypto
from pyscitt.cli.main import main
from pyscitt.client import Client, ReceiptType

from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


class TestAcceptedAlgorithms:
    @pytest.fixture
    def submit(self, client: Client, trusted_ca):
        def f(**kwargs):
            """Sign and submit the claims with a new identity"""
            identity = trusted_ca.create_identity(**kwargs)
            claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
            client.submit_claim_and_confirm(claims)

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
            client.submit_claim_and_confirm(signed_claimset)

        for err, signed_claimsets in refused_signed_claims.items():
            for signed_claimset in signed_claimsets:
                with service_error(err):
                    client.submit_claim_and_confirm(signed_claimset)

    def test_svn_policy(
        self,
        client: Client,
        configure_service,
        trusted_ca: X5ChainCertificateAuthority,
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
            client.submit_claim_and_confirm(signed_claimset)

        for err, signed_claimsets in refused_signed_claims.items():
            for signed_claimset in signed_claimsets:
                with service_error(err):
                    client.submit_claim_and_confirm(signed_claimset)

    def test_trivial_pass_policy(
        self, client: Client, configure_service, signed_claimset
    ):
        configure_service(
            {"policy": {"policy_script": "export function apply() { return true }"}}
        )

        client.submit_claim_and_confirm(signed_claimset)

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
            client.submit_claim_and_confirm(signed_claimset)

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
            client.submit_claim_and_confirm(signed_claimset)

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
            client.submit_claim_and_confirm(signed_claimset)

    def test_cts_hashv_cwtclaims_payload_with_policy(
        self,
        tmp_path,
        client: Client,
        configure_service,
        trusted_ca: X5ChainCertificateAuthority,
        untrusted_ca: X5ChainCertificateAuthority,
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

        submission = client.submit_claim_and_confirm(
            cts_hashv_cwtclaims, receipt_type=ReceiptType.EMBEDDED
        )

        # store submission receipt in random file in tmp_path
        receipt_path = tmp_path / "receipt.cose"
        receipt_path.write_bytes(submission.receipt_bytes)
        # print to preview what was accepted and to check if pretty-receipt understands the given receipt
        main(["pretty-receipt", str(receipt_path)])

def test_without_service_identifier(
    client: Client,
    configure_service,
    trusted_ca: X5ChainCertificateAuthority,
):
    identity = trusted_ca.create_identity(
        length=1, alg="ES256", kty="ec", ec_curve="P-256"
    )

    claim = crypto.sign_json_claimset(identity, {"foo": "bar"})

    # The test framework automatically configures the service with a DID.
    # Reconfigure the service to disable it.
    configure_service({"service_identifier": None})

    # The receipts it returns have no issuer or kid.
    receipt = client.submit_claim_and_confirm(claim).receipt
    assert crypto.SCITTIssuer.identifier not in receipt.phdr
    assert pycose.headers.KID not in receipt.phdr