# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pycose
import pytest

from pyscitt import crypto
from pyscitt.client import Client

from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


class TestAcceptedAlgorithms:
    @pytest.fixture
    def submit(self, client: Client, trusted_ca):
        def f(**kwargs):
            """Sign and submit the statement with a new identity"""
            identity = trusted_ca.create_identity(**kwargs)
            signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})
            client.submit_signed_statement_and_wait(signed_statement)

        return f

    def test_reject_everything(self, configure_service, submit):
        # Configure the service with no accepted algorithms.
        # The service should reject anything we submit to it.
        configure_service({"policy": {"acceptedAlgorithms": []}})

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES256", kty="ec", ec_curve="P-256")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES384", kty="ec", ec_curve="P-384")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="PS256", kty="rsa")

    def test_allow_select_algorithm(self, configure_service, submit):
        # Add just one algorithm to the policy. Statements signed with this
        # algorithm are accepted but not the others.
        configure_service({"policy": {"acceptedAlgorithms": ["ES256"]}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES384", kty="ec", ec_curve="P-384")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="PS256", kty="rsa")

    def test_default_allows_anything(self, configure_service, submit):
        # If no acceptedAlgorithms are defined in the policy, any algorithm
        # is accepted.
        configure_service({"policy": {}})
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        submit(alg="ES384", kty="ec", ec_curve="P-384")
        submit(alg="PS256", kty="rsa")


class TestPolicyEngine:
    @pytest.fixture(scope="class")
    def signed_statement(self, trusted_ca: X5ChainCertificateAuthority):
        identity = trusted_ca.create_identity(alg="ES256", kty="ec")
        return crypto.sign_json_statement(identity, {"foo": "bar"})

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
        statement = {"foo": "bar"}

        permitted_signed_statements = [
            crypto.sign_json_statement(identities[1], statement, feed=feed, cwt=True),
        ]

        profile_error = "This policy only accepts IETF did:x509 signed statements"
        invalid_issuer = "Invalid issuer"
        eku_not_found = "EKU not found"
        openssl_error = "OpenSSL error"
        invalid_did = "invalid DID string"
        not_supported = "Payloads with CWT_Claims must have a did:x509 iss and x5chain"

        # Keyed by expected error, values are lists of signed statements which should trigger this error
        refused_signed_statements = {
            # Well-constructed, but not a valid issuer
            invalid_issuer: [
                crypto.sign_json_statement(
                    identities[0], statement, feed=feed, cwt=True
                ),
            ],
            eku_not_found: [
                crypto.sign_json_statement(
                    identities[2], statement, feed=feed, cwt=True
                ),
            ],
            openssl_error: [
                crypto.sign_json_statement(
                    identities[3], statement, feed=feed, cwt=True
                ),
            ],
            invalid_did: [
                crypto.sign_json_statement(
                    identities[4], statement, feed=feed, cwt=True
                ),
                crypto.sign_json_statement(
                    identities[5], statement, feed=feed, cwt=True
                ),
            ],
            not_supported: [
                crypto.sign_json_statement(
                    identities[6], statement, feed=feed, cwt=True
                ),
            ],
        }

        policy_script = f"""
export function apply(profile, phdr) {{
    if (profile !== "IETF") {{ return "{profile_error}"; }}

    // Check exact issuer 
    if (phdr.cwt.iss !== "{didx509_issuer(trusted_ca)}") {{ return "Invalid issuer"; }}

    return true;
}}"""

        configure_service({"policy": {"policyScript": policy_script}})

        for signed_statement in permitted_signed_statements:
            client.submit_signed_statement_and_wait(signed_statement)

        for err, signed_statements in refused_signed_statements.items():
            for signed_statement in signed_statements:
                with service_error(err):
                    client.submit_signed_statement_and_wait(signed_statement)

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
        statement = {"foo": "bar"}

        permitted_signed_statements = [
            crypto.sign_json_statement(identity, statement, feed=feed, svn=1, cwt=True),
        ]

        profile_error = "This policy only accepts IETF did:x509 signed statements"
        invalid_svn = "Invalid SVN"

        # Keyed by expected error, values are lists of signed statements which should trigger this error
        refused_signed_statements = {
            # Well-constructed, but not a valid issuer
            invalid_svn: [
                crypto.sign_json_statement(identity, statement, feed=feed, cwt=True),
                crypto.sign_json_statement(
                    identity, statement, feed=feed, svn=-11, cwt=True
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

        configure_service({"policy": {"policyScript": policy_script}})

        for signed_statement in permitted_signed_statements:
            client.submit_signed_statement_and_wait(signed_statement)

        for err, signed_statements in refused_signed_statements.items():
            for signed_statement in signed_statements:
                with service_error(err):
                    client.submit_signed_statement_and_wait(signed_statement)

    def test_trivial_pass_policy(
        self, client: Client, configure_service, signed_statement
    ):
        configure_service(
            {"policy": {"policyScript": "export function apply() { return true }"}}
        )

        client.submit_signed_statement_and_wait(signed_statement)

    def test_trivial_fail_policy(
        self, client: Client, configure_service, signed_statement
    ):
        configure_service(
            {
                "policy": {
                    "policyScript": "export function apply() { return `All entries are refused`; }"
                }
            }
        )

        with service_error("Policy was not met"):
            client.submit_signed_statement_and_wait(signed_statement)

    def test_exceptional_policy(
        self, client: Client, configure_service, signed_statement
    ):
        configure_service(
            {
                "policy": {
                    "policyScript": 'export function apply() { throw new Error("Boom"); }'
                }
            }
        )

        with service_error("Error while applying policy"):
            client.submit_signed_statement_and_wait(signed_statement)

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
        self, client: Client, configure_service, signed_statement, script
    ):
        configure_service({"policy": {"policyScript": script}})

        with service_error("Invalid policy module"):
            client.submit_signed_statement_and_wait(signed_statement)

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
if (profile !== "IETF") {{ return "This policy only accepts IETF did:x509 signed statements"; }}

// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat < (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

return true;
}}"""

        configure_service({"policy": {"policyScript": policy_script}})

        with open("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rb") as f:
            cts_hashv_cwtclaims = f.read()

        statement = client.submit_signed_statement_and_wait(
            cts_hashv_cwtclaims
        ).response_bytes

        # store statement
        transparent_statement = tmp_path / "transparent_statement.cose"
        transparent_statement.write_bytes(statement)
