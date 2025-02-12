# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import sys

import pycose
import pytest

from pyscitt import crypto
from pyscitt.client import Client

from . import policies
from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


class TestAcceptedAlgorithms:
    @pytest.fixture
    def submit(self, client: Client, trusted_ca):
        def f(**kwargs):
            """Sign and submit the statement with a new identity"""
            identity = trusted_ca.create_identity(**kwargs)
            signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})
            client.register_signed_statement(signed_statement)

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
            client.register_signed_statement(signed_statement)

        for err, signed_statements in refused_signed_statements.items():
            for signed_statement in signed_statements:
                with service_error(err):
                    client.register_signed_statement(signed_statement)

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_svn_policy(
        self,
        client: Client,
        configure_service,
        trusted_ca: X5ChainCertificateAuthority,
        lang,
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

        err_msgs = {
            "js": "Policy was not met: Invalid SVN",
            "rego": "Policy was not met",
        }

        # Keyed by expected error, values are lists of signed statements which should trigger this error
        refused_signed_statements = {
            # Well-constructed, but not a valid issuer
            err_msgs[lang]: [
                crypto.sign_json_statement(identity, statement, feed=feed, cwt=True),
                crypto.sign_json_statement(
                    identity, statement, feed=feed, svn=-11, cwt=True
                ),
            ],
        }

        issuer = didx509_issuer(trusted_ca)
        configure_service({"policy": policies.SVN[lang](issuer)})

        for signed_statement in permitted_signed_statements:
            client.register_signed_statement(signed_statement)

        for err, signed_statements in refused_signed_statements.items():
            for signed_statement in signed_statements:
                with service_error(err):
                    client.register_signed_statement(signed_statement)

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_trivial_pass_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        configure_service({"policy": policies.PASS[lang]})

        client.register_signed_statement(signed_statement)

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_trivial_fail_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        configure_service({"policy": policies.FAIL[lang]})

        with service_error("Policy was not met"):
            client.register_signed_statement(signed_statement)

    @pytest.mark.parametrize("lang", ["js"])
    def test_exceptional_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        # No runtime error test for Rego, because things that seem like they
        # would cause runtime errors, such as dividing by zero, cause a policy
        # failure instead.
        configure_service({"policy": policies.RUNTIME_ERROR[lang]})

        with service_error("Error while applying policy"):
            client.register_signed_statement(signed_statement)

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_invalid_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        for invalid_policy in policies.INVALID[lang]:
            configure_service({"policy": invalid_policy})

            with service_error("Invalid policy module"):
                client.register_signed_statement(signed_statement)

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_cts_hashv_cwtclaims_payload_with_policy(
        self, tmp_path, client: Client, configure_service, lang
    ):
        configure_service({"policy": policies.SAMPLE[lang]})

        with open("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rb") as f:
            cts_hashv_cwtclaims = f.read()

        statement = client.register_signed_statement(cts_hashv_cwtclaims).response_bytes

        # store statement
        transparent_statement = tmp_path / "transparent_statement.cose"
        transparent_statement.write_bytes(statement)
