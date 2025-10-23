# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
import os.path
from hashlib import sha256

import cbor2
import pycose
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from pycose.keys.cosekey import CoseKey

from pyscitt import crypto
from pyscitt.client import Client

from . import policies
from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


class TestAcceptedAlgorithms:
    @pytest.fixture
    def submit(self, client: Client, cert_authority):
        def f(**kwargs):
            """Sign and submit the statement with a new identity"""
            kwargs["add_eku"] = "2.999"
            identity = cert_authority.create_identity(**kwargs)
            signed_statement = crypto.sign_json_statement(
                identity, {"foo": "bar"}, cwt=True
            )
            client.submit_signed_statement_and_wait(signed_statement)

        return f

    def test_reject_everything(self, configure_service, submit):
        # Configure the service with no accepted algorithms.
        # The service should reject anything we submit to it.
        configure_service(
            {
                "policy": {
                    "acceptedAlgorithms": [],
                    "policyScript": 'export function apply() { return "Not supported"; }',
                }
            }
        )

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES256", kty="ec", ec_curve="P-256")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES384", kty="ec", ec_curve="P-384")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="PS256", kty="rsa")

    def test_allow_select_algorithm(self, configure_service, submit):
        # Add just one algorithm to the policy. Statements signed with this
        # algorithm are accepted but not the others.
        configure_service(
            {
                "policy": {
                    "acceptedAlgorithms": ["ES256"],
                    "policyScript": "export function apply() { return true; }",
                }
            }
        )
        submit(alg="ES256", kty="ec", ec_curve="P-256")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="ES384", kty="ec", ec_curve="P-384")

        with service_error("InvalidInput: Unsupported algorithm"):
            submit(alg="PS256", kty="rsa")

    def test_default_allows_anything(self, configure_service, submit):
        # If no acceptedAlgorithms are defined in the policy, any algorithm
        # is accepted.
        configure_service(
            {"policy": {"policyScript": "export function apply() { return true; }"}}
        )
        submit(alg="ES256", kty="ec", ec_curve="P-256")
        submit(alg="ES384", kty="ec", ec_curve="P-384")
        submit(alg="PS256", kty="rsa")


class TestPolicyEngine:
    @pytest.fixture(scope="class")
    def signed_statement(self, cert_authority: X5ChainCertificateAuthority):
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku="2.999"
        )

        def f(json_payload: dict = {"foo": "bar"}) -> bytes:
            return crypto.sign_json_statement(
                identity,
                json_payload,
                cwt=True,
            )

        return f

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_ietf_didx509_policy(
        self,
        client: Client,
        configure_service,
        cert_authority: X5ChainCertificateAuthority,
        lang,
    ):
        example_eku = "2.999"

        untrusted_cert_authority = X5ChainCertificateAuthority(kty="ec")

        # We will apply a policy that only allows issuers endorsed by a specific trusted CA
        # and containing a specific EKU to be registered.
        identities = [
            untrusted_cert_authority.create_identity(
                alg="ES256", kty="ec", add_eku=example_eku
            ),
            cert_authority.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            cert_authority.create_identity(alg="ES256", kty="ec"),
            cert_authority.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            cert_authority.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            cert_authority.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
            cert_authority.create_identity(alg="ES256", kty="ec", add_eku=example_eku),
        ]

        def didx509_issuer(ca):
            root_cert = ca.cert_bundle
            root_fingerprint = crypto.get_cert_fingerprint_b64url(root_cert)
            return f"did:x509:0:sha256:{root_fingerprint}::eku:{example_eku}"

        identities[0].issuer = didx509_issuer(untrusted_cert_authority)
        identities[1].issuer = didx509_issuer(cert_authority)
        identities[2].issuer = didx509_issuer(cert_authority)

        identities[3].issuer = didx509_issuer(cert_authority).strip(
            example_eku
        )  # No EKU bits
        identities[4].issuer = didx509_issuer(cert_authority).strip(
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

        invalid_issuer = "Invalid issuer"
        eku_not_found = "EKU not found"
        openssl_error = "OpenSSL error"
        invalid_did = "invalid DID string"
        not_supported = "CWT_Claims issuer is unsupported"

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

        issuer = didx509_issuer(cert_authority)
        configure_service({"policy": policies.DID_X509[lang](issuer)})

        for signed_statement in permitted_signed_statements:
            client.submit_signed_statement_and_wait(signed_statement)

        for err, signed_statements in refused_signed_statements.items():
            for signed_statement in signed_statements:
                with service_error(err):
                    client.submit_signed_statement_and_wait(signed_statement)

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_svn_policy(
        self,
        client: Client,
        configure_service,
        cert_authority: X5ChainCertificateAuthority,
        lang,
    ):
        example_eku = "2.999"

        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku=example_eku
        )

        def didx509_issuer(ca):
            root_cert = ca.cert_bundle
            root_fingerprint = crypto.get_cert_fingerprint_b64url(root_cert)
            return f"did:x509:0:sha256:{root_fingerprint}::eku:{example_eku}"

        issuer = didx509_issuer(cert_authority)
        configure_service({"policy": policies.DID_X509[lang](issuer)})
        feed = "SomeFeed"
        # SBOMs
        statement = {"foo": "bar"}

        permitted_signed_statements = [
            crypto.sign_json_statement(identity, statement, feed=feed, svn=1, cwt=True),
        ]

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
export function apply(phdr) {{
    // Check exact issuer 
    if (phdr.cwt.iss !== "{didx509_issuer(cert_authority)}") {{ return "Invalid issuer"; }}
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

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_trivial_pass_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        configure_service({"policy": policies.PASS[lang]})

        client.submit_signed_statement_and_wait(signed_statement())

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_trivial_fail_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        configure_service({"policy": policies.FAIL[lang]})

        with service_error("Policy was not met"):
            client.submit_signed_statement_and_wait(signed_statement())

    @pytest.mark.parametrize("lang", ["js"])
    def test_exceptional_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        # No runtime error test for Rego, because things that seem like they
        # would cause runtime errors, such as dividing by zero, cause a policy
        # failure instead.
        configure_service({"policy": policies.RUNTIME_ERROR[lang]})

        with service_error("Error while applying policy"):
            client.submit_signed_statement_and_wait(signed_statement())

    @pytest.mark.parametrize("lang", ["js", "rego"])
    def test_invalid_policy(
        self, client: Client, configure_service, signed_statement, lang
    ):
        for invalid_policy in policies.INVALID[lang]:
            configure_service({"policy": invalid_policy})

            with service_error("Invalid policy module.*"):
                client.submit_signed_statement_and_wait(signed_statement())

    @pytest.mark.parametrize(
        "filepath, lang",
        [
            ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "js"),
            ("test/payloads/cts-hashv-cwtclaims-b64url.cose", "rego"),
            ("test/payloads/manifest.spdx.json.sha384.digest.cose", "js"),
            ("test/payloads/manifest.spdx.json.sha384.digest.cose", "rego"),
        ],
    )
    def test_cts_hashv_cwtclaims_payload_with_policy(
        self, tmp_path, client: Client, configure_service, filepath, lang
    ):
        configure_service({"policy": policies.SAMPLE[lang]})

        with open(filepath, "rb") as f:
            cts_hashv_cwtclaims = f.read()

        statement = client.submit_signed_statement_and_wait(
            cts_hashv_cwtclaims
        ).response_bytes

        # store statement
        transparent_statement = tmp_path / f"ts_{os.path.basename(filepath)}"
        transparent_statement.write_bytes(statement)

    def test_payload_policy(self, client: Client, configure_service, signed_statement):
        configure_service(
            {
                "policy": {
                    "policyScript": 'export function apply(phdr, uhdr, payload) { if (ccf.bufToStr(payload) !== "{\\"foo\\": \\"bar\\"}") { return `Invalid payload`; } return true; }'
                }
            }
        )

        client.submit_signed_statement_and_wait(signed_statement())

    def test_payload_policy_with_large_payload(
        self, client: Client, configure_service, signed_statement
    ):
        policy_script = """
        export function apply(phdr, uhdr, payload) {
            const parsed = JSON.parse(ccf.bufToStr(payload));
            if (parsed.foo.length < 1000) {
                return `Invalid payload`; 
            } 
            return true; 
        }
        """
        configure_service({"policy": {"policyScript": policy_script}})

        # Create a large JSON payload
        big_json: dict = {"foo": []}
        for _ in range(1000):
            big_json["foo"].append("a" * 1024)
        print(f"JSON payload size: {len(json.dumps(big_json))} bytes")
        statement = signed_statement(big_json)
        print(f"Signed statement size: {len(statement)} bytes")

        client.submit_signed_statement_and_wait(statement)

    @pytest.fixture(scope="class")
    def didx509_signed_statement_with_attestation(
        self, cert_authority: X5ChainCertificateAuthority
    ):
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku="2.999"
        )
        return crypto.sign_json_statement(
            identity,
            {"foo": "bar"},
            cwt=True,
            additional_phdr={
                "attestedsvc": {
                    "svc_id": "msft-css-dev",
                    "attestation": b"testAttestation",
                    "snp_endorsements": b"testSnpEndorsements",
                    "uvm_endorsements": b"testUvmEndorsements",
                },
            },
        )

    def test_tss_map(
        self,
        client: Client,
        configure_service,
        didx509_signed_statement_with_attestation,
    ):
        policy_script = """
        export function apply(phdr, uhdr, payload) {
            if (phdr["attestedsvc"].svc_id !== "msft-css-dev") {
                return `Invalid attestedsvc.svc_id`;
            }
            if (ccf.bufToStr(phdr["attestedsvc"].attestation) !== "testAttestation") {
                return `Invalid attestedsvc.attestation`;
            }
            if (ccf.bufToStr(phdr["attestedsvc"].snp_endorsements) !== "testSnpEndorsements") {
                return `Invalid attestedsvc.snp_endorsements`;
            }
            if (ccf.bufToStr(phdr["attestedsvc"].uvm_endorsements) !== "testUvmEndorsements") {
                return `Invalid attestedsvc.uvm_endorsements`;
            }
            return true;
        }
        """

        configure_service({"policy": {"policyScript": policy_script}})

        client.submit_signed_statement_and_wait(
            didx509_signed_statement_with_attestation
        )

    @pytest.fixture(scope="class")
    def signed_statement_with_attestation(self):
        # Create static signer
        # because the public key has to be used when generating snp report
        # fmt: off
        #[SuppressMessage("Microsoft.Security", "CS002:SecretInNextLine", Justification="Test key")]
        generated_test_key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwsl9BwpcxTw79lQ8\n+rtsYyZ8CNVpgnJ9L9NuRmgiZ2qhRANCAATtJmmhf9hdySatQFUHh3+ILwBRlO4j\nantkQ/2KFzXseETRvTuZuyoYWi+hBg//qzfNJfvvjoEtiaa7426R82XZ\n-----END PRIVATE KEY-----\n"
        # fmt: on
        generated_test_x5c = [
            "-----BEGIN CERTIFICATE-----\nMIIBwTCCAWagAwIBAgIULfldx1HL14KvXqBMVEEq61q68+IwCgYIKoZIzj0EAwIw\nLzEtMCsGA1UEAwwkMGQ2MDMzOGYtYmQ4Yy00YmVmLWE5YjgtZWFjZThjNDRjMTFk\nMB4XDTI1MDcyNDE5MzIwOVoXDTI1MDgwMzE5MzIwOVowLzEtMCsGA1UEAwwkOGYz\nNDYyZmItMDVkYy00YjU0LWE0NDEtMjk2Nzk5NjE1ZWYzMFkwEwYHKoZIzj0CAQYI\nKoZIzj0DAQcDQgAE7SZpoX/YXckmrUBVB4d/iC8AUZTuI2p7ZEP9ihc17HhE0b07\nmbsqGFovoQYP/6s3zSX7746BLYmmu+NukfNl2aNgMF4wDgYDVR0PAQH/BAQDAgeA\nMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGkP1dHhmW5Sw19dLNwa0udg3dncMB8G\nA1UdIwQYMBaAFDBndIFyJUU3FbqU8R8WytENgRYlMAoGCCqGSM49BAMCA0kAMEYC\nIQC7/2EGZdHD8tpNPIwDfqf0Sa7AXt5XDXRdeJTasbwi3QIhAN5VpmAntiniBJZ8\nGQurE+3XV4ZLWrskP5pSpyTt0Swc\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIBwzCCAWmgAwIBAgIUN1tVTBRw8OxeFRwuC8mokXGW5ocwCgYIKoZIzj0EAwIw\nLzEtMCsGA1UEAwwkMGQ2MDMzOGYtYmQ4Yy00YmVmLWE5YjgtZWFjZThjNDRjMTFk\nMB4XDTI1MDcyNDE5MzIwOVoXDTI1MDgwMzE5MzIwOVowLzEtMCsGA1UEAwwkMGQ2\nMDMzOGYtYmQ4Yy00YmVmLWE5YjgtZWFjZThjNDRjMTFkMFkwEwYHKoZIzj0CAQYI\nKoZIzj0DAQcDQgAEh9rXU4Hn482VUC1kMg3OeHgkc9NfjAAiowTUxC0JgRtheXf/\nEjtUc6xnxOV+L+oXDdBYfCDD06KSCpjzGsaU+qNjMGEwDgYDVR0PAQH/BAQDAgIE\nMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFDBndIFyJUU3FbqU8R8WytENgRYl\nMB8GA1UdIwQYMBaAFDBndIFyJUU3FbqU8R8WytENgRYlMAoGCCqGSM49BAMCA0gA\nMEUCIHTtEid/s7U0aCo3C0svZuBxzbwI1Wic9JychB1ceQXcAiEAoejSglEUf59o\nwfYmQlPDq+YPjBuRMVNnx1Hs1fTagDI=\n-----END CERTIFICATE-----\n",
        ]
        identity = crypto.Signer(
            generated_test_key,
            algorithm="ES256",
            x5c=generated_test_x5c,
            issuer="did:attestedsvc:msft-css-dev::foo:bar:baz",
        )

        # Create CoseKey
        # use the first certificate in the chain as the COSE key
        # extract public key from that certificate
        # convert it to PEM and the use it to create a COSE key
        cert_pem = identity.x5c[0]
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode("utf-8"), default_backend()
        )
        pub_key = cert.public_key()
        pub_key_pem = pub_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        cose_key = CoseKey.from_pem_public_key(pub_key_pem.decode("utf-8"))
        cose_key_cbor = cose_key.encode()
        # kid is used in verification and needs to be set
        identity.kid = sha256(cose_key_cbor).digest()

        # Attestation and endorsements
        # Generate these following details within a running C-ACI instance
        # using image: mcr.microsoft.com/acc/samples/aci/helloworld:2.8
        # But there might be issues with decoding if the base64 encoded files are copied from portal
        # decode them in the instance and send to tmpfiles.org to then be able to download
        # e.g.: curl -k -F "file=@uvm_endorsements.cose" https://tmpfiles.org/api/v1/upload

        # cat /security-context-3802821067/host-amd-cert-base64
        snp_endorsements = "eyJ2Y2VrQ2VydCI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRlF6Q0NBdmVnQXdJQkFnSUJBREJCQmdrcWhraUc5dzBCQVFvd05LQVBNQTBHQ1dDR1NBRmxBd1FDQWdVQVxub1J3d0dnWUpLb1pJaHZjTkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVEF3ZXpFVU1CSUdBMVVFQ3d3TFxuUlc1bmFXNWxaWEpwYm1jeEN6QUpCZ05WQkFZVEFsVlRNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTFxuTUFrR0ExVUVDQXdDUTBFeEh6QWRCZ05WQkFvTUZrRmtkbUZ1WTJWa0lFMXBZM0p2SUVSbGRtbGpaWE14RWpBUVxuQmdOVkJBTU1DVk5GVmkxTmFXeGhiakFlRncweU5UQXhNamd4TmpVeU5EVmFGdzB6TWpBeE1qZ3hOalV5TkRWYVxuTUhveEZEQVNCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFxuVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUjh3SFFZRFZRUUtEQlpCWkhaaGJtTmxaQ0JOYVdOeVxuYnlCRVpYWnBZMlZ6TVJFd0R3WURWUVFEREFoVFJWWXRWa05GU3pCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaVxuQTJJQUJHNkh5eGxhbmJjdXU3VEFRVkt5Uk1ZSGZtMDBYYzhUWFh3bU5Ld1hkaXFTcjhjckpHd2Zac0FxeTFzcFxuSVIvM3RPV21HbytoejZZMFhrWjNPN09NVlRCU2g5ZVVNRGQrbndBSTZLVEFHU3lBWnh1OWdjVHBqT0FMS2lPaVxuR2dDN2txT0NBUmN3Z2dFVE1CQUdDU3NHQVFRQm5IZ0JBUVFEQWdFQU1CY0dDU3NHQVFRQm5IZ0JBZ1FLRmdoTlxuYVd4aGJpMUNNREFSQmdvckJnRUVBWng0QVFNQkJBTUNBUVF3RVFZS0t3WUJCQUdjZUFFREFnUURBZ0VBTUJFR1xuQ2lzR0FRUUJuSGdCQXdRRUF3SUJBREFSQmdvckJnRUVBWng0QVFNRkJBTUNBUUF3RVFZS0t3WUJCQUdjZUFFRFxuQmdRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdjRUF3SUJBREFSQmdvckJnRUVBWng0QVFNREJBTUNBUmd3RWdZS1xuS3dZQkJBR2NlQUVEQ0FRRUFnSUEyekJOQmdrckJnRUVBWng0QVFRRVFMRDlHUzJYYWZDM3NzSVZHVlJPWG9QOFxuOGkzbGszdWhWb0V1NnVzVkZQRjNoaC9kRk9HblNLVGkxbDlucElRRzIzWktKVHcvbXBlTXlJRUVJWEIwZ0I0d1xuUVFZSktvWklodmNOQVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTlxuQmdsZ2hrZ0JaUU1FQWdJRkFLSURBZ0V3QTRJQ0FRQUlCRFdWWDZSazJ0b1NaRFI4Wm5vSlVnNE1hbWEyOWVtZVxuU21VK2JXdCtCYjJMalAxbE9Ea21wWHFXV2xZYk1JcHNIUWV6NlZweElUWm4zQUVPeTdkemdLS0FSZWQ0SERTdlxuU1M2TUlsSmJrNmhjMm5oSHNtcU9Vb3g3dEZjVkI3Z3dScXFBc2dySUNoVU5GUEx5cXdZMFdSNHBYUG45S01ITFxuVXNySncrZHVJUkpRWHRkakJSblowM2tFR2VxL1NLQm1keDNKNXhuWDhOK0hrNW02NmZHNnRJV0t4dkl5ZzFtQlxucFB2VUZKcEVSMDlyZGFNdlZVNG5lYkN1blhmVDQ4dVhhSDhGd21xSXRJQ3hEOTQ4c0NNZ2JWdlI4ZW5RN2NrY1xuRFRobTZSVCtPT01EKzhBL2d6STUxZnI4dHZOWXdPQ0hGUUJON3F0MWNUYUMvTDZXOHgzTGRvS2EwMkp5N1JzaFxuTTNSMVVlUXhjalhuWGZmTnFUS2hQSlMrMWtVS2xHZVVkR21OaG5pNzRGZDdnM1NyT0lZejQ0clU0Y1N6emN1eVxuaDI2dXNmbENuMHZBRHkvK2ViQUNSempSWU9XR3MrYjRqbElkUjVjc2pxN29JL2VqdERJaU1YcVB2cm12SGVTdlxuSWlHNlljejZMTmtiL3hmRlJ4NTA2aDZCYlk5aGRzcitPYTdHZnc3ZHJZS2FpK1hzL01ib0JpUDUwR2puUHdpRlxuZDZuUlVQTEpZOUtNVlFVYVFXSHBSeHEvanNZVWMwVmE5WGNnZDZVSlc2MzIyUmY5Yyt6K1g3azJpcDRlZkgzWFxuME5FVVluUjRvQ0ZUckxtNjJ0bEVqLzN5ZHArZ0dZczJGWDlaN05aNm9IcFJFTVp2bkhpZE1Ecm44Z1pUYTlmelxudnhrcWxFL1Zxdz09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4iLCJ0Y2JtIjoiREIxODAwMDAwMDAwMDAwNCIsImNlcnRpZmljYXRlQ2hhaW4iOiItLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1JSUdpVENDQkRpZ0F3SUJBZ0lEQVFBQk1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNcbkJRQ2hIREFhQmdrcWhraUc5dzBCQVFnd0RRWUpZSVpJQVdVREJBSUNCUUNpQXdJQk1LTURBZ0VCTUhzeEZEQVNcbkJnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1Rc3dDUVlEVlFRR0V3SlZVekVVTUJJR0ExVUVCd3dMVTJGdWRHRWdcblEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnBcblkyVnpNUkl3RUFZRFZRUUREQWxCVWtzdFRXbHNZVzR3SGhjTk1qQXhNREl5TVRneU5ESXdXaGNOTkRVeE1ESXlcbk1UZ3lOREl3V2pCN01SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVMTUFrR0ExVUVCaE1DVlZNeEZEQVNcbkJnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWpcblpXUWdUV2xqY204Z1JHVjJhV05sY3pFU01CQUdBMVVFQXd3SlUwVldMVTFwYkdGdU1JSUNJakFOQmdrcWhraUdcbjl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFuVTJkcnJOVGZiaE5RSWxsZitXMnkrUk9DYlN6SWQxYUtaZnRcbjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05UY0IwVllYdDNKeFpTek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXdcbktaWDBKbVFFdVlqbStXS2tzTHR4Z2RMcDlFN0VaTndORHFWMXIwcVJQNXRCOE9Xa3lRYklkTGV1NGFDejdqL1NcbmwxRmtCeXRldjlzYkZHenQ3Y3duanppOW03bm9xc2srdVJWQnAzK0luMzVRUGRjajhZZmxFbW5IQk52dVVESmhcbkxDSk1XOEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pUTThLc05iVXgzQThlazVFVkxcbmpaV0gxcHQ5RTNUZnBSNlh5ZlFLblk2a2w1YUVJUHdkVzNlRllhcUNGUHJJbzlwUVQ2V3VEU1A0SkNZSmJabmVcbktLSWJaanpYa0p0M05RRzMyRXVrWUltQmI5U0NrbTkrZlM1TFpGZzlvanp1Yk1YMytOa0JvU1hJN09Qdm5ITXhcbmp1cDltdzVzZTZRVVY3R3FwQ0EyVE55cG9sbXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGxcbkFsSnc1RDBDVFJUQzFZNVlXRkRCQ3JBL3ZHbm1UbnFHOEMrampVQVM3Y2pqUjhxNE9QaHlEbUpSUG5hQy9aRzVcbnVQMEswejZHb08vM3Vlbjl3cXNoQ3VIZWdMVHBPZUhFSlJLclFGcjRQVkl3Vk9CMCtlYk81RmdveU93NDNueUZcbkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FSSXMxRW9xRWptRjhVdHJtUVdWMmhVand6cXd2SEZcbmVpOHJQeE1DQXdFQUFhT0JvekNCb0RBZEJnTlZIUTRFRmdRVU84WnVHQ3JEL1QxaVpFaWI0N2RITExUOHYvZ3dcbkh3WURWUjBqQkJnd0ZvQVVoYXdhMFVQM3lLeFYxTVVkUVVpcjFYaEsxRk13RWdZRFZSMFRBUUgvQkFnd0JnRUJcbi93SUJBREFPQmdOVkhROEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIwY0hNNkx5OXJcblpITnBiblJtTG1GdFpDNWpiMjB2ZG1ObGF5OTJNUzlOYVd4aGJpOWpjbXd3UmdZSktvWklodmNOQVFFS01EbWdcbkR6QU5CZ2xnaGtnQlpRTUVBZ0lGQUtFY01Cb0dDU3FHU0liM0RRRUJDREFOQmdsZ2hrZ0JaUU1FQWdJRkFLSURcbkFnRXdvd01DQVFFRGdnSUJBSWdlVVFTY0FmM2xEWXFnV1UxVnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEVcblBJMWpoM2dKYkx4TDZnZjNLOGp4Y3R6T1dua1ljYmRmTU9PcjI4S1QzNUlhQVIyMHJla0tSRnB0VEhoZStERnJcbjNBRnpaTEREN2NXSzI5L0dwUGl0UEpES0N2STdBNFVnMDZyazdKMHpCZTFmei9xZTRpMi9GMTJydmZ3Q0dZaGNcblJ4UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpNa3Q3REZ2S1JoKzJ6Sys1cGxWR0dcbkZzakRKdE16MnVkOXkwcHZPRTRqM2RINUlXOWpHeGFTR1N0cU5yYWJubnBGMjM2RVRyMS9hNDNiOEZGS0w1UU5cbm10OFZyOXhuWFJwem5xQ1J2cWpyK2tWcmI2ZGxmdVRsbGlYZVFUTWxCb1JXRkpPUkw4QWNCSnhHWjRLMm1YZnRcbmwxalU1VExlaDVLWEw5Tlc3YS9xQU9JVXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnJcbkVnNnpreG12TXVhYlpPc2RLZlJrV2ZoSDJaS2NUbERmbUgxSDB6cTBRMmJHM3V2YVZkaUN0RlkxTGxXeUIzOEpcblMyZk5zUi9QeTZ0NWJyRUpDRk52emFEa3k2S2VDNGlvbi9jVmdVYWk3enpTM2JHUVd6S0RLVTM1U3FOVTJXa1Bcbkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBlMDF6RDBOOGF0RnhtV2lTbmZKbDY5MEI5ckpwTlIvZklcbmFqeENXM1NlaXdzNnIxWm0rdEN1VmJNaU50cFM5VGhqTlg0dXZlNXRoeWZFMkRnb3hSRnZZMUNzb0Y1TVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlHWXpDQ0JCS2dBd0lCQWdJREFRQUFNRVlHQ1NxR1NJYjNEUUVCQ2pBNW9BOHdEUVlKWUlaSUFXVURCQUlDXG5CUUNoSERBYUJna3Foa2lHOXcwQkFRZ3dEUVlKWUlaSUFXVURCQUlDQlFDaUF3SUJNS01EQWdFQk1Ic3hGREFTXG5CZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnXG5RMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUjh3SFFZRFZRUUtEQlpCWkhaaGJtTmxaQ0JOYVdOeWJ5QkVaWFpwXG5ZMlZ6TVJJd0VBWURWUVFEREFsQlVrc3RUV2xzWVc0d0hoY05NakF4TURJeU1UY3lNekExV2hjTk5EVXhNREl5XG5NVGN5TXpBMVdqQjdNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTXG5CZ05WQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqXG5aV1FnVFdsamNtOGdSR1YyYVdObGN6RVNNQkFHQTFVRUF3d0pRVkpMTFUxcGJHRnVNSUlDSWpBTkJna3Foa2lHXG45dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJSSk9kZWlKbHFLMkpkc1ZtRDdGa3R1b3RXd1gxZk5nXG5XNDFYWTlYejFIRWhTVW1oTHo5Q3U5REhSbHZnSlNOeGJlWVlzbkpmdnlqeDFNZlUwVjV0a0tpVTFFZXNORnRhXG4xa1RBMHN6TmlzZFljOWlzcWs3bVhUNStLZkdSYmZjNFYvOXpSSWNFOGpsSE42MVMxanU4WDkzKzZkeERVckcyXG5TenhxSjRCaHF5WW1VRHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0yQitPK3Zqc0MwXG42MGQzN2pZOUxGZXVPUDRNZXJpOHFnZmkyUzVrS3FnL2FGNmFQdHVBWlFWUjd1M0tGWVhQNTlYbUpndGNvZzA1XG5nbUkwVC9PaXRMaHV6VnZwWmNMcGgwb2RoLzFJUFhxeDMrTW5qRDk3QTdmWHBxR2QveThLeFg3amtzVEV6QU9nXG5iS0FlYW0zbG0rM3lLSWNUWU1sc1JNWFBjak5iSXZtc0J5a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzXG4rZ1ZEa3VWUGhzbnpJUk5nWXZNNDhZKzdMR2lKWW5ybUU4eGNyZXhla0J4cnZhMlY5VEpRcW5OM1E1M2t0NXZpXG5RaTMrZ0NmbWt3QzBGMHRpcklaYkxrWFByUHd6WjBNOWVOeGhJeVNiMm5wSmZnbnF6NTVJMHUzM3doNHIwWk5RXG5lVEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBDcTcrT2dwQ0NvTU5pdDJ1TG85TTE4XG5mSHoxMGxPTVQ4bldBVXZSWkZ6dGVYQ20rN1BIZFlQbG1Rd1V3M0x2ZW5KL0lMWG9RUEhmYmtIMEN5UGZobDFqXG5XaEpGWmFzQ0F3RUFBYU4rTUh3d0RnWURWUjBQQVFIL0JBUURBZ0VHTUIwR0ExVWREZ1FXQkJTRnJCclJRL2ZJXG5yRlhVeFIxQlNLdlZlRXJVVXpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VHXG5LV2gwZEhCek9pOHZhMlJ6YVc1MFppNWhiV1F1WTI5dEwzWmpaV3N2ZGpFdlRXbHNZVzR2WTNKc01FWUdDU3FHXG5TSWIzRFFFQkNqQTVvQTh3RFFZSllJWklBV1VEQkFJQ0JRQ2hIREFhQmdrcWhraUc5dzBCQVFnd0RRWUpZSVpJXG5BV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDNm0wa0RwNnp2NE9qZmd5K3psZWVoc3g2b2wwb2NnVmVsXG5FVG9icHgrRXVDc3FWRlJQSzFqWjFzcC9seWQ5KzBmUTByNjZuN2thZ1JrNENhMzlnNjZXR1RKTWVKZHFZcml3XG5TVGpqRENLVlBTZXNXWFlQVkF5RGhtUDVuMnYrQllpcFpXaHB2cXBhaU8rRUdLNUlCUCs1NzhRZVcvc1Nva3JLXG5kSGFMQXhHMkxoWnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dTZ2tEZ3V0Q1RCMVlxXG56VDVEdXd2QWUrY28yQ0lWSXpNRGFtWXVTRmpQTjBCQ2dvamw3VitiVG91N2RNc3FJdS9UVy9yUENYOS9FVWNwXG5LR0txUFEzUCtOOXIxaGpFRlkxcGxCZzkzdDUzT09vNDlHTkkrVjF6dlhQTEk2eElGVnNoK210bzJSdGdFWC9lXG5wbU1LVE5ONnBzVzg4cWc3YzFoVFd0TjZNYlJ1UTB2bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxXG5IbklZaHh5MFlLWEd5YVcxTmpmVUx4cnJteFZXNHdjbjVFOEdkZG12TmE2eVltOHNjSmFnRWkxM21oR3U0SnFoXG4zUVUzc2Y4aVVTVXIwOXhRRHdIdE9RVVZJcXg0bWFCWlBCdFNNZitxVUR0alhTU3E4bGZXY2Q4YkxyOW1kc1VuXG5KWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2VzFVbXEyNWJveENZSitUdUJvYTRzK0hIXG5DVmlBdmdUOWtmL3JCcTFkK2l2ajZza2tIeHV6Y3hiazF4djZaR3hydGVKeFZIN0tsWDdZUmRaNmVBUkt3TGU0XG5BRlpFQXdvS0NRPT1cbi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS1cbiIsImNhY2hlQ29udHJvbCI6Ijg2NDAwIn0="
        # cat /security-context-3802821067/reference-info-base64
        uvm_endorsements = "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"
        # create cose_key hex
        # curl -LOk https://github.com/ivarprudnikov/random-tools/raw/refs/heads/main/get-snp-report
        # chmod a+x get-snp-report
        # ./get-snp-report cose_key_hex_here
        # convert output hex to base64
        snp_report = "AwAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAEAAAAAAAY2yUAAAAAAAAAAAAAAAAAAABGDc4HsDoKTzpCz5PyAQWV56jaBnezoBob8IghpIvfrwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX+7jDW1+Gin0A9cKQZgjfd+xMFGi1pdkOUh8YJOI7X+YGJiHkgqy+gCWkDoMI/yhc5c7eNcMxoNTQm3hiNtd/Fflt2bjmZNftzphEn6ibSAK15zrC2SLDmqQ2KqfbqJMM6lotmMghTUxReixmkdBotq5ujQuE75PwNIl6InMGlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB7IvQp0syiOy7T/FvWD2tAY2VpIE5HCUiCDY//1LKv1///////////////////////////////////////////BAAAAAAAGNsZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAACw/Rktl2nwt7LCFRlUTl6D/PIt5ZN7oVaBLurrFRTxd4Yf3RThp0ik4tZfZ6SEBtt2SiU8P5qXjMiBBCFwdIAeBAAAAAAAGNsdNwEAHTcBAAQAAAAAABjbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmr8/+gbIDhJivgdNj8r6klcaZR1utgszbq8r194pitT0+qkr+xl+FIO4hrkbf4oYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK50yU+gQ8H2Q9lNeUO7+6YcnCiLf8oSrcQNke7KDUayvXIbL2yIMFCCMGRPptBe2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        # AMD JSON format to single certificate chain
        snp_e_json = json.loads(base64.b64decode(snp_endorsements, validate=True))
        snp_e = (snp_e_json["vcekCert"] + snp_e_json["certificateChain"]).encode(
            "utf-8"
        )
        uvm_e = base64.b64decode(uvm_endorsements)
        snp_r = base64.b64decode(snp_report)

        return crypto.sign_json_statement(
            identity,
            {"foo": "bar"},
            cwt=True,
            additional_phdr={
                2: ["attestedsvc"],
                "attestedsvc": {
                    "svc_id": "msft-css-dev",
                    "attestation": snp_r,
                    "attestation_type": "SEV-SNP:ContainerPlat-AMD-UVM",
                    "snp_endorsements": snp_e,
                    "uvm_endorsements": uvm_e,
                    "cose_key": cbor2.loads(cose_key_cbor),
                    "ver": 0,
                },
            },
        )

    def test_valid_attestedsvc_signature_and_also_verify_attestation_in_policy(
        self, client: Client, configure_service, signed_statement_with_attestation
    ):
        policy_script = """
        export function apply(phdr, uhdr, payload) {
            var claims = snp_attestation.verifySnpAttestation(
                phdr["attestedsvc"].attestation,
                phdr["attestedsvc"].snp_endorsements,
                phdr["attestedsvc"].uvm_endorsements
            );

            function toHexStr(arrayBuffer) {
                var hex = "";
                var bytes = new Uint8Array(arrayBuffer);
                for (var i = 0; i < bytes.byteLength; i++) {
                    hex += ('0' + bytes[i].toString(16)).slice(-2);
                }
                return hex;
            }

            const container_security_policy_digest = toHexStr(claims.attestation.host_data);
            if (container_security_policy_digest !== "73973b78d70cc68353426de188db5dfc57e5b766e399935fb73a61127ea26d20")
            {
                throw new Error("Invalid container security policy digest " + container_security_policy_digest);
            }
            return true;
        }
        """
        configure_service({"policy": {"policyScript": policy_script}})

        client.submit_signed_statement_and_wait(signed_statement_with_attestation)

    def test_valid_attestedsvc_signature_and_exposed_attestation_details(
        self, client: Client, configure_service, signed_statement_with_attestation
    ):
        policy_script = """
        export function apply(phdr, uhdr, payload, details) {
            if (details.measurement !== "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1")
            {
                throw new Error("Invalid measurement hex " + details.measurement);
            }
            if (details.report_data !== "460dce07b03a0a4f3a42cf93f2010595e7a8da0677b3a01a1bf08821a48bdfaf0000000000000000000000000000000000000000000000000000000000000000")
            {
                throw new Error("Invalid report data hex " + details.report_data);
            }
            if (details.host_data !== "73973b78d70cc68353426de188db5dfc57e5b766e399935fb73a61127ea26d20")
            {
                throw new Error("Invalid host data hex " + details.host_data);
            }
            if (details.uvm_endorsements.did !== "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2")
            {
                throw new Error("Invalid uvm_endorsements did " + details.uvm_endorsements.did);
            }
            if (details.uvm_endorsements.feed !== "ContainerPlat-AMD-UVM")
            {
                throw new Error("Invalid uvm_endorsements feed " + details.uvm_endorsements.feed);
            }
            if (details.uvm_endorsements.svn !== "101")
            {
                throw new Error("Invalid uvm_endorsements svn " + details.uvm_endorsements.svn);
            }
            if (details.product_name != "Milan")
            {
                throw new Error("Invalid product name " + details.product_name);
            }
            if (details.reported_tcb.hexstring !== "db18000000000004")
            {
                throw new Error("Invalid reported TCB hexstring " + details.reported_tcb.hexstring);
            }
            return true;
        }
        """
        configure_service({"policy": {"policyScript": policy_script}})

        client.submit_signed_statement_and_wait(signed_statement_with_attestation)
