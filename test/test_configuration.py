# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
import os.path
import time

import pycose
import pytest

from pyscitt import crypto
from pyscitt.client import Client

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
        return crypto.sign_json_statement(
            identity,
            {"foo": "bar"},
            cwt=True,
        )

    def test_ietf_didx509_policy(
        self,
        client: Client,
        configure_service,
        cert_authority: X5ChainCertificateAuthority,
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
        not_supported = "CWT_Claims issuer must be a did:x509"

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
export function apply(phdr) {{
    // Check exact issuer 
    if (phdr.cwt.iss !== "{didx509_issuer(cert_authority)}") {{ return "Invalid issuer"; }}

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
        cert_authority: X5ChainCertificateAuthority,
    ):
        example_eku = "2.999"

        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku=example_eku
        )

        def didx509_issuer(ca):
            root_cert = ca.cert_bundle
            root_fingerprint = crypto.get_cert_fingerprint_b64url(root_cert)
            return f"did:x509:0:sha256:{root_fingerprint}::eku:{example_eku}"

        identity.issuer = didx509_issuer(cert_authority)
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

    @pytest.mark.parametrize(
        "filepath",
        [
            "test/payloads/cts-hashv-cwtclaims-b64url.cose",
            "test/payloads/manifest.spdx.json.sha384.digest.cose",
        ],
    )
    def test_cts_hashv_cwtclaims_payload_with_policy(
        self, tmp_path, client: Client, configure_service, filepath
    ):

        policy_script = f"""
export function apply(phdr) {{

// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat < (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

return true;
}}"""

        configure_service({"policy": {"policyScript": policy_script}})

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

        client.submit_signed_statement_and_wait(signed_statement)

    @pytest.fixture(scope="class")
    def tss_signed_statement(self, cert_authority: X5ChainCertificateAuthority):
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku="2.999"
        )
        return crypto.sign_json_statement(
            identity,
            {"foo": "bar"},
            cwt=True,
            additional_phdr={
                "msft-css-dev": {
                    "attestation": b"testAttestation",
                    "snp_endorsements": b"testSnpEndorsements",
                    "uvm_endorsements": b"testUvmEndorsements",
                }
            },
        )

    def test_tss_map(self, client: Client, configure_service, tss_signed_statement):
        policy_script = """
        export function apply(phdr, uhdr, payload) {
            if (ccf.bufToStr(phdr["msft-css-dev"].attestation) !== "testAttestation") {
                return `Invalid msft-css-dev.attestation`;
            }
            if (ccf.bufToStr(phdr["msft-css-dev"].snp_endorsements) !== "testSnpEndorsements") {
                return `Invalid msft-css-dev.snp_endorsements`;
            }
            if (ccf.bufToStr(phdr["msft-css-dev"].uvm_endorsements) !== "testUvmEndorsements") {
                return `Invalid msft-css-dev.uvm_endorsements`;
            }
            return true;
        }
        """

        configure_service({"policy": {"policyScript": policy_script}})

        client.submit_signed_statement_and_wait(tss_signed_statement)

    @pytest.fixture(scope="class")
    def signed_statement_with_attestation(
        self, cert_authority: X5ChainCertificateAuthority
    ):
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku="2.999"
        )
        snp_endorsements = "eyJ2Y2VrQ2VydCI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRlF6Q0NBdmVnQXdJQkFnSUJBREJCQmdrcWhraUc5dzBCQVFvd05LQVBNQTBHQ1dDR1NBRmxBd1FDQWdVQVxub1J3d0dnWUpLb1pJaHZjTkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVEF3ZXpFVU1CSUdBMVVFQ3d3TFxuUlc1bmFXNWxaWEpwYm1jeEN6QUpCZ05WQkFZVEFsVlRNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTFxuTUFrR0ExVUVDQXdDUTBFeEh6QWRCZ05WQkFvTUZrRmtkbUZ1WTJWa0lFMXBZM0p2SUVSbGRtbGpaWE14RWpBUVxuQmdOVkJBTU1DVk5GVmkxTmFXeGhiakFlRncweU5UQXhNak14T0RNNE16WmFGdzB6TWpBeE1qTXhPRE00TXpaYVxuTUhveEZEQVNCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFxuVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUjh3SFFZRFZRUUtEQlpCWkhaaGJtTmxaQ0JOYVdOeVxuYnlCRVpYWnBZMlZ6TVJFd0R3WURWUVFEREFoVFJWWXRWa05GU3pCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaVxuQTJJQUJGNDJOL3RFV0tvb2FoamZYaHBlbDR1bm40dVBlM2gxMWZvTjkwd2VIOUJoL25jaFlpcFgxSWZ2M3R0bFxubUVmTVRjRFJtbHdYWTFIU0dPZnk4VTdWUkxUdytlQlUvTklabm1FZVJTWEtubkhPSXZveE9CMytYSFI3NHBLTVxuVzV2YXBLT0NBUmN3Z2dFVE1CQUdDU3NHQVFRQm5IZ0JBUVFEQWdFQU1CY0dDU3NHQVFRQm5IZ0JBZ1FLRmdoTlxuYVd4aGJpMUNNREFSQmdvckJnRUVBWng0QVFNQkJBTUNBUVF3RVFZS0t3WUJCQUdjZUFFREFnUURBZ0VBTUJFR1xuQ2lzR0FRUUJuSGdCQXdRRUF3SUJBREFSQmdvckJnRUVBWng0QVFNRkJBTUNBUUF3RVFZS0t3WUJCQUdjZUFFRFxuQmdRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdjRUF3SUJBREFSQmdvckJnRUVBWng0QVFNREJBTUNBUmd3RWdZS1xuS3dZQkJBR2NlQUVEQ0FRRUFnSUEyekJOQmdrckJnRUVBWng0QVFRRVFIUEd4cmlmWHFDamt6bkcxb3NYYjZtZlxuTk1SeWJtNERkdVZGcGRVbFZ4T1RKdnFBMVBIZjFlRFdEZEZTY3VzS1RCVjZzM2ViZ01JSDFMWVVKZTVlYUw0d1xuUVFZSktvWklodmNOQVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTlxuQmdsZ2hrZ0JaUU1FQWdJRkFLSURBZ0V3QTRJQ0FRQ0dKUHgzNzVSUDhBV0dOQS9LaTAxd1dKTDVkSFRkMlBRQVxuWC9MN2R0WlgvOUVuOThBLzEwWFpWV1NDWnUxdWJDMUNSR25FSFZ5WHZ6NEJwclVHZE92VjRycXVKOG0zSUZSUFxuMCt2NTJjMVVXS0dZQmsyek9nYmFETUFWaUdLcnV6cmFlM0NZSEJOb09jeHFkY1krWm54OExzb1dqZFJpekZGOVxubWlCYlpLTFBhemo0TTNhOXp4ZEw1d3dLK1diZjdQbDJtZ3ptZVBJMEpyVUx2R0RXeUlLMzNrMTJpeVkxeUJmcVxuUEo4a0d0RjlENXU5cUlOeE5JaHVXTEt1VGttUGJpSE54Z1VkY3BWb0FkZlBmU3lHUG11czEvUG9meWpYU21tYVxuZmpnYy9acHJqY0JVT1NqblpEU2JuN3VYQWFDNHUzKzdUcVBJNkNpTWpIR1V2VFFUSUFIcDdHQ295SDJraHBFWVxudlNJazNPZ0lXZnJwY1QyWEo2NUVwazZ4RE5IRTZjdGRjWllZUzc2MW82V1JMZS9ITk5Ka2hUV1VkaWJ4TTg0clxuM2FYWTdJYVJtaW1wQU5KaDM2YU1wemtBTHlBWEVTclYvVk51V2taSnB2ajB4ZzhsVGhLTnYvNmZadExBZ2ZOMlxuM2JnWksyQUJQLzdndzRtUHdqdlF3aUZHTzBta1A5YkxuQUk5YmZyUG9CYWhQMlo2Sk5tSjg4K1pUNWdLMEZ1U1xuMjFmS0dpZzIrS3RhNmd3M3p4SjM2TU5oelpBdzVadkRWYU9NZU1kQVhVWWt4Qmp4elRpaFQyK0NsRWZ4NEVnS1xuNFRtUmhaNDlJbnNSZS9RRHQrVWFyK2NhMjdLcU51ZC9VUGFhUzVDSGttenAwRi9NekJVZ2JZRFh4alNYWCtCc1xuSzEzQ0hWTHc5QT09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4iLCJ0Y2JtIjoiREIxODAwMDAwMDAwMDAwNCIsImNlcnRpZmljYXRlQ2hhaW4iOiItLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1JSUdpVENDQkRpZ0F3SUJBZ0lEQVFBQk1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNcbkJRQ2hIREFhQmdrcWhraUc5dzBCQVFnd0RRWUpZSVpJQVdVREJBSUNCUUNpQXdJQk1LTURBZ0VCTUhzeEZEQVNcbkJnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1Rc3dDUVlEVlFRR0V3SlZVekVVTUJJR0ExVUVCd3dMVTJGdWRHRWdcblEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnBcblkyVnpNUkl3RUFZRFZRUUREQWxCVWtzdFRXbHNZVzR3SGhjTk1qQXhNREl5TVRneU5ESXdXaGNOTkRVeE1ESXlcbk1UZ3lOREl3V2pCN01SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVMTUFrR0ExVUVCaE1DVlZNeEZEQVNcbkJnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWpcblpXUWdUV2xqY204Z1JHVjJhV05sY3pFU01CQUdBMVVFQXd3SlUwVldMVTFwYkdGdU1JSUNJakFOQmdrcWhraUdcbjl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFuVTJkcnJOVGZiaE5RSWxsZitXMnkrUk9DYlN6SWQxYUtaZnRcbjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05UY0IwVllYdDNKeFpTek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXdcbktaWDBKbVFFdVlqbStXS2tzTHR4Z2RMcDlFN0VaTndORHFWMXIwcVJQNXRCOE9Xa3lRYklkTGV1NGFDejdqL1NcbmwxRmtCeXRldjlzYkZHenQ3Y3duanppOW03bm9xc2srdVJWQnAzK0luMzVRUGRjajhZZmxFbW5IQk52dVVESmhcbkxDSk1XOEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pUTThLc05iVXgzQThlazVFVkxcbmpaV0gxcHQ5RTNUZnBSNlh5ZlFLblk2a2w1YUVJUHdkVzNlRllhcUNGUHJJbzlwUVQ2V3VEU1A0SkNZSmJabmVcbktLSWJaanpYa0p0M05RRzMyRXVrWUltQmI5U0NrbTkrZlM1TFpGZzlvanp1Yk1YMytOa0JvU1hJN09Qdm5ITXhcbmp1cDltdzVzZTZRVVY3R3FwQ0EyVE55cG9sbXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGxcbkFsSnc1RDBDVFJUQzFZNVlXRkRCQ3JBL3ZHbm1UbnFHOEMrampVQVM3Y2pqUjhxNE9QaHlEbUpSUG5hQy9aRzVcbnVQMEswejZHb08vM3Vlbjl3cXNoQ3VIZWdMVHBPZUhFSlJLclFGcjRQVkl3Vk9CMCtlYk81RmdveU93NDNueUZcbkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FSSXMxRW9xRWptRjhVdHJtUVdWMmhVand6cXd2SEZcbmVpOHJQeE1DQXdFQUFhT0JvekNCb0RBZEJnTlZIUTRFRmdRVU84WnVHQ3JEL1QxaVpFaWI0N2RITExUOHYvZ3dcbkh3WURWUjBqQkJnd0ZvQVVoYXdhMFVQM3lLeFYxTVVkUVVpcjFYaEsxRk13RWdZRFZSMFRBUUgvQkFnd0JnRUJcbi93SUJBREFPQmdOVkhROEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIwY0hNNkx5OXJcblpITnBiblJtTG1GdFpDNWpiMjB2ZG1ObGF5OTJNUzlOYVd4aGJpOWpjbXd3UmdZSktvWklodmNOQVFFS01EbWdcbkR6QU5CZ2xnaGtnQlpRTUVBZ0lGQUtFY01Cb0dDU3FHU0liM0RRRUJDREFOQmdsZ2hrZ0JaUU1FQWdJRkFLSURcbkFnRXdvd01DQVFFRGdnSUJBSWdlVVFTY0FmM2xEWXFnV1UxVnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEVcblBJMWpoM2dKYkx4TDZnZjNLOGp4Y3R6T1dua1ljYmRmTU9PcjI4S1QzNUlhQVIyMHJla0tSRnB0VEhoZStERnJcbjNBRnpaTEREN2NXSzI5L0dwUGl0UEpES0N2STdBNFVnMDZyazdKMHpCZTFmei9xZTRpMi9GMTJydmZ3Q0dZaGNcblJ4UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpNa3Q3REZ2S1JoKzJ6Sys1cGxWR0dcbkZzakRKdE16MnVkOXkwcHZPRTRqM2RINUlXOWpHeGFTR1N0cU5yYWJubnBGMjM2RVRyMS9hNDNiOEZGS0w1UU5cbm10OFZyOXhuWFJwem5xQ1J2cWpyK2tWcmI2ZGxmdVRsbGlYZVFUTWxCb1JXRkpPUkw4QWNCSnhHWjRLMm1YZnRcbmwxalU1VExlaDVLWEw5Tlc3YS9xQU9JVXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnJcbkVnNnpreG12TXVhYlpPc2RLZlJrV2ZoSDJaS2NUbERmbUgxSDB6cTBRMmJHM3V2YVZkaUN0RlkxTGxXeUIzOEpcblMyZk5zUi9QeTZ0NWJyRUpDRk52emFEa3k2S2VDNGlvbi9jVmdVYWk3enpTM2JHUVd6S0RLVTM1U3FOVTJXa1Bcbkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBlMDF6RDBOOGF0RnhtV2lTbmZKbDY5MEI5ckpwTlIvZklcbmFqeENXM1NlaXdzNnIxWm0rdEN1VmJNaU50cFM5VGhqTlg0dXZlNXRoeWZFMkRnb3hSRnZZMUNzb0Y1TVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlHWXpDQ0JCS2dBd0lCQWdJREFRQUFNRVlHQ1NxR1NJYjNEUUVCQ2pBNW9BOHdEUVlKWUlaSUFXVURCQUlDXG5CUUNoSERBYUJna3Foa2lHOXcwQkFRZ3dEUVlKWUlaSUFXVURCQUlDQlFDaUF3SUJNS01EQWdFQk1Ic3hGREFTXG5CZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnXG5RMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUjh3SFFZRFZRUUtEQlpCWkhaaGJtTmxaQ0JOYVdOeWJ5QkVaWFpwXG5ZMlZ6TVJJd0VBWURWUVFEREFsQlVrc3RUV2xzWVc0d0hoY05NakF4TURJeU1UY3lNekExV2hjTk5EVXhNREl5XG5NVGN5TXpBMVdqQjdNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTXG5CZ05WQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqXG5aV1FnVFdsamNtOGdSR1YyYVdObGN6RVNNQkFHQTFVRUF3d0pRVkpMTFUxcGJHRnVNSUlDSWpBTkJna3Foa2lHXG45dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJSSk9kZWlKbHFLMkpkc1ZtRDdGa3R1b3RXd1gxZk5nXG5XNDFYWTlYejFIRWhTVW1oTHo5Q3U5REhSbHZnSlNOeGJlWVlzbkpmdnlqeDFNZlUwVjV0a0tpVTFFZXNORnRhXG4xa1RBMHN6TmlzZFljOWlzcWs3bVhUNStLZkdSYmZjNFYvOXpSSWNFOGpsSE42MVMxanU4WDkzKzZkeERVckcyXG5TenhxSjRCaHF5WW1VRHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0yQitPK3Zqc0MwXG42MGQzN2pZOUxGZXVPUDRNZXJpOHFnZmkyUzVrS3FnL2FGNmFQdHVBWlFWUjd1M0tGWVhQNTlYbUpndGNvZzA1XG5nbUkwVC9PaXRMaHV6VnZwWmNMcGgwb2RoLzFJUFhxeDMrTW5qRDk3QTdmWHBxR2QveThLeFg3amtzVEV6QU9nXG5iS0FlYW0zbG0rM3lLSWNUWU1sc1JNWFBjak5iSXZtc0J5a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzXG4rZ1ZEa3VWUGhzbnpJUk5nWXZNNDhZKzdMR2lKWW5ybUU4eGNyZXhla0J4cnZhMlY5VEpRcW5OM1E1M2t0NXZpXG5RaTMrZ0NmbWt3QzBGMHRpcklaYkxrWFByUHd6WjBNOWVOeGhJeVNiMm5wSmZnbnF6NTVJMHUzM3doNHIwWk5RXG5lVEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBDcTcrT2dwQ0NvTU5pdDJ1TG85TTE4XG5mSHoxMGxPTVQ4bldBVXZSWkZ6dGVYQ20rN1BIZFlQbG1Rd1V3M0x2ZW5KL0lMWG9RUEhmYmtIMEN5UGZobDFqXG5XaEpGWmFzQ0F3RUFBYU4rTUh3d0RnWURWUjBQQVFIL0JBUURBZ0VHTUIwR0ExVWREZ1FXQkJTRnJCclJRL2ZJXG5yRlhVeFIxQlNLdlZlRXJVVXpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VHXG5LV2gwZEhCek9pOHZhMlJ6YVc1MFppNWhiV1F1WTI5dEwzWmpaV3N2ZGpFdlRXbHNZVzR2WTNKc01FWUdDU3FHXG5TSWIzRFFFQkNqQTVvQTh3RFFZSllJWklBV1VEQkFJQ0JRQ2hIREFhQmdrcWhraUc5dzBCQVFnd0RRWUpZSVpJXG5BV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDNm0wa0RwNnp2NE9qZmd5K3psZWVoc3g2b2wwb2NnVmVsXG5FVG9icHgrRXVDc3FWRlJQSzFqWjFzcC9seWQ5KzBmUTByNjZuN2thZ1JrNENhMzlnNjZXR1RKTWVKZHFZcml3XG5TVGpqRENLVlBTZXNXWFlQVkF5RGhtUDVuMnYrQllpcFpXaHB2cXBhaU8rRUdLNUlCUCs1NzhRZVcvc1Nva3JLXG5kSGFMQXhHMkxoWnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dTZ2tEZ3V0Q1RCMVlxXG56VDVEdXd2QWUrY28yQ0lWSXpNRGFtWXVTRmpQTjBCQ2dvamw3VitiVG91N2RNc3FJdS9UVy9yUENYOS9FVWNwXG5LR0txUFEzUCtOOXIxaGpFRlkxcGxCZzkzdDUzT09vNDlHTkkrVjF6dlhQTEk2eElGVnNoK210bzJSdGdFWC9lXG5wbU1LVE5ONnBzVzg4cWc3YzFoVFd0TjZNYlJ1UTB2bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxXG5IbklZaHh5MFlLWEd5YVcxTmpmVUx4cnJteFZXNHdjbjVFOEdkZG12TmE2eVltOHNjSmFnRWkxM21oR3U0SnFoXG4zUVUzc2Y4aVVTVXIwOXhRRHdIdE9RVVZJcXg0bWFCWlBCdFNNZitxVUR0alhTU3E4bGZXY2Q4YkxyOW1kc1VuXG5KWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2VzFVbXEyNWJveENZSitUdUJvYTRzK0hIXG5DVmlBdmdUOWtmL3JCcTFkK2l2ajZza2tIeHV6Y3hiazF4djZaR3hydGVKeFZIN0tsWDdZUmRaNmVBUkt3TGU0XG5BRlpFQXdvS0NRPT1cbi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS1cbiIsImNhY2hlQ29udHJvbCI6Ijg2NDAwIn0="
        uvm_endorsements = "0oRZE86nATglA3BhcHBsaWNhdGlvbi9qc29uGCGDWQZvMIIGazCCBFOgAwIBAgITMwAAACj0ZX46brvO9QAAAAAAKDANBgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgU0NEIFByb2R1Y3RzIFJTQSBDQTAeFw0yNDA4MjIyMTA3NDJaFw0yNTA4MjAyMTA3NDJaMGwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAMTDUNvbnRhaW5lclBsYXQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCeumXJShe9UgIgIhjocTyXdn775JKPJkyxL42E8wPO5XbKvfXWL9T9Go4nAqIv4fBOee90Eko5L06LT6zIAijdzJMcD5hKqLpYv2kei9/HravzzUDiZZGgO/ZUpmtqkJlM7i/kz7xcyWlksBKsQGxLGw0B9zxXRv1iIsngbNQ6jUohx6LUS2Q9MQYiBXt8dE7O6zXhhFMYyA5Ip35eVBpC+4ft6SqAJByzN4H486cTX8vLxwgd1JRll8K0a6vKoKaUaRSkn9tJFbSm8AYBh0gY/bpiAfU1oHWthi6xDxuYMtSpj8AmhhMFbaEK3vaQWSJOlAp0ro1bFj88Otmefuu5SK8RSKHFVw4rcRyNp5sVGpJ1jxST3p8ozK3dLhVi/eYwtCpy1BVhsx7/xeMaLMWChBp1k8sIdTjRBHfNtzFHVXObHsQaNyOpL/+e/8mSq8xYargnF8EzdTwFfAh3SvH19ZlI8oDOKVvryOuz3KEkJjwlCuxK6Mw324ttQlP/wxECAwEAAaOCAZswggGXMA4GA1UdDwEB/wQEAwIHgDAjBgNVHSUEHDAaBgsrBgEEAYI3TDsBAQYLKwYBBAGCN0w7AQIwHQYDVR0OBBYEFAqI8sG0RmzUYX3D3s9tHKiJlFWSMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQLExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ3Mjk3Mis1MDI3MDAwHwYDVR0jBBgwFoAUVc1NhW7NSjXDjj9yAbqqmBmXS6cwXgYDVR0fBFcwVTBToFGgT4ZNaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwU0NEJTIwUHJvZHVjdHMlMjBSU0ElMjBDQS5jcmwwawYIKwYBBQUHAQEEXzBdMFsGCCsGAQUFBzAChk9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFNDRCUyMFByb2R1Y3RzJTIwUlNBJTIwQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEMBQADggIBAJxaIwPjsU1fL1JxbH3mMw4wi/pU0OX0D8z3wJ5lCaCKJZmcWp9JP0FkNl5FDjX8xkMtpWpZYnj1WinjeAFSrN/RYFrZ0WN2C9uawQE/MzezCCxRc41CImJQ4ctDpJXH37VO9i9K7pZX+TO950lQUuMRL2GlBSYvSXpDKgAunEkGgg2l/OkPrK/kZmGqSo1P5UdMlMr3ntdQb958khm53ISpeQu0Te8Q1Dlmhgy53uLYSZR/WeyKIBDe0KQzx5kpppQVF85GHaKq9KQuDR0CWRaICxoJ+tYM4VE3Sxct+UTpIt+MwQNzTf4VjRLRS0Vh9wELqKQ8D4It+YYECFkaLfxqcZaVnSAhuUF9QtOcA2Knzw88LQcAyHEb/Bl6QwpnJWpqtiBpkKvAdfpQ2fP+5v4a6UZhkpm1f6O4eEnGGj0f73JQJBTGi1IEkM+0+iRFJVWSe+ShbS99ItQYIeMuF20fKHSf7qurxZj84uH2GEiW2KH/k4NEx9Z0rj8GS2xUezvxlAwv61crcALXr85qC69Z5bDXLdeFVJtl4jG8v0g1WIGR7I3vqpMUfnybGX3hIVUipU8zpIoizDEsGBe/0zM4740RNoeSaz+pwnGNTIP9MVvZu2yYUXcyB1NlZTAWAts+HP15eCpZVSRvInFukouGwC6Tub9/rYCHBnk30ge3WQbVMIIG0TCCBLmgAwIBAgITMwAAAAOVhEf/iehmCQAAAAAAAzANBgkqhkiG9w0BAQwFADBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb290IENBIDIwMjIwHhcNMjIwMjE3MDA0NTIzWhcNNDIwMjE3MDA1NTIzWjBVMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgU0NEIFByb2R1Y3RzIFJTQSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvtf7VxvoxzvvHXyp3xAdZ0h7yMQpNMn8qVdGtOR+pyhLWkFsGMQlTXDe2Yes+o7mC0IEQJMz39CJxIjG6XYIQfcF2CaO/6MCzWzysbFvlTkoY/LN/g0/RlcJ/IdFlf0VWcvujpZPh9CLlEd0HS9qYFRAPRRQOvwe3NT5uEd38fRbKbZ6vCJG2c/YxHByKbeooYReovPoNpVpxdaIDS64IdgGl8mX+yTPwwwLHOfR+E2UWgnnQqgNYp0hCM2YZ+J5zU0QZCwZ1JMLXQ9eK0sJW3uPfj7iA/k1k57kN3dSZ4P4hkqGVTAnrBzaoZsINMkGVJbgEpfSPrRLBOkr4Zmh7m8PigL8B8xIJ01Tx1KBmfiWAFGmVx++NSY8oFxRW/DdKdwWLr5suCpB2ONjF7LNv4A5v4SZ+zYCwpTc8ouxPPUtZSG/fklVEFveW30jMJwQAf29X8wAuJ0pwuWaP2PziQSonR4VmRP3cKz88aAbm0zmzvx+pdTCX9fH/cTuYwErjJA3d9G7/3sDGE/QBqkjC+NkZI8XCdm6Ur8QIK4LaZJ/ZBT9QEkXF7xML0FBe3YLYWk5F2pc4d2wJinZIFvJJvLvkAp//guabt6wCXTjxHDz2RkiJnmiteSLO09DeQIvgEGY7nJTKy1oMwRoalGrL14YD4QyNawcazBtGZQ20NAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFFXNTYVuzUo1w44/cgG6qpgZl0unMBEGA1UdIAQKMAgwBgYEVR0gADAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFAuzaDuv2q/ucKV22SH3zEQWB9D4MGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFN1cHBseSUyMENoYWluJTIwUlNBJTIwUm9vdCUyMENBJTIwMjAyMi5jcmwweQYIKwYBBQUHAQEEbTBrMGkGCCsGAQUFBzAChl1odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFN1cHBseSUyMENoYWluJTIwUlNBJTIwUm9vdCUyMENBJTIwMjAyMi5jcnQwDQYJKoZIhvcNAQEMBQADggIBAG/eYdZr+kG/bRyUyOGKw8qn9DME5Ckmz3vmIdcmdU+LE3TnFzEBRo1FRF1tdOdqCq58vtH5luxa8hkl4wyvvAjv0ahppr+2UI79vyozKGIC4ud2zBpWgtmxifFv5KyXy7kZyrvuaVDmR3hwAhpZyTfS6XLxdRnsDlsD95qdw89hBKf8l/QfFhCkPJi3BPftb0E1kFQ5qUzl4jSngCKyT8fdXZBRdHlHil11BJpNm7gcJxJQfYWBX+EDRpNGS0YI5/cQhMES35jYJfGGosw9DFCfORzjRmc1zpEVXUrnbnJDtcjrpeQz0DQg6KVwOjSkEkvjzKltH0+bnU1IKvrSuVy8RFWci1vdrAj0I6Y2JaALcE00Lh86BHGYVK/NZEZQAAXlCPRaOQkcCaxkuT0zNZB0NppU1485jHR67p78bbBpXSe9LyfpWFwB3q6jye9KW2uXi/7zTPYByX0AteoVo6JW56JXhILCWmzBjbj8WUzco/sxjwbthT0WtKDADKuKREahCy0tSestD3D5XcGIdMvU9BBLFglXtW2LmdTDe4lLBSuuS2TQoFBw/BoqXctCe/sDer5TVxeZ4h7zU50vcrCV74x+xCI4XpUmXI3uyLrhEVJh0C03L3pE+NTmIIm+7Zk8q5MmrkQ7pVwkJdT7cW7YgiqkoCIOeygb/UVPXxhWWQWzMIIFrzCCA5egAwIBAgIQaCjVTH5c2r1DOa4MwVoqNTANBgkqhkiG9w0BAQwFADBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb290IENBIDIwMjIwHhcNMjIwMjE3MDAxMjM2WhcNNDcwMjE3MDAyMTA5WjBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb290IENBIDIwMjIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCeJQFmGR9kNMGdOSNiHXGLVuol0psf7ycBgr932JQzgxhIm1Cee5ZkwtDDX0X/MpzoFxe9eO11mF86BggrHDebRkqQCrCvRpI+M4kq+rjnMmPzI8du0hT7Jlju/gaEVPrBHzeq29TsViq/Sb3M6wLtxk78rBm1EjVpFYkXTaNo6mweKZoJ8856IcYJ0RnqjzBGaTtoBCt8ii3WY13qbdY5nr0GPlvuLxFbKGunUqRoXkyk6q7OI79MNnHagUVQjsqGzv9Tw7hDsyTuB3qitPrHCh17xlI1MewIH4SAklv4sdo51snn5YkEflF/9OZqZEdJ6vjspvagQ1P+2sMjJNgl2hMsKrc/lN53HEx4HGr5mo/rahV3d61JhM4QQMeZSA/Vlh6AnHOhOKEDb9NNINC1Q+T3LngPTve8v2XabZALW7/e6icnmWT4OXxzPdYh0u7W81MRLlXD3OrxKVfeUaF4c5ALL/XJdTbrjdJtjnlduho4/98ZAajSyNHW8uuK9S7RzJMTm5yQeGVjeQTE8Z6fjDrzZAz+mB2T4o9WpWNTI7hucxZFGrb3ew/NpDL/Wv6WjeGHeNtwg6gkhWkgwm0SDeV59ipZz9ar54HmoLGILQiMC7HP12w2r575A2fZQXOpq0W4cWBYGNQWLGW60QXeksVQEBGQzkfM+6+/I8CfBQIDAQABo2cwZTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUC7NoO6/ar+5wpXbZIffMRBYH0PgwEAYJKwYBBAGCNxUBBAMCAQAwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4ICAQBIxzf//8FoV9eLQ2ZGOiZrL+j63mihj0fxPTSVetpVMfSV0jhfLLqPpY1RMWqJVWhsK0JkaoUkoFEDx93RcljtbB6M2JHF50kRnRl6N1ged0T7wgiYQsRN45uKDs9ARU8bgHBZjJOB6A/VyCaVqfcfdwa4yu+c++hm2uU54NLSYsOn1LYYmiebJlBKcpfVs1sqpP1fL37mYqMnZgz62RnMER0xqAFSCOZUDJljK+rYhNS0CBbvvkpbiFj0Bhag63pd4cdE1rsvVVYl8J4M5A8S28B/r1ZdxokOcalWEuS5nKhkHrVHlZKu0HDIk318WljxBfFKuGxyGKmuH1eZJnRm9R0P313w5zdbX7rwtO/kYwd+HzIYaalwWpL5eZxY1H6/cl1TRituo5lg1oWMZncWdq/ixRhb4l0INtZmNxdl8C7PoeW85o0NZbRWU12fyK9OblHPiL6S6jD7LOd1P0JgxHHnl59zx5/K0bhsI+pQKB0OQ8z1qRtA66aY5eUPxZIvpZbH1/o8GO4dG2ED/YbnJEEzvdjztmB88xyCA9Vgr9/0IKTkgQYiWsyFM31k+OS4v4AX1PshP2Ou54+3F0Tsci41yQvQgR3pcgMJQdnfCUjmzbeyHGAlGVLzPRJJ7Z2UIo5xKPjBB1Rz3TgItIWPFGyqAK9Aq7WHzrY5XHP5kBgigi9YICHKYq7ni97nCgzZ0aICw2QVooHnbLdQx1nSCKoR9SBYY2lzc3hcZGlkOng1MDk6MDpzaGEyNTY6SV9faXVMMjVvWEVWRmRUUF9hQkx4X2VUMVJQSGJDUV9FQ0JRZllacHQ5czo6ZWt1OjEuMy42LjEuNC4xLjMxMS43Ni41OS4xLjJkZmVlZHVDb250YWluZXJQbGF0LUFNRC1VVk1rc2lnbmluZ3RpbWXBGmc1iLuhaXRpbWVzdGFtcFkUSjCCFEYGCSqGSIb3DQEHAqCCFDcwghQzAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFtBgsqhkiG9w0BCRABBKCCAVwEggFYMIIBVAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCrqMTfBKUhB2LDJJ/t1gd6ZSFaAmlrti7Sh1h7rePDswIGZxqLgxRaGBMyMDI0MTExNDA1MjA1OS40NzRaMASAAgH0AhkA38u98zjp+mgCh6HTaYs7UjZBHAbwwdGeoIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTYwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg6ZMIIHIDCCBQigAwIBAgITMwAAAe+JP1ahWMyo2gABAAAB7zANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1NDhaFw0yNTAzMDUxODQ1NDhaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTYwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjC1jinwzgHwhOakZqy17oE4BIBKsm5kX4DUmCBWI0lFVpEiK5mZ2Kh59soL4ns52phFMQYGG5kypCipungwP9Nob4VGVE6aoMo5hZ9NytXR5ZRgb9Z8NR6EmLKICRhD4sojPMg/RnGRTcdf7/TYvyM10jLjmLyKEegMHfvIwPmM+AP7hzQLfExDdqCJ2u64Gd5XlnrFOku5U9jLOKk1y70c+Twt04/RLqruv1fGP8LmYmtHvrB4TcBsADXSmcFjh0VgQkX4zXFwqnIG8rgY+zDqJYQNZP8O1Yo4kSckHT43XC0oM40ye2+9l/rTYiDFM3nlZe2jhtOkGCO6GqiTp50xI9ITpJXi0vEek8AejT4PKMEO2bPxU63p63uZbjdN5L+lgIcCNMCNI0SIopS4gaVR4Sy/IoDv1vDWpe+I28/Ky8jWTeed0O3HxPJMZqX4QB3I6DnwZrHiKn6oE38tgBTCCAKvEoYOTg7r2lF0Iubt/3+VPvKtTCUbZPFOG8jZt9q6AFodlvQntiolYIYtqSrLyXAQIlXGhZ4gNcv4dv1YAilnbWA9CsnYh+OKEFr/4w4M69lI+yaoZ3L/t/UfXpT/+yc7hS/FolcmrGFJTBYlS4nE1cuKblwZ/UOG26SLhDONWXGZDKMJKN53oOLSSk4ldR0HlsbT4heLlWlOElJQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFO1MWqKFwrCbtrw9P8A63bAVSJzLMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAYGZa3aCDudbk9EVdkP8xcQGZuIAIPRx9K1CA7uRzBt80fC0aWkuYYhQMvHHJRHUobSM4Uw3zN7fHEN8hhaBDb9NRaGnFWdtHxmJ9eMz6Jpn6KiIyi9U5Og7QCTZMl17n2w4eddq5vtk4rRWOVvpiDBGJARKiXWB9u2ix0WH2EMFGHqjIhjWUXhPgR4C6NKFNXHvWvXecJ2WXrJnvvQGXAfNJGETJZGpR41nUN3ijfiCSjFDxamGPsy5iYu904Hv9uuSXYd5m0Jxf2WNJSXkPGlNhrO27pPxgT111myAR61S3S2hc572zN9yoJEObE98Vy5KEM3ZX53cLefN81F1C9p/cAKkE6u9V6ryyl/qSgxu1UqeOZCtG/iaHSKMoxM7Mq4SMFsPT/8ieOdwClYpcw0CjZe5KBx2xLa4B1neFib8J8/gSosjMdF3nHiyHx1YedZDtxSSgegeJsi0fbUgdzsVMJYvqVw52WqQNu0GRC79ZuVreUVKdCJmUMBHBpTp6VFopL0Jf4Srgg+zRD9iwbc9uZrn+89odpInbznYrnPKHiO26qe1ekNwl/d7ro2ItP/lghz0DoD7kEGeikKJWHdto7eVJoJhkrUcanTuUH08g+NYwG6S+PjBSB/NyNF6bHa/xR+ceAYhcjx0iBiv90Mn0JiGfnA2/hLj5evhTcAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvIxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAe+JP1ahWMyo2gABAAAB7zANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDu6zAXDFdRquZA3/O3pH/PmNufEyTl9YMclyaM/hkMATCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPBhKEW4Fo3wUz09NQx2a0DbcdsX8jovM5LizHmnyX+jMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHviT9WoVjMqNoAAQAAAe8wIgQg61/JGcqzl2ixLJlu12B9xmJmNZOvcC8C9WRFGQsPYVowDQYJKoZIhvcNAQELBQAEggIAjhuMVoziRxb9jJ9Rza0xnkxYM70ET3/iq6hflIh1niJEjmuZjLSOiiAJeiqa/Gqj4U6z7qy/cQMHO/qgAfgQceGv+P0PTsIB0rdXwmCJ7mKG4fNv4kmu4wAMFOfogwE/o3gQ8oUvTdKp3KIZuFUf5Ni1Bee9I/DzPY3fbKNdNVN3WAZIubiNR2NK6d4Z3MR51iGls4ZLkihZxpWnHABypue3U5ifssxTHvuZpC9NRleRR/8TXjvWA3zyajsL0gXbtsCtspzHr9x/cTRvnfbnNRLbiYgI5AghMzWqGD3YRIyFU2kQ2Xh80W7hSVeTKWAxPtdOneO1AHD5R2oHmBkS1TL6iRpFh2Scb4DwwTaRJTTt54LFMogK2WpIml8Xzwg6B/OL/x2u/mmuhTimDG2KLwPMcwsvXIqOsQEnSQbciye2nwYav35yjCT1MOqnLoHrGRCmYAecF8RTkBmqBbecah00osjtXzl56V29Ow+fzEnu5BguWkZfGoOM/ZEjqonGYeRWm5B3bg28UU4powcr8Kn2q/g6hnmL4vOoTT95mHjsB24KBjLBwt7ZpRzrmeI23TmZYnkHSKrcgCR0bVSeMhHPABhQxoEHTEQkRLAVQJ8ekVyUKpwawkpMRYEjFFZWGbR0GbNraq5L8XoA1n7EMm1rL8EPW0OIw/bn50jIKgpYrnsKICAieC1tcy1zZXZzbnB2bS1ndWVzdHN2biI6ICIxMDEiLAogICJ4LW1zLXNldnNucHZtLWxhdW5jaG1lYXN1cmVtZW50IjogIjVmZWVlMzBkNmQ3ZTFhMjlmNDAzZDcwYTQxOTgyMzdkZGZiMTMwNTFhMmQ2OTc2NDM5NDg3YzYwOTM4OGVkN2Y5ODE4OTg4NzkyMGFiMmZhMDA5NjkwM2EwYzIzZmNhMSIKfVkBgJEktaxbW8+tXJhYV5irDbvlES+KvY0e+ym9C2ahCXVCvfs6mnp4cL5lrtSTGV7GkZ1Wvxu7FyjRWg/3mo3+lnREdxl4q8E3nDT+QUx04f0sECqrJN1Fs9OndaLlDcznGyMiQ1ybvJVRITqD8SiUQGpiXzGfaTOBiIBDSKR+ppJyhjkFtr0z9sNoNTWOINa6gre/U6URDJwsWxHreVGI6EsSaJmbCHL3XOKYOlrdAMvNog9Zp/xKjdbo8IvNjMbkQry2Of3qG3uaaVPPMY/ioYRv623rlmIsq7H6o7bLwQ5j1B++yCUE0DSpv4wslBsOR7P9NFerWfyaQB62vMTg+eW0i64gVJYzxYTRzb5YfrSu/9T9mqNTPGq/ATvgubDw9+KqfUta33qk5ISdRGMFzrnOr/o7mvSAQQsTFROO5pTNHGeBcJsbdBqA0b7QD7TwNLdayYH7+RzZZ7ZwSXXXiUUk5VMmCripm1U0H0H114qAlXcBV92qr87UQ8por64K7Q=="
        snp_report = "AwAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAEAAAAAAAY2yUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX+7jDW1+Gin0A9cKQZgjfd+xMFGi1pdkOUh8YJOI7X+YGJiHkgqy+gCWkDoMI/yhT0RIxn88jfyN6KXjcSXYB9rcxB8GzyP2FdvVLux3fRAK15zrC2SLDmqQ2KqfbqJMM6lotmMghTUxReixmkdBotq5ujQuE75PwNIl6InMGlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD3DuYayvQtDCwXv0opnMV6yGPOHq3gQJTuUPEG1HXwJv//////////////////////////////////////////BAAAAAAAGNsZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAABzxsa4n16go5M5xtaLF2+pnzTEcm5uA3blRaXVJVcTkyb6gNTx39Xg1g3RUnLrCkwVerN3m4DCB9S2FCXuXmi+BAAAAAAAGNsdNwEAHTcBAAQAAAAAABjbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFBTdDQ5/A3p3s++bzOD793PE1QECHvfJeeu0NqHTUmUSvUlrn2Qukya1MO1d+BoQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAerr4p1RFQZqmMQQzkgOWP3X2zAlL7qv4C9sK3NZdWvfxW3Zz4PyUir2GrVU91ZM7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        # AMD JSON format to single certificate chain
        snp_e_json = json.loads(base64.b64decode(snp_endorsements))
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
                "msft-css-dev": {
                    "attestation": snp_r,
                    "snp_endorsements": snp_e,
                    "uvm_endorsements": uvm_e,
                }
            },
        )

    def test_attestation_verification(
        self, client: Client, configure_service, signed_statement_with_attestation
    ):
        policy_script = """
        export function apply(phdr, uhdr, payload) {
            var claims = snp_attestation.verifySnpAttestation(
                phdr["msft-css-dev"].attestation,
                phdr["msft-css-dev"].snp_endorsements,
                phdr["msft-css-dev"].uvm_endorsements
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
            if (container_security_policy_digest !== "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10")
            {
                throw new Error("Invalid container security policy digest");
            }
            return true;
        }
        """
        configure_service({"policy": {"policyScript": policy_script}})

        client.submit_signed_statement_and_wait(signed_statement_with_attestation)
