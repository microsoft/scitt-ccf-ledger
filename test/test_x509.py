# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import time

import cbor2
import pycose
import pytest
from pycose.messages import Sign1Message

from pyscitt import crypto, governance
from pyscitt.client import Client
from pyscitt.verify import TrustStore, verify_receipt

from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


@pytest.mark.parametrize(
    "length, algorithm, params",
    [
        (1, "PS384", {"kty": "rsa"}),
        (2, "PS384", {"kty": "rsa"}),
        (3, "PS384", {"kty": "rsa"}),
        (1, "ES256", {"kty": "ec", "ec_curve": "P-256"}),
    ],
)
def test_submit_claim_x5c(
    client: Client,
    trust_store: TrustStore,
    trusted_ca: X5ChainCertificateAuthority,
    length: int,
    algorithm: str,
    params: dict,
):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts for x5c.

    Test is parametrized over different signing parameters.
    """
    identity = trusted_ca.create_identity(length=length, alg=algorithm, **params)

    # Sign and submit a dummy claim using our new identity
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    receipt = client.submit_claim(claims).receipt
    # check if the header struct contains mrenclave header
    assert "enclave_measurement" in receipt.phdr
    PLATFORM = os.environ.get("PLATFORM")
    if PLATFORM == "virtual":
        assert receipt.phdr["enclave_measurement"] == ""
    elif PLATFORM == "sgx":
        assert len(receipt.phdr["enclave_measurement"]) > 0
    else:
        raise Exception("Unknown PLATFORM, should be sgx or virtual")
    verify_receipt(claims, trust_store, receipt)


def test_invalid_certificate_chain(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    # Create a certificate chain, but remove one of the intermediate certs
    x5c, private_key = trusted_ca.create_chain(length=3, kty="ec")
    del x5c[1]

    identity = crypto.Signer(private_key, x5c=x5c)
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

    with service_error("Certificate chain is invalid"):
        client.submit_claim(claims)


def test_wrong_certificate(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    """
    Submit a claim that embeds a x509 certificate chain for a different key pair.
    """

    # Create two different certificates from the CA, but use the private key of
    # one and the certificate chain of the other
    _, private_key = trusted_ca.create_chain(kty="ec")
    x5c, _ = trusted_ca.create_chain(kty="ec")
    identity = crypto.Signer(private_key, x5c=x5c)

    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

    with service_error("Signature verification failed"):
        client.submit_claim(claims)


def test_untrusted_ca(client: Client):
    """
    Submit a claim signed by a certificate issued by an untrusted CA.
    """
    untrusted_ca = X5ChainCertificateAuthority(kty="ec")
    identity = untrusted_ca.create_identity(alg="ES256", kty="ec")
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

    with service_error("Certificate chain is invalid"):
        client.submit_claim(claims)


def test_self_signed_trusted(
    client: Client,
    trust_store: TrustStore,
):
    """
    Submit a claim signed by a trusted self-signed certificate.
    """

    private_key, _ = crypto.generate_keypair(kty="ec")
    cert_pem = crypto.generate_cert(private_key, ca=False)

    proposal = governance.set_ca_bundle_proposal("x509_roots", cert_pem)
    client.governance.propose(proposal, must_pass=True)

    identity = crypto.Signer(private_key, x5c=[cert_pem])
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

    # See verifier.h's check_certificate_policy for a discussion of why we
    # choose to reject this.
    # We're pretty flexible about the error message here, because the exact
    # behaviour depends on the OpenSSL version.
    with service_error("Certificate chain"):
        client.submit_claim(claims)


def test_multiple_trusted_roots(client: Client, trust_store: TrustStore):
    first_ca = X5ChainCertificateAuthority(kty="ec")
    second_ca = X5ChainCertificateAuthority(kty="ec")

    # The cert bundles are just PEM bags of certificates.
    # We can combine them simply using string concatenation.
    proposal = governance.set_ca_bundle_proposal(
        "x509_roots", first_ca.cert_bundle + second_ca.cert_bundle
    )
    client.governance.propose(proposal, must_pass=True)

    first_identity = first_ca.create_identity(alg="ES256", kty="ec")
    first_claims = crypto.sign_json_claimset(first_identity, {"foo": "bar"})

    second_identity = second_ca.create_identity(alg="ES256", kty="ec")
    second_claims = crypto.sign_json_claimset(second_identity, {"foo": "bar"})

    first_receipt = client.submit_claim(first_claims).receipt
    second_receipt = client.submit_claim(second_claims).receipt

    verify_receipt(first_claims, trust_store, first_receipt)
    verify_receipt(second_claims, trust_store, second_receipt)


def test_self_signed_untrusted(client: Client):
    """
    Submit a claim signed by a untrusted self-signed certificate.
    """
    private_key, _ = crypto.generate_keypair(kty="ec")
    cert_pem = crypto.generate_cert(private_key, ca=False)

    identity = crypto.Signer(private_key, x5c=[cert_pem])
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

    with service_error("Certificate chain is invalid"):
        client.submit_claim(claims)


def test_leaf_ca(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    """
    Submit claims signed by a leaf certificate with the CA flag set.
    """
    identity = trusted_ca.create_identity(alg="ES256", kty="ec", ca=True)
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    with service_error("Signing certificate is CA"):
        client.submit_claim(claims).receipt


def test_root_ca(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    """
    Submit claims signed by the trusted root CA.
    """

    identity = crypto.Signer(trusted_ca.root_key_pem, x5c=[trusted_ca.root_cert_pem])
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    with service_error("Certificate chain must include at least one CA certificate"):
        client.submit_claim(claims).receipt


@pytest.mark.parametrize(
    "length, algorithm, params",
    [
        (1, "PS384", {"kty": "rsa"}),
        (2, "PS384", {"kty": "rsa"}),
        (1, "ES256", {"kty": "ec", "ec_curve": "P-256"}),
    ],
)
def test_submit_claim_notary_x509(
    client: Client,
    trust_store: TrustStore,
    trusted_ca: X5ChainCertificateAuthority,
    length: int,
    algorithm: str,
    params: dict,
):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts for x5c.

    Test is parametrized over different signing parameters.
    """
    identity = trusted_ca.create_identity(length=length, alg=algorithm, **params)

    phdr: dict = {}
    phdr[pycose.headers.Algorithm] = identity.algorithm
    phdr[pycose.headers.ContentType] = "application/vnd.cncf.notary.payload.v1+json"
    phdr[pycose.headers.Critical] = ["io.cncf.notary.signingScheme"]
    phdr["io.cncf.notary.signingTime"] = cbor2.CBORTag(1, int(time.time()))
    phdr["io.cncf.notary.signingScheme"] = "notary.x509"

    uhdr: dict = {}
    assert identity.x5c is not None
    uhdr[pycose.headers.X5chain] = [crypto.cert_pem_to_der(x5) for x5 in identity.x5c]
    uhdr["io.cncf.notary.signingAgent"] = "Notation/1.0.0"

    payload = json.dumps(
        {
            "targetArtifact": {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": "sha256:beac45bd57e10fa6b607fb84daa51dce8d81928f173d215f1f3544c07f90c8c1",
                "size": 942,
            }
        }
    ).encode("utf-8")

    msg = Sign1Message(phdr=phdr, uhdr=uhdr, payload=payload)
    msg.key = crypto.cose_private_key_from_pem(identity.private_key)
    claim = msg.encode(tag=True)

    submission = client.submit_claim(claim)
    verify_receipt(claim, trust_store, submission.receipt)

    # Embedding the receipt requires re-encoding the unprotected header.
    # Notary has x5chain in the unprotected header.
    # This checks whether x5chain is preserved after re-encoding by simply
    # submitting the claim again.
    claim_with_receipt = client.get_claim(submission.tx, embed_receipt=True)
    client.submit_claim(claim_with_receipt)
