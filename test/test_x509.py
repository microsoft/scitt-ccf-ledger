# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import time

import cbor2
import pycose
import pytest
from pycose.keys.cosekey import CoseKey
from pycose.messages import Sign1Message

from pyscitt import crypto, governance
from pyscitt.client import Client
from pyscitt.verify import TrustStore, verify_transparent_statement

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
def test_register_statement_x5c(
    client: Client,
    trust_store: TrustStore,
    trusted_ca: X5ChainCertificateAuthority,
    length: int,
    algorithm: str,
    params: dict,
):
    """
    Submit signed statements to the SCITT CCF ledger and verify the resulting transparent for x5c.

    Test is parametrized over different signing parameters.
    """
    identity = trusted_ca.create_identity(length=length, alg=algorithm, **params)

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})
    transparent_statement = client.submit_signed_statement_and_wait(
        signed_statement
    ).response_bytes
    verify_transparent_statement(transparent_statement, trust_store, signed_statement)


def test_invalid_certificate_chain(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    # Create a certificate chain, but remove one of the intermediate certs
    x5c, private_key = trusted_ca.create_chain(length=3, kty="ec")
    del x5c[1]

    identity = crypto.Signer(private_key, x5c=x5c)
    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})

    with service_error("Certificate chain is invalid"):
        client.submit_signed_statement_and_wait(signed_statement)


def test_wrong_certificate(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    """
    Submit a signed statement that embeds a x509 certificate chain for a different key pair.
    """

    # Create two different certificates from the CA, but use the private key of
    # one and the certificate chain of the other
    _, private_key = trusted_ca.create_chain(kty="ec")
    x5c, _ = trusted_ca.create_chain(kty="ec")
    identity = crypto.Signer(private_key, x5c=x5c)

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})

    with service_error("Signature verification failed"):
        client.submit_signed_statement_and_wait(signed_statement)


def test_untrusted_ca(client: Client):
    """
    Submit a signed statement by a certificate issued by an untrusted CA.
    """
    untrusted_ca = X5ChainCertificateAuthority(kty="ec")
    identity = untrusted_ca.create_identity(alg="ES256", kty="ec")
    signged_statement = crypto.sign_json_statement(identity, {"foo": "bar"})

    with service_error("Certificate chain is invalid"):
        client.submit_signed_statement_and_wait(signged_statement)


def test_self_signed_trusted(
    client: Client,
    trust_store: TrustStore,
):
    """
    Submit a signed statement by a trusted self-signed certificate.
    """

    private_key, _ = crypto.generate_keypair(kty="ec")
    cert_pem = crypto.generate_cert(private_key, ca=False)

    proposal = governance.set_ca_bundle_proposal("x509_roots", cert_pem)
    client.governance.propose(proposal, must_pass=True)

    identity = crypto.Signer(private_key, x5c=[cert_pem])
    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})

    # See verifier.h's check_certificate_policy for a discussion of why we
    # choose to reject this.
    # We're pretty flexible about the error message here, because the exact
    # behaviour depends on the OpenSSL version.
    with service_error("Certificate chain"):
        client.submit_signed_statement_and_wait(signed_statement)


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
    first_signed_statement = crypto.sign_json_statement(first_identity, {"foo": "bar"})

    second_identity = second_ca.create_identity(alg="ES256", kty="ec")
    second_signed_statement = crypto.sign_json_statement(
        second_identity, {"foo": "bar"}
    )

    first_transparent_statement = client.submit_signed_statement_and_wait(
        first_signed_statement
    ).response_bytes
    second_transparent_statement = client.submit_signed_statement_and_wait(
        second_signed_statement
    ).response_bytes

    verify_transparent_statement(
        first_transparent_statement, trust_store, first_signed_statement
    )
    verify_transparent_statement(
        second_transparent_statement, trust_store, second_signed_statement
    )


def test_self_signed_untrusted(client: Client):
    """
    Submit a signed statement by a untrusted self-signed certificate.
    """
    private_key, _ = crypto.generate_keypair(kty="ec")
    cert_pem = crypto.generate_cert(private_key, ca=False)

    identity = crypto.Signer(private_key, x5c=[cert_pem])
    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})

    with service_error("Certificate chain is invalid"):
        client.submit_signed_statement_and_wait(signed_statement)


def test_leaf_ca(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    """
    Submit signed statement by a leaf certificate with the CA flag set.
    """
    identity = trusted_ca.create_identity(alg="ES256", kty="ec", ca=True)
    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})
    with service_error("Signing certificate is CA"):
        client.submit_signed_statement_and_wait(signed_statement).receipt


def test_root_ca(
    client: Client,
    trusted_ca: X5ChainCertificateAuthority,
):
    """
    Submit signed statement by the trusted root CA.
    """

    identity = crypto.Signer(trusted_ca.root_key_pem, x5c=[trusted_ca.root_cert_pem])
    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"})
    with service_error("Certificate chain must include at least one CA certificate"):
        client.submit_signed_statement_and_wait(signed_statement).receipt


def strip_uhdr(cose: bytes) -> bytes:
    """
    Strip the uhdr from a COSE message.
    """
    msg = Sign1Message.decode(cose)
    msg.uhdr = {}
    return msg.encode(tag=True, sign=False)
