# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os

import pytest

from infra.did_web_server import DIDWebServer
from infra.x5chain_certificate_authority import X5ChainCertificateAuthority
from pyscitt import crypto, governance
from pyscitt.client import Client, ServiceError
from pyscitt.verify import verify_receipt


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256"},
        {"alg": "ES384", "kty": "ec", "ec_curve": "P-384"},
        {"alg": "ES512", "kty": "ec", "ec_curve": "P-521"},
        {"alg": "PS256", "kty": "rsa"},
        {"alg": "PS384", "kty": "rsa"},
        {"alg": "PS512", "kty": "rsa"},
        {"alg": "EdDSA", "kty": "ed25519"},
    ],
)
def test_submit_claim(client: Client, did_web, trust_store, params):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts.

    Test is parametrized over different signing parameters.
    """
    identity = did_web.create_identity(**params)

    # Sign and submit a dummy claim using our new identity
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    receipt = client.submit_claim(claims).receipt
    verify_receipt(claims, trust_store, receipt)

    embedded = crypto.embed_receipt_in_cose(claims, receipt)
    verify_receipt(embedded, trust_store, None)


@pytest.mark.parametrize(
    "params,x5c_len",
    [
        ({"alg": "PS384", "kty": "rsa"}, 1),
        ({"alg": "PS384", "kty": "rsa"}, 2),
        ({"alg": "PS384", "kty": "rsa"}, 3),
        ({"alg": "ES256", "kty": "ec", "ec_curve": "P-256"}, 1),
    ],
)
def test_submit_claim_x5c(client: Client, trust_store, params: dict, x5c_len: int):
    """
    Submit claims to the SCITT CCF ledger and verify the resulting receipts for x5c.

    Test is parametrized over different signing parameters.
    """
    x5c_ca = X5ChainCertificateAuthority(**params)

    client.governance.propose(
        governance.set_ca_bundle_proposal("x509_roots", x5c_ca.cert_bundle),
        must_pass=True,
    )

    identity = x5c_ca.create_identity(x5c_len, **params)

    # Sign and submit a dummy claim using our new identity
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
    receipt = client.submit_claim(claims).receipt
    verify_receipt(claims, trust_store, receipt)


def test_invalid_x5c(client: Client, trust_store):
    x5c_ca = X5ChainCertificateAuthority(alg="ES256", kty="ec")
    client.governance.propose(
        governance.set_ca_bundle_proposal("x509_roots", x5c_ca.cert_bundle),
        must_pass=True,
    )

    # Create a signer with a missing certificate in the chain
    x5c, private_key = x5c_ca.create_chain(length=3, kty="ec")
    identity = crypto.Signer(private_key, x5c=x5c[1:])
    claims = crypto.sign_json_claimset(identity, {"foo": "bar"})

    with pytest.raises(ServiceError, match="Signature verification failed"):
        client.submit_claim(claims)


def test_default_did_port(client: Client, trust_store, tmp_path):
    """
    Submit a claim using a DID web server running on the default port 443.

    This test may require elevated priviledges to run, either as root or with
    CAP_NET_BIND_SERVICE. Unless the SCITT_CI environment variable is set, the
    test will be skipped if the port could not be bound.
    """

    # Unlike other tests, we don't use the did_web fixture but instead
    # instantiate a DIDWebServer manually since we need control over
    # its arguments and need to catch the exception.
    try:
        did_web = DIDWebServer(tmp_path, use_default_port=True)
    except PermissionError:
        if os.environ.get("SCITT_CI"):
            raise
        else:
            pytest.skip("Could not bind priviledged port")

    with did_web:
        cert_bundle = did_web.cert_bundle
        client.governance.propose(
            governance.set_ca_bundle_proposal("did_web_tls_roots", cert_bundle),
            must_pass=True,
        )

        identity = did_web.create_identity()

        # Sign and submit a dummy claim using our new identity
        claims = crypto.sign_json_claimset(identity, {"foo": "bar"})
        receipt = client.submit_claim(claims).receipt
        verify_receipt(claims, trust_store, receipt)


def test_consistent_kid(client, did_web, trust_store):
    """
    Submit a claim with a known kid and check that it is consistent
    in the claim header and DID document.
    """
    kid = "#key-1"
    identity = did_web.create_identity(kid=kid)

    # Sign a dummy claim using our new identity.
    claim = crypto.sign_json_claimset(identity, {"foo": "bar"})

    # Check that the COSE header contains the expected kid.
    header, _ = crypto.parse_cose_sign1(claim)
    assert header["kid"] == kid

    # Submit the claim and verify the resulting receipt.
    receipt = client.submit_claim(claim).receipt
    verify_receipt(claim, trust_store, receipt)

    # Check that the resolved DID document contains the expected assertion
    # method id.
    did_doc = client.get_did_document(identity.issuer)
    assert did_doc["assertionMethod"][0]["id"] == f"{identity.issuer}{kid}"


def test_invalid_kid(client, did_web):
    """
    Submit a claim with an invalid kid and check that it is rejected.
    """
    identity = did_web.create_identity(kid="#key-1")
    invalid_identity = crypto.Signer(
        identity.private_key, issuer=identity.issuer, kid="key-1"
    )

    claim = crypto.sign_json_claimset(invalid_identity, {"foo": "bar"})

    with pytest.raises(ServiceError, match="kid must start with '#'"):
        client.submit_claim(claim)
