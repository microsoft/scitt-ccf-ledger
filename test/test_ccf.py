# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import time

import cbor2
import pycose
import pycose.headers
import pytest
from pycose.messages import Sign1Message

from pyscitt import crypto, governance
from pyscitt.client import Client, ServiceError
from pyscitt.verify import verify_receipt

from .infra.did_web_server import DIDWebServer
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


# Temporary monkey-patch for pycose until https://github.com/TimothyClaeys/pycose/pull/107
# is released.
def crit_is_array(value):
    if (
        not isinstance(value, list)
        or len(value) < 1
        or not all(isinstance(x, (int, str)) for x in value)
    ):
        raise ValueError(
            "CRITICAL should be a list with at least one integer or string element"
        )
    return value


pycose.headers.Critical.value_parser = crit_is_array


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
    receipt = client.submit_claim(claims).raw_receipt
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


def test_invalid_x5c(client: Client):
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


@pytest.mark.parametrize(
    "params,x5c_len",
    [
        ({"alg": "PS384", "kty": "rsa"}, 1),
        ({"alg": "ES256", "kty": "ec", "ec_curve": "P-256"}, 1),
    ],
)
def test_submit_claim_notary_x509(
    client: Client, trust_store, params: dict, x5c_len: int
):
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


@pytest.mark.needs_cchost
@pytest.mark.isolated_test
def test_recovery(client, did_web, restart_service):
    identity = did_web.create_identity()
    client.submit_claim(crypto.sign_json_claimset(identity, {"foo": "bar"}))

    old_network = client.get("/node/network").json()
    assert old_network["recovery_count"] == 0

    restart_service()

    new_network = client.get("/node/network").json()
    assert new_network["recovery_count"] == 1
    assert new_network["service_certificate"] != old_network["service_certificate"]

    # Check that the service is still operating correctly
    client.submit_claim(crypto.sign_json_claimset(identity, {"foo": "hello"}))
