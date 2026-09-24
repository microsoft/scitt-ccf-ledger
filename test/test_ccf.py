# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import json
from hashlib import sha256

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from jwcrypto import jwk

from pyscitt import crypto
from pyscitt.client import Client, ServiceError
from pyscitt.verify import (
    DynamicTrustStore,
    DynamicTrustStoreClient,
    verify_transparent_statement,
)

from .infra.assertions import service_error

CURVE_TO_COSE_CRV = {
    "secp256r1": 1,  # P-256
    "secp384r1": 2,  # P-384
    "secp521r1": 3,  # P-521
}


def pem_cert_to_ccf_cose_key(cert_pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    pub_key = cert.public_key()
    assert isinstance(pub_key, EllipticCurvePublicKey)
    ccf_kid = (
        sha256(
            pub_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        .digest()
        .hex()
    )
    numbers = pub_key.public_numbers()
    curve = pub_key.curve
    crv = CURVE_TO_COSE_CRV[curve.name]
    key_size = (curve.key_size + 7) // 8
    return {
        1: 2,  # kty: EC2
        2: ccf_kid.encode(),  # kid (bstr per RFC 9052 Section 7)
        -1: crv,  # crv
        -2: numbers.x.to_bytes(key_size, "big"),  # x
        -3: numbers.y.to_bytes(key_size, "big"),  # y
    }


def pem_cert_to_ccf_jwk(cert_pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    pkey_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key = jwk.JWK.from_pem(pkey_pem)
    jwk_from_cert = json.loads(key.export(private_key=False))
    # jwcrypto sets the kid to the JWK thumbprint, which is not what CCF does
    # because it would not work in CBOR/COSE contexts. Instead, CCF uses the
    # SHA-256 hash of the DER-encoded public key, encoded as hex.
    # The kid is to be used as an opaque handler by clients, but we want this
    # test to be precise.
    ccf_kid = (
        sha256(
            cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        .digest()
        .hex()
    )
    jwk_from_cert["kid"] = ccf_kid
    return jwk_from_cert


def test_jwks(client: Client):
    """
    Test that the JWKS endpoint returns the expected keys.
    """

    jwks = client.get_jwks()
    assert len(jwks["keys"]) == 1

    cert_pem = client.get("/node/network").json()["service_certificate"]
    svc_jwk = pem_cert_to_ccf_jwk(cert_pem)
    assert svc_jwk == jwks["keys"][0]


def test_scitt_keys(client: Client):
    """
    Test that the SCITT keys endpoint returns the expected keys.
    """

    keys = client.get_scitt_keys()
    assert len(keys) == 1

    cert_pem = client.get("/node/network").json()["service_certificate"]
    expected = pem_cert_to_ccf_cose_key(cert_pem)
    assert expected == keys[0]


def test_scitt_key_by_kid(client: Client):
    """
    Test that a single key can be retrieved by kid.
    """
    keys = client.get_scitt_keys()
    assert len(keys) == 1
    kid = keys[0][2]  # label 2 is kid
    # Returns a single COSE Key (map), not a COSE Key Set (array)
    single_key = client.get_scitt_key(kid)
    assert isinstance(single_key, dict)
    assert single_key == keys[0]


def test_scitt_key_by_kid_not_found(client: Client):
    """
    Test that requesting a non-existent kid returns 404.
    """
    with pytest.raises(ServiceError) as exc_info:
        client.get("/.well-known/scitt-keys/nonexistent-kid")
    assert exc_info.value.code == "No such key"


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256", "add_eku": "2.999"},
        {"alg": "ES384", "kty": "ec", "ec_curve": "P-384", "add_eku": "2.999"},
        {"alg": "PS256", "kty": "rsa", "add_eku": "2.999"},
        {"alg": "PS384", "kty": "rsa", "add_eku": "2.999"},
        {"alg": "PS512", "kty": "rsa", "add_eku": "2.999"},
    ],
)
def test_make_signed_statement_transparent(
    client: Client, cert_authority, trust_store, params, configure_service
):
    """
    Register a signed statement in the SCITT CCF ledger and verify the resulting transparent statement.
    """
    identity = cert_authority.create_identity(**params)
    configure_service(
        {
            "policy": {
                "policyScript": f'export function apply(phdr) {{ return phdr.cwt.iss === "{identity.issuer}"; }}'
            }
        }
    )

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"}, cwt=True)
    transparent_statement = client.submit_signed_statement_and_wait(
        signed_statement
    ).response_bytes
    verify_transparent_statement(transparent_statement, trust_store, signed_statement)

    dynamic_trust_store = DynamicTrustStore(
        client=DynamicTrustStoreClient(forced_httpclient=client.session)
    )
    verify_transparent_statement(
        transparent_statement, dynamic_trust_store, signed_statement
    )


@pytest.mark.isolated_test
def test_recovery(client, cert_authority, restart_service, configure_service):
    identity = cert_authority.create_identity(alg="PS384", kty="rsa", add_eku="2.999")
    configure_service(
        {
            "policy": {
                "policyScript": f'export function apply(phdr) {{ return phdr.cwt.iss === "{identity.issuer}"; }}'
            }
        }
    )

    first_signed_statement = crypto.sign_json_statement(
        identity, {"foo": "bar"}, cwt=True
    )
    first_transparent_statement = client.submit_signed_statement_and_wait(
        first_signed_statement
    ).response_bytes

    old_network = client.get("/node/network").json()
    assert old_network["recovery_count"] == 0
    old_jwk = pem_cert_to_ccf_jwk(old_network["service_certificate"])
    old_cose_key = pem_cert_to_ccf_cose_key(old_network["service_certificate"])

    restart_service()

    new_network = client.get("/node/network").json()
    assert new_network["recovery_count"] == 1
    assert new_network["service_certificate"] != old_network["service_certificate"]
    new_jwk = pem_cert_to_ccf_jwk(new_network["service_certificate"])
    new_cose_key = pem_cert_to_ccf_cose_key(new_network["service_certificate"])

    # Check that the service is still operating correctly
    second_signed_statement = crypto.sign_json_statement(
        identity, {"foo": "hello"}, cwt=True
    )
    second_transparent_statement = client.submit_signed_statement_and_wait(
        second_signed_statement
    ).response_bytes

    jwks = client.get_jwks()
    assert len(jwks["keys"]) == 2
    assert old_jwk in jwks["keys"]
    assert new_jwk in jwks["keys"]

    keys = client.get_scitt_keys()
    assert len(keys) == 2
    assert old_cose_key in keys
    assert new_cose_key in keys

    dynamic_trust_store = DynamicTrustStore(
        client=DynamicTrustStoreClient(forced_httpclient=client.session)
    )
    verify_transparent_statement(
        first_transparent_statement, dynamic_trust_store, first_signed_statement
    )
    verify_transparent_statement(
        second_transparent_statement, dynamic_trust_store, second_signed_statement
    )


@pytest.mark.isolated_test
def test_transparency_configuration(client, cchost):
    issuer = f"127.0.0.1:{cchost.rpc_port}"
    reference = {"issuer": issuer, "jwks_uri": f"https://{issuer}/jwks"}
    config = client.get("/.well-known/transparency-configuration")
    assert config.status_code == 200
    assert config.headers["Content-Type"] == "application/cbor"
    assert cbor2.loads(config.content) == reference
