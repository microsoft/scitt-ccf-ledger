# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import json
from hashlib import sha256

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.verify import DynamicTrustStore, verify_transparent_statement

from .infra.assertions import service_error


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


@pytest.mark.parametrize(
    "params",
    [
        {"alg": "ES256", "kty": "ec", "ec_curve": "P-256", "add_eku": "2.999"},
        {"alg": "ES384", "kty": "ec", "ec_curve": "P-384", "add_eku": "2.999"},
        #        {"alg": "ES512", "kty": "ec", "ec_curve": "P-521", "add_eku": "2.999"}, https://github.com/microsoft/CCF/issues/6858
        {"alg": "PS256", "kty": "rsa", "add_eku": "2.999"},
        {"alg": "PS384", "kty": "rsa", "add_eku": "2.999"},
        {"alg": "PS512", "kty": "rsa", "add_eku": "2.999"},
    ],
)
def test_make_signed_statement_transparent(
    client: Client, trusted_ca, trust_store, params, configure_service
):
    """
    Register a signed statement in the SCITT CCF ledger and verify the resulting transparent statement.
    """
    identity = trusted_ca.create_identity(**params)
    configure_service(
        {
            "policy": {
                "policyScript": f'export function apply(phdr) {{ return phdr.cwt.iss === "{identity.issuer}"; }}'
            }
        }
    )

    signed_statement = crypto.sign_json_statement(identity, {"foo": "bar"}, cwt=True)
    transparent_statement = client.register_signed_statement(
        signed_statement
    ).response_bytes
    verify_transparent_statement(transparent_statement, trust_store, signed_statement)

    dynamic_trust_store = DynamicTrustStore(client.get)
    verify_transparent_statement(
        transparent_statement, dynamic_trust_store, signed_statement
    )


@pytest.mark.isolated_test
def test_recovery(client, trusted_ca, restart_service, configure_service):
    identity = trusted_ca.create_identity(alg="PS384", kty="rsa", add_eku="2.999")
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
    first_transparent_statement = client.register_signed_statement(
        first_signed_statement
    ).response_bytes

    old_network = client.get("/node/network").json()
    assert old_network["recovery_count"] == 0
    old_jwk = pem_cert_to_ccf_jwk(old_network["service_certificate"])

    restart_service()

    new_network = client.get("/node/network").json()
    assert new_network["recovery_count"] == 1
    assert new_network["service_certificate"] != old_network["service_certificate"]
    new_jwk = pem_cert_to_ccf_jwk(new_network["service_certificate"])

    # Check that the service is still operating correctly
    second_signed_statement = crypto.sign_json_statement(
        identity, {"foo": "hello"}, cwt=True
    )
    second_transparent_statement = client.register_signed_statement(
        second_signed_statement
    ).response_bytes

    jwks = client.get_jwks()
    assert len(jwks["keys"]) == 2
    assert old_jwk in jwks["keys"]
    assert new_jwk in jwks["keys"]

    dynamic_trust_store = DynamicTrustStore(client.get)
    verify_transparent_statement(
        first_transparent_statement, dynamic_trust_store, first_signed_statement
    )
    verify_transparent_statement(
        second_transparent_statement, dynamic_trust_store, second_signed_statement
    )


@pytest.mark.isolated_test
def test_transparency_configuration(client, cchost):
    issuer = f"127.0.0.1:{cchost.rpc_port}"
    reference = {"issuer": issuer, "jwksUri": f"https://{issuer}/jwks"}

    # Unsupported Accept header
    with service_error("UnsupportedContentType"):
        client.get(
            "/.well-known/transparency-configuration",
            headers={"Accept": "application/text"},
        )

    # Empty Accept header
    with service_error("UnsupportedContentType"):
        client.get(
            "/.well-known/transparency-configuration",
            headers={"Accept": ""},
        )

    config = client.get(
        "/.well-known/transparency-configuration",
        headers={"Accept": "application/json"},
    )
    assert config.status_code == 200
    assert config.headers["Content-Type"] == "application/json"
    assert config.json() == reference

    config = client.get(
        "/.well-known/transparency-configuration",
        headers={"Accept": "application/cbor"},
    )
    assert config.status_code == 200
    assert config.headers["Content-Type"] == "application/cbor"
    assert cbor2.loads(config.content) == reference

    config = client.get(
        "/.well-known/transparency-configuration", headers={"Accept": "*/*"}
    )
    assert config.status_code == 200
    assert config.headers["Content-Type"] == "application/cbor"
    assert cbor2.loads(config.content) == reference

    config = client.get("/.well-known/transparency-configuration")
    assert config.status_code == 200
    assert config.headers["Content-Type"] == "application/cbor"
    assert cbor2.loads(config.content) == reference
