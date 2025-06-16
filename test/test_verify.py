# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import ANY, MagicMock, Mock, patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from pycose.headers import KID
from pycose.messages import Sign1Message

from pyscitt.crypto import CWT_ISS, CWTClaims
from pyscitt.verify import DynamicTrustStore, DynamicTrustStoreClient


class TestDynamicTrustStore:
    def test_init_creates_client_if_none_provided(self):
        trust_store = DynamicTrustStore()
        assert isinstance(trust_store.client, DynamicTrustStoreClient)

    def test_init_uses_provided_client(self):
        client = Mock()
        trust_store = DynamicTrustStore(client)
        assert trust_store.client is client

    def test_services_property_raises_not_implemented(self):
        trust_store = DynamicTrustStore()
        with pytest.raises(NotImplementedError):
            _ = trust_store.services

    @patch("pyscitt.verify.Sign1Message")
    @patch("pyscitt.verify.load_pem_public_key")
    def test_get_key_retrieves_from_jwks(self, mock_load_key, mock_sign1):
        # Setup mocks
        mock_receipt = b"test_receipt"
        mock_parsed = Mock()
        mock_cwt = {CWT_ISS: "example.com"}
        mock_kid = b"test_kid"
        mock_parsed.phdr = {CWTClaims: mock_cwt, KID: mock_kid}
        mock_sign1.decode.return_value = mock_parsed

        mock_client = Mock()
        mock_client.is_confidential_ledger_issuer.return_value = False
        mock_jwks_response = Mock()
        mock_jwks_response.raise_for_status = Mock()
        mock_jwks_response.json.return_value = {
            "keys": [{"kid": "test_kid", "kty": "RSA"}]
        }
        mock_client.get_jwks.return_value = mock_jwks_response

        mock_jwk = MagicMock()
        mock_jwk.export_to_pem.return_value = b"mock_pem"

        mock_key = Mock()
        mock_load_key.return_value = mock_key

        with patch("pyscitt.verify.jwk.JWK.from_json", return_value=mock_jwk):
            trust_store = DynamicTrustStore(mock_client)
            result = trust_store.get_key(mock_receipt)

        # Assertions
        mock_sign1.decode.assert_called_once_with(mock_receipt)
        mock_client.get_jwks.assert_called_once_with("example.com")
        mock_jwks_response.raise_for_status.assert_called_once()
        mock_load_key.assert_called_once_with(
            b"mock_pem",
            pytest.importorskip("cryptography.hazmat.backends").default_backend(),
        )
        assert result == mock_key

    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.Sign1Message")
    @patch("pyscitt.verify.load_pem_public_key")
    @patch("pyscitt.verify.sha256")
    def test_get_key_validates_cl_tls_cert(
        self, mock_sha256, mock_load_key, mock_sign1, mock_load_cert
    ):
        # create test certificate
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pays de la Loire"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Nantes"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
                x509.NameAttribute(NameOID.COMMON_NAME, "mycompany.com"),
            ]
        )
        test_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )

        # Setup mocks
        mock_receipt = b"test_receipt"
        mock_parsed = Mock()
        mock_cwt = {CWT_ISS: "test.confidential-ledger.azure.com"}
        mock_kid = b"test_kid"
        mock_kid_hex = "746573745f6b6964"  # hex representation of "test_kid"
        mock_parsed.phdr = {CWTClaims: mock_cwt, KID: bytes(mock_kid_hex, "utf-8")}
        mock_sign1.decode.return_value = mock_parsed

        mock_client = Mock()
        mock_client.is_confidential_ledger_issuer.return_value = True
        mock_client.confidential_ledger_certs = {
            "test.confidential-ledger.azure.com": "mock_pem_cert"
        }

        mock_jwks_response = Mock()
        mock_jwks_response.raise_for_status = Mock()
        mock_jwks_response.json.return_value = {
            "keys": [{"kid": mock_kid_hex, "kty": "RSA"}]
        }
        mock_client.get_jwks.return_value = mock_jwks_response

        # Mock the sha256 result for TLS cert validation
        mock_sha_obj = Mock()
        mock_sha_obj.digest.return_value = mock_kid
        mock_sha256.return_value = mock_sha_obj

        # Mock the key loading
        mock_key = Mock()
        mock_load_key.side_effect = [mock_key]

        mock_jwk = MagicMock()
        mock_jwk.export_to_pem.return_value = b"mock_pem"

        mock_load_cert.return_value = test_cert

        with patch("pyscitt.verify.jwk.JWK.from_json", return_value=mock_jwk):
            trust_store = DynamicTrustStore(mock_client)
            result = trust_store.get_key(mock_receipt)

        mock_load_cert.assert_called_once_with(b"mock_pem_cert", ANY)
        assert mock_load_key.call_count == 1  # Called for both TLS cert and JWKS
        assert result == mock_key


class TestDynamicTrustStoreClient:
    def test_init_sets_default_values(self):
        client = DynamicTrustStoreClient()
        assert client.retries == 5
        assert client._forced_httpclient is None

    def test_init_accepts_forced_client(self):
        forced_client = httpx.Client()
        client = DynamicTrustStoreClient(forced_httpclient=forced_client)
        assert client._forced_httpclient is forced_client

    def test_client_returns_forced_client_when_provided(self):
        forced_client = httpx.Client()
        client = DynamicTrustStoreClient(forced_httpclient=forced_client)
        assert client._client() is forced_client

    @patch("pyscitt.verify.httpx.Client")
    @patch("pyscitt.verify.httpx.HTTPTransport")
    @patch("pyscitt.verify.ssl")
    def test_client_creates_new_client_with_cadata(
        self, mock_ssl, mock_transport, mock_client
    ):
        client = DynamicTrustStoreClient()
        result = client._client(cadata="test_cert")
        mock_ssl.create_default_context.assert_called_once()
        mock_transport.assert_called_once()
        mock_client.assert_called_once()

    def test_is_confidential_ledger_issuer(self):
        client = DynamicTrustStoreClient()
        assert (
            client.is_confidential_ledger_issuer("test.confidential-ledger.azure.com")
            is True
        )
        assert client.is_confidential_ledger_issuer("example.com") is False

    @patch("pyscitt.verify.ConfidentialLedgerCertificateClient")
    def test_get_confidential_ledger_tls_pem(self, mock_cl_client):
        mock_identity_client = Mock()
        mock_cl_client.return_value = mock_identity_client
        mock_identity_client.get_ledger_identity.return_value = {
            "ledgerTlsCertificate": "test_cert"
        }

        client = DynamicTrustStoreClient()
        result = client.get_confidential_ledger_tls_pem(
            "test.confidential-ledger.azure.com"
        )

        mock_identity_client.get_ledger_identity.assert_called_once_with(
            ledger_id="test"
        )
        assert result == "test_cert"

    @patch("pyscitt.verify.ConfidentialLedgerCertificateClient")
    def test_get_confidential_ledger_tls_pem_raises_for_missing_cert(
        self, mock_cl_client
    ):
        mock_identity_client = Mock()
        mock_cl_client.return_value = mock_identity_client
        mock_identity_client.get_ledger_identity.return_value = {}

        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="No TLS certificate found for issuer"):
            client.get_confidential_ledger_tls_pem("test.confidential-ledger.azure.com")

    def test_get_configuration_raises_for_empty_issuer(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="Issuer cannot be empty"):
            client.get_configuration("")
