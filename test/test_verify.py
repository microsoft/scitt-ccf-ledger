# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from unittest.mock import ANY, DEFAULT, MagicMock, Mock, patch

import cbor2
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

    @patch("pyscitt.verify.jwk.JWK.from_json")
    @patch("pyscitt.verify.Sign1Message")
    @patch("pyscitt.verify.load_pem_public_key")
    def test_get_key_retrieves_from_jwks(
        self, mock_load_key, mock_sign1, mock_jwk_from_json
    ):
        # Setup mocks
        mock_receipt = b"test_receipt"
        mock_parsed = Mock()
        mock_cwt = {CWT_ISS: "example.com"}
        mock_kid = b"test_kid"
        mock_parsed.phdr = {CWTClaims: mock_cwt, KID: mock_kid}
        mock_sign1.decode.return_value = mock_parsed
        mock_matched_jwk = MagicMock()
        mock_matched_jwk.export_to_pem.return_value = b"mock_pem"
        mock_jwk_from_json.return_value = mock_matched_jwk
        mock_return_key = Mock()
        mock_load_key.return_value = mock_return_key
        mock_client = Mock()
        mock_client.get_jwks.return_value = {
            "keys": [{"kid": "test_kid", "kty": "RSA"}]
        }

        # Create instance and call method
        trust_store = DynamicTrustStore(mock_client)
        result = trust_store.get_key(mock_receipt)

        # Assertions
        mock_sign1.decode.assert_called_once_with(mock_receipt)
        mock_client.get_jwks.assert_called_once_with("example.com")
        mock_load_key.assert_called_once_with(
            b"mock_pem",
            pytest.importorskip("cryptography.hazmat.backends").default_backend(),
        )
        assert result == mock_return_key


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

    @patch("pyscitt.verify.DynamicTrustStoreClient.get_confidential_ledger_tls_pem")
    @patch("pyscitt.verify.DynamicTrustStoreClient._assert_tls_in_jwks")
    def test_get_jwks_validates_tls_cert(
        self, mock_assert_tls_in_jwks, mock_get_confidential_ledger_tls_pem
    ):
        # key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # subject = issuer = x509.Name(
        #     [
        #         x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        #         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pays de la Loire"),
        #         x509.NameAttribute(NameOID.LOCALITY_NAME, "Nantes"),
        #         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        #         x509.NameAttribute(NameOID.COMMON_NAME, "mycompany.com"),
        #     ]
        # )
        # test_cert = (
        #     x509.CertificateBuilder()
        #     .subject_name(subject)
        #     .issuer_name(issuer)
        #     .public_key(key.public_key())
        #     .serial_number(x509.random_serial_number())
        #     .not_valid_before(datetime.utcnow())
        #     .not_valid_after(datetime.utcnow() + timedelta(days=365))
        #     .sign(key, hashes.SHA256())
        # )

        # Setup mocks
        mock_get_confidential_ledger_tls_pem.return_value = "mock_pem_cert"
        mock_httpx_client = Mock()

        def get_side_effect(*args, **kwargs):
            if (
                args[0]
                == "https://foobar.confidential-ledger.azure.com/.well-known/transparency-configuration"
            ):
                with BytesIO() as fp:
                    cbor2.CBOREncoder(fp).encode(
                        {
                            "jwks_uri": "https://foobar.confidential-ledger.azure.com/jwks"
                        }
                    )

                return httpx.Response(
                    200,
                    content=cbor2.dumps(
                        {
                            "jwks_uri": "https://foobar.confidential-ledger.azure.com/jwks"
                        }
                    ),
                    request=httpx.Request("GET", args[0]),
                )
            if args[0] == "https://foobar.confidential-ledger.azure.com/jwks":
                return httpx.Response(
                    200, json={"keys": ["test"]}, request=httpx.Request("GET", args[0])
                )

        mock_httpx_client.get = Mock(side_effect=get_side_effect)

        # Create instance and call method
        trust_store_client = DynamicTrustStoreClient(
            forced_httpclient=mock_httpx_client
        )
        result = trust_store_client.get_jwks("foobar.confidential-ledger.azure.com")

        # Assertions
        mock_assert_tls_in_jwks.assert_called_once_with(
            "mock_pem_cert", {"keys": ["test"]}
        )
        assert result == {"keys": ["test"]}

    def test_assert_tls_in_jwks_raises_for_empty_tls_pem(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="TLS PEM certificate is required"):
            client._assert_tls_in_jwks("", {"keys": []})

    def test_assert_tls_in_jwks_raises_for_none_jwks(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="JWKS is required"):
            client._assert_tls_in_jwks("certificate", None)

    def test_assert_tls_in_jwks_raises_for_missing_keys(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="JWKS does not contain 'keys'"):
            client._assert_tls_in_jwks("certificate", {"other_key": []})

    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.sha256")
    @patch("pyscitt.verify.jwk.JWK.from_json")
    def test_assert_tls_in_jwks_raises_when_key_not_found(
        self, mock_jwk_from_json, mock_sha256, mock_load_cert
    ):
        # Mock certificate loading and hashing
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_jwks_cert = Mock()
        mock_jwks_public_key = Mock()
        mock_jwks_cert.public_key.return_value = mock_jwks_public_key
        mock_jwks_public_key.public_bytes.return_value = b"jwks_public_bytes"
        # Second call is for JWKS key
        mock_load_cert.side_effect = [mock_cert, mock_jwks_cert]

        # cert digests
        mock_tls_digest = Mock()
        mock_tls_digest.digest.return_value.hex.return_value = "tls_cert_digest"
        mock_sha256.side_effect = lambda x: (
            mock_tls_digest if x == b"mock_public_bytes" else DEFAULT
        )

        # JWKS key setup
        mock_jwks_key = Mock()
        mock_jwks_key.export_to_pem.return_value = b"jwks_pem"
        mock_jwk_from_json.return_value = mock_jwks_key

        jwks = {"keys": [{"kid": "test_kid"}]}
        client = DynamicTrustStoreClient()

        with pytest.raises(
            ValueError, match="TLS public key digest tls_cert_digest not found in JWKS"
        ):
            client._assert_tls_in_jwks("certificate", jwks)

        # Verify all expected calls
        mock_load_cert.assert_called()
        assert len(mock_load_cert.call_args_list) == 2
        mock_sha256.assert_called()
        assert len(mock_sha256.call_args_list) == 2
        mock_jwk_from_json.assert_called_once_with('{"kid": "test_kid"}')

    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.sha256")
    @patch("pyscitt.verify.jwk.JWK.from_json")
    def test_assert_tls_in_jwks_succeeds_when_key_found(
        self, mock_jwk_from_json, mock_sha256, mock_load_cert
    ):
        # Mock certificate loading and hashing
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_load_cert.return_value = mock_cert

        # Same digest for both TLS cert and JWKS key
        mock_digest = Mock()
        mock_digest.digest.return_value.hex.return_value = "same_digest"
        mock_sha256.return_value = mock_digest

        # JWKS key setup
        mock_jwks_key = Mock()
        mock_jwks_key.export_to_pem.return_value = b"jwks_pem"
        mock_jwk_from_json.return_value = mock_jwks_key

        client = DynamicTrustStoreClient()
        client._assert_tls_in_jwks("certificate", {"keys": [{"kid": "test_kid"}]})

        # Verify all expected calls
        mock_load_cert.assert_called()
        assert len(mock_load_cert.call_args_list) == 2
        mock_sha256.assert_called()
        assert len(mock_sha256.call_args_list) == 2
        mock_jwk_from_json.assert_called_once_with('{"kid": "test_kid"}')

    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.jwk.JWK.from_json")
    @patch("builtins.print")
    def test_assert_tls_in_jwks_handles_invalid_jwks_key(
        self, mock_print, mock_jwk_from_json, mock_load_cert
    ):
        # Mock certificate loading for TLS cert
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_load_cert.return_value = mock_cert

        # Mock JWK parsing to raise exception
        mock_jwk_from_json.side_effect = Exception("Invalid JWK")

        client = DynamicTrustStoreClient()
        # Should raise because no valid keys were found
        with pytest.raises(
            ValueError, match="TLS public key digest .* not found in JWKS"
        ):
            client._assert_tls_in_jwks("certificate", {"keys": [{"kid": "test_kid"}]})

        # Verify warning was printed
        mock_print.assert_called_with("Warning: Could not parse JWKS key: Invalid JWK")
