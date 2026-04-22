# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

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

from pyscitt.crypto import CWT_ISS, CWTClaims, SCITTReceipts
from pyscitt.verify import (
    DynamicTrustStore,
    DynamicTrustStoreClient,
    verify_transparent_statement,
)


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

    @patch("pyscitt.verify.ec")
    @patch("pyscitt.verify.Sign1Message")
    def test_get_key_retrieves_from_cose_keys(self, mock_sign1, mock_ec):
        # Setup mocks
        mock_receipt = b"test_receipt"
        mock_parsed = Mock()
        mock_cwt = {CWT_ISS: "example.com"}
        mock_kid = b"test_kid"
        mock_parsed.phdr = {CWTClaims: mock_cwt, KID: mock_kid}
        mock_sign1.decode.return_value = mock_parsed
        mock_public_key = Mock()
        mock_public_numbers = Mock()
        mock_public_numbers.public_key.return_value = mock_public_key
        mock_ec.EllipticCurvePublicNumbers.return_value = mock_public_numbers
        mock_ec.SECP256R1.return_value = "mock_curve"
        mock_client = Mock()
        mock_client.get_scitt_keys.return_value = [
            {1: 2, 2: "test_kid", -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        ]

        # Create instance and call method
        trust_store = DynamicTrustStore(mock_client)
        result = trust_store.get_key(mock_receipt)

        # Assertions
        mock_sign1.decode.assert_called_once_with(mock_receipt)
        mock_client.get_scitt_keys.assert_called_once_with("example.com")
        mock_ec.EllipticCurvePublicNumbers.assert_called_once()
        assert result == mock_public_key


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
    @patch("pyscitt.verify.DynamicTrustStoreClient._assert_tls_in_cose_keys")
    def test_get_scitt_keys_validates_tls_cert(
        self, mock_assert_tls_in_cose_keys, mock_get_confidential_ledger_tls_pem
    ):
        # Setup mocks
        mock_get_confidential_ledger_tls_pem.return_value = "mock_pem_cert"
        mock_httpx_client = Mock()
        test_cose_keys = [
            {1: 2, 2: "test_kid", -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        ]

        def get_side_effect(*args, **kwargs):
            if (
                args[0]
                == "https://foobar.confidential-ledger.azure.com/.well-known/transparency-configuration"
            ):
                return httpx.Response(
                    200,
                    content=cbor2.dumps(
                        {
                            "jwks_uri": "https://foobar.confidential-ledger.azure.com/.well-known/scitt-keys"
                        }
                    ),
                    request=httpx.Request("GET", args[0]),
                )
            if (
                args[0]
                == "https://foobar.confidential-ledger.azure.com/.well-known/scitt-keys"
            ):
                return httpx.Response(
                    200,
                    content=cbor2.dumps(test_cose_keys),
                    request=httpx.Request("GET", args[0]),
                )

        mock_httpx_client.get = Mock(side_effect=get_side_effect)

        # Create instance and call method
        trust_store_client = DynamicTrustStoreClient(
            forced_httpclient=mock_httpx_client
        )
        result = trust_store_client.get_scitt_keys(
            "foobar.confidential-ledger.azure.com"
        )

        # Assertions
        mock_assert_tls_in_cose_keys.assert_called_once_with(
            "mock_pem_cert", test_cose_keys
        )
        assert result == test_cose_keys

    def test_assert_tls_in_cose_keys_raises_for_empty_tls_pem(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="TLS PEM certificate is required"):
            client._assert_tls_in_cose_keys("", [])

    def test_assert_tls_in_cose_keys_raises_for_none_cose_keys(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="COSE Key Set is required"):
            client._assert_tls_in_cose_keys("certificate", None)

    def test_assert_tls_in_cose_keys_raises_for_empty_cose_keys(self):
        client = DynamicTrustStoreClient()
        with pytest.raises(ValueError, match="COSE Key Set is required"):
            client._assert_tls_in_cose_keys("certificate", [])

    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.sha256")
    def test_assert_tls_in_cose_keys_raises_when_key_not_found(
        self, mock_sha256, mock_load_cert
    ):
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_load_cert.return_value = mock_cert

        mock_digest = Mock()
        mock_digest.digest.return_value.hex.return_value = "tls_cert_digest"
        mock_sha256.return_value = mock_digest

        cose_keys = [{1: 2, 2: "other_kid", -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}]
        client = DynamicTrustStoreClient()

        with pytest.raises(
            ValueError,
            match="TLS public key digest tls_cert_digest not found in COSE Key Set",
        ):
            client._assert_tls_in_cose_keys("certificate", cose_keys)

        mock_load_cert.assert_called_once()
        mock_sha256.assert_called_once()

    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.sha256")
    def test_assert_tls_in_cose_keys_succeeds_when_key_found(
        self, mock_sha256, mock_load_cert
    ):
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_load_cert.return_value = mock_cert

        mock_digest = Mock()
        mock_digest.digest.return_value.hex.return_value = "matching_digest"
        mock_sha256.return_value = mock_digest

        cose_keys = [
            {1: 2, 2: "matching_digest", -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        ]
        client = DynamicTrustStoreClient()
        # Should not raise
        client._assert_tls_in_cose_keys("certificate", cose_keys)

        mock_load_cert.assert_called_once()
        mock_sha256.assert_called_once()


class TestVerifyTransparentStatement:
    def _build_receipt(self, issuer):
        """Build a sample COSE Sign1 receipt with CWT claims containing an issuer."""
        receipt = Sign1Message()
        receipt.phdr = {
            CWTClaims: {CWT_ISS: issuer},
            KID: b"test_kid",
        }
        receipt.payload = b""
        receipt._signature = b"fake_sig"
        return receipt.encode(tag=True, sign=False)

    def _build_transparent_statement(self, receipts):
        """Build a sample transparent statement with embedded receipts."""
        ts = Sign1Message()
        ts.phdr = {}
        ts.uhdr = {SCITTReceipts: receipts}
        ts.payload = b"test payload"
        ts._signature = b"fake_sig"
        return ts.encode(tag=True, sign=False)

    @patch("pyscitt.verify.ccf.cose.verify_receipt")
    def test_returns_issuer_for_each_receipt(self, mock_verify_receipt):
        issuer = "test-issuer.example.com"
        receipt_bytes = self._build_receipt(issuer)
        ts_bytes = self._build_transparent_statement([receipt_bytes])
        signed_statement = b"signed_statement"

        mock_trust_store = Mock()
        mock_trust_store.get_key.return_value = Mock()

        details = verify_transparent_statement(
            ts_bytes, mock_trust_store, signed_statement
        )

        assert len(details) == 1
        assert details[0]["iss"] == issuer

    @patch("pyscitt.verify.ccf.cose.verify_receipt")
    def test_returns_issuers_for_multiple_receipts(self, mock_verify_receipt):
        issuers = ["issuer-a.example.com", "issuer-b.example.com"]
        receipts = [self._build_receipt(iss) for iss in issuers]
        ts_bytes = self._build_transparent_statement(receipts)
        signed_statement = b"signed_statement"

        mock_trust_store = Mock()
        mock_trust_store.get_key.return_value = Mock()

        details = verify_transparent_statement(
            ts_bytes, mock_trust_store, signed_statement
        )

        assert len(details) == 2
        assert details[0]["iss"] == issuers[0]
        assert details[1]["iss"] == issuers[1]

    @patch("pyscitt.verify.ccf.cose.verify_receipt")
    def test_returns_none_issuer_when_no_cwt_claims(self, mock_verify_receipt):
        receipt = Sign1Message()
        receipt.phdr = {KID: b"test_kid"}
        receipt.payload = b""
        receipt._signature = b"fake_sig"
        receipt_bytes = receipt.encode(tag=True, sign=False)
        ts_bytes = self._build_transparent_statement([receipt_bytes])
        signed_statement = b"signed_statement"

        mock_trust_store = Mock()
        mock_trust_store.get_key.return_value = Mock()

        details = verify_transparent_statement(
            ts_bytes, mock_trust_store, signed_statement
        )

        assert len(details) == 1
        assert details[0]["iss"] is None

    def test_validate_print_issuers(self, capsys):
        """Validate CLI output against a checked-in golden transparent statement."""
        from pyscitt.cli.validate import validate_transparent_statement

        golden_dir = Path(__file__).parent / "transparent_statements"
        golden_file = golden_dir / "uvm_0.2.10.cose"

        validate_transparent_statement(golden_file, service_trust_store_path=golden_dir)

        captured = capsys.readouterr()
        lines = captured.out.strip().splitlines()
        assert len(lines) == 2
        assert lines[0] == (
            "Verified receipt from issuer esrp-cts-db.confidential-ledger.azure.com, "
            "registered at 458.12440, signed at 458.12441 (2025-12-22T21:11:28+00:00): "
            "https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440"
        )
        assert lines[1] == f"Statement is transparent: {golden_file}"
