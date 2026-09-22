# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
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

from pyscitt.cli.validate import build_trust_store
from pyscitt.crypto import CWT_ISS, CWTClaims, SCITTReceipts
from pyscitt.verify import (
    DEFAULT_AUTHORIZED_DOMAINS,
    DynamicTrustStore,
    DynamicTrustStoreClient,
    FallbackTrustStore,
    StaticTrustStore,
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

    @pytest.mark.parametrize(
        "issuer,authorized,expected",
        [
            ("ledger.confidential-ledger.azure.com", None, True),
            ("evil.example.com", None, True),
            ("ledger.confidential-ledger.azure.com", DEFAULT_AUTHORIZED_DOMAINS, True),
            ("Ledger.Confidential-Ledger.Azure.Com", DEFAULT_AUTHORIZED_DOMAINS, True),
            ("evil.example.com", DEFAULT_AUTHORIZED_DOMAINS, False),
            # A wildcard only covers one label boundary upwards, as in TLS.
            (
                "confidential-ledger.azure.com",
                DEFAULT_AUTHORIZED_DOMAINS,
                False,
            ),
            ("ledger.confidential-ledger.azure.com", ["*"], True),
            (
                "ledger.confidential-ledger.azure.com",
                ["ledger.confidential-ledger.azure.com"],
                True,
            ),
            (
                "other.confidential-ledger.azure.com",
                ["ledger.confidential-ledger.azure.com"],
                False,
            ),
            # An issuer which is not a bare hostname can never be authorized:
            # it would address a host other than the one it appears to name.
            (
                "evil.com/x.confidential-ledger.azure.com",
                DEFAULT_AUTHORIZED_DOMAINS,
                False,
            ),
            ("evil.com#.confidential-ledger.azure.com", ["*"], False),
            ("user@evil.com.confidential-ledger.azure.com", ["*"], False),
            ("evil.com/x.confidential-ledger.azure.com", None, False),
        ],
    )
    def test_is_authorized_issuer(self, issuer, authorized, expected):
        trust_store = DynamicTrustStore(Mock(), authorized_domains=authorized)
        assert trust_store.is_authorized_issuer(issuer) is expected

    def test_get_key_refuses_unauthorized_issuer(self):
        receipt = Sign1Message()
        receipt.phdr = {CWTClaims: {CWT_ISS: "evil.example.com"}, KID: b"kid"}
        receipt.payload = b""
        receipt._signature = b"sig"
        client = Mock()

        trust_store = DynamicTrustStore(
            client, authorized_domains=DEFAULT_AUTHORIZED_DOMAINS
        )
        with pytest.raises(ValueError, match="not an authorized domain"):
            trust_store.get_key(receipt.encode(tag=True, sign=False))

        client.get_jwks.assert_not_called()


class TestFallbackTrustStore:
    def _receipt(self) -> bytes:
        receipt = Sign1Message()
        receipt.phdr = {
            CWTClaims: {CWT_ISS: "ledger.confidential-ledger.azure.com"},
            KID: b"kid",
        }
        receipt.payload = b""
        receipt._signature = b"sig"
        return receipt.encode(tag=True, sign=False)

    def test_prefers_local_key(self):
        local, remote = Mock(), Mock()
        local.get_key.return_value = "local_key"

        store = FallbackTrustStore(local, remote)

        assert store.get_key(self._receipt()) == "local_key"
        assert store.verification_key_sources == ["trust_store"]
        remote.get_key.assert_not_called()

    def test_downloads_key_when_missing_locally(self):
        local, remote = Mock(), Mock()
        local.get_key.side_effect = KeyError(b"kid")
        remote.get_key.return_value = "downloaded_key"

        store = FallbackTrustStore(local, remote)
        receipt = self._receipt()

        assert store.get_key(receipt) == "downloaded_key"
        assert store.verification_key_sources == ["downloaded"]
        remote.get_key.assert_called_once_with(receipt)

    def test_reports_both_failures(self):
        local, remote = Mock(), Mock()
        local.get_key.side_effect = KeyError("missing locally")
        remote.get_key.side_effect = ValueError("not an authorized domain")

        store = FallbackTrustStore(local, remote)

        with pytest.raises(ValueError, match="could not be downloaded"):
            store.get_key(self._receipt())
        assert store.verification_key_sources == []

    def test_does_not_download_on_unexpected_local_failure(self):
        local, remote = Mock(), Mock()
        local.get_key.side_effect = OSError("trust store is unreadable")

        store = FallbackTrustStore(local, remote)

        with pytest.raises(OSError):
            store.get_key(self._receipt())
        remote.get_key.assert_not_called()


class TestBuildTrustStore:
    def test_downloads_by_default_without_trust_store(self):
        store = build_trust_store()
        assert isinstance(store, DynamicTrustStore)
        assert store.authorized_domains == DEFAULT_AUTHORIZED_DOMAINS

    def test_falls_back_to_download_with_trust_store(self, tmp_path):
        store = build_trust_store(tmp_path)
        assert isinstance(store, FallbackTrustStore)
        assert isinstance(store.local, StaticTrustStore)
        assert store.remote.authorized_domains == DEFAULT_AUTHORIZED_DOMAINS

    def test_custom_authorized_domains(self, tmp_path):
        store = build_trust_store(tmp_path, ["my.example.com"])
        assert store.remote.authorized_domains == ["my.example.com"]

    def test_offline_never_downloads(self, tmp_path):
        store = build_trust_store(tmp_path, offline=True)
        assert isinstance(store, StaticTrustStore)

    def test_offline_requires_trust_store(self):
        with pytest.raises(ValueError, match="--offline requires"):
            build_trust_store(offline=True)


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

    @patch("pyscitt.verify.load_pem_public_key")
    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.sha256")
    @patch("pyscitt.verify.jwk.JWK.from_json")
    def test_assert_tls_in_jwks_raises_when_key_not_found(
        self, mock_jwk_from_json, mock_sha256, mock_load_cert, mock_load_pub_key
    ):
        # Mock certificate loading and hashing
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_load_cert.return_value = mock_cert

        # Mock digests
        mock_tls_digest = Mock()
        mock_tls_digest.digest.return_value.hex.return_value = "tls_cert_digest"
        mock_sha256.side_effect = lambda x: (
            mock_tls_digest if x == b"mock_public_bytes" else DEFAULT
        )

        # JWKS key setup
        mock_jwks_key = Mock()
        mock_jwks_key.export_to_pem.return_value = b"jwks_pem"
        mock_jwk_from_json.return_value = mock_jwks_key

        # Mock JWK pub key loading
        mock_jwks_public_key = Mock()
        mock_jwks_public_key.public_bytes.return_value = b"jwks_public_bytes"
        mock_load_pub_key.return_value = mock_jwks_public_key

        jwks = {"keys": [{"kid": "test_kid"}]}
        client = DynamicTrustStoreClient()

        with pytest.raises(
            ValueError, match="TLS public key digest tls_cert_digest not found in JWKS"
        ):
            client._assert_tls_in_jwks("certificate", jwks)

        # Verify all expected calls
        mock_load_cert.assert_called_once()
        mock_load_pub_key.assert_called_once()
        mock_sha256.assert_called()
        assert len(mock_sha256.call_args_list) == 2
        mock_jwk_from_json.assert_called_once_with('{"kid": "test_kid"}')

    @patch("pyscitt.verify.load_pem_public_key")
    @patch("pyscitt.verify.x509.load_pem_x509_certificate")
    @patch("pyscitt.verify.sha256")
    @patch("pyscitt.verify.jwk.JWK.from_json")
    def test_assert_tls_in_jwks_succeeds_when_key_found(
        self, mock_jwk_from_json, mock_sha256, mock_load_cert, mock_load_pub_key
    ):
        # Mock certificate loading and hashing
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_cert.public_key.return_value = mock_public_key
        mock_public_key.public_bytes.return_value = b"mock_public_bytes"
        mock_load_cert.return_value = mock_cert

        # Mock digests
        mock_digest = Mock()
        mock_digest.digest.return_value.hex.return_value = "same_digest"
        mock_sha256.return_value = mock_digest

        # JWKS key setup
        mock_jwks_key = Mock()
        mock_jwks_key.export_to_pem.return_value = b"jwks_pem"
        mock_jwk_from_json.return_value = mock_jwks_key

        # Mock JWK pub key loading
        mock_jwks_public_key = Mock()
        mock_jwks_public_key.public_bytes.return_value = b"jwks_public_bytes"
        mock_load_pub_key.return_value = mock_jwks_public_key

        client = DynamicTrustStoreClient()
        client._assert_tls_in_jwks("certificate", {"keys": [{"kid": "test_kid"}]})

        # Verify all expected calls
        mock_load_cert.assert_called_once()
        mock_load_pub_key.assert_called_once()
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

    def test_validate_structured_output(self):
        """Validate CLI output against a checked-in golden transparent statement."""
        from pyscitt.cli.validate import (
            format_validation_result,
            validate_transparent_statement,
        )

        golden_dir = Path(__file__).parent / "transparent_statements"
        golden_file = golden_dir / "uvm_0.2.10.cose"

        result = validate_transparent_statement(
            golden_file, service_trust_store_path=golden_dir
        )

        assert result["transparent"] is True
        assert result["statement"] == str(golden_file)
        assert result["receipts"] == [
            {
                "issuer": "esrp-cts-db.confidential-ledger.azure.com",
                "registration_txid": "458.12440",
                "signature_txid": "458.12441",
                "issued_at": 1766437888,
                "issued_at_utc": "2025-12-22T21:11:28+00:00",
                "urls": {
                    "receipt": "https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440",
                    "transparent_statement": "https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440/statement",
                },
                "verification_key_source": "trust_store",
            }
        ]

        # The JSON rendering is the default and must round-trip.
        assert json.loads(format_validation_result(result, "json")) == result

        lines = format_validation_result(result, "text").splitlines()
        assert lines == [
            "Verified receipt from issuer esrp-cts-db.confidential-ledger.azure.com, "
            "registered at 458.12440, signed at 458.12441 (2025-12-22T21:11:28+00:00)",
            "  Receipt URL: https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440",
            "  Transparent statement URL: https://esrp-cts-db.confidential-ledger.azure.com/entries/458.12440/statement",
            "  Verification key source: trust_store",
            f"Statement is transparent: {golden_file}",
        ]

    def test_error_is_reported_in_the_same_shape(self):
        """A statement which is not transparent is reported, not raised."""
        from pyscitt.cli.validate import build_error_result, format_validation_result

        statement = Path("some.cose")
        result = build_error_result(statement, ValueError("no receipt here"))

        assert result == {
            "statement": "some.cose",
            "transparent": False,
            "error": "no receipt here",
            "receipts": [],
        }
        assert json.loads(format_validation_result(result, "json")) == result
        assert format_validation_result(result, "text").splitlines() == [
            "Statement is not transparent: some.cose",
            "no receipt here",
        ]

    def test_signed_statement_is_not_transparent(self):
        """A statement with no receipt fails with a readable message."""
        signed_statement = (
            Path(__file__).parent / "payloads" / "cosesign1tool-scitt-a3be7e5.cose"
        )
        with pytest.raises(ValueError, match="carries no receipt"):
            verify_transparent_statement(
                signed_statement.read_bytes(), Mock(), b"signed_statement"
            )
