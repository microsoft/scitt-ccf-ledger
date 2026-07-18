# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
import ssl
from abc import ABC, abstractmethod
from hashlib import sha256
from pathlib import Path
from typing import Dict, Optional

import cbor2
import ccf.cose
import httpx
from azure.confidentialledger.certificate import ConfidentialLedgerCertificateClient
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from cryptography.x509 import load_der_x509_certificate
from jwcrypto import jwk
from pycose.headers import KID
from pycose.keys.cosekey import CoseKey
from pycose.messages import Sign1Message

from . import crypto
from .crypto import CWT_IAT, CWT_ISS, CWTClaims

COSE_HEADER_PARAM_VDS = 395
VDS_RFC9162_SHA256 = 1
VDS_CCF = 2


class TrustStore(ABC):
    @property
    @abstractmethod
    def services(self):
        pass

    @abstractmethod
    def get_key(self, receipt: bytes) -> PublicKeyTypes:
        """
        Look up a service's public key based on the protected headers from a
        receipt. Raises an exception if not matching service is found.
        """
        raise NotImplementedError()


def verify_cose_sign1(buf: bytes, cert_pem: str):
    msg = Sign1Message.decode(buf)
    msg.key = msg.key = CoseKey.from_pem_public_key(cert_pem)
    if not msg.verify_signature():
        raise ValueError("signature is invalid")


def _rfc9162_root(entry: bytes, encoded_proof: bytes) -> bytes:
    proof = cbor2.loads(encoded_proof)
    if not isinstance(proof, list) or len(proof) != 3:
        raise ValueError("inclusion proof must contain three elements")
    tree_size, leaf_index, path = proof
    if (
        type(tree_size) is not int
        or tree_size <= 0
        or type(leaf_index) is not int
        or not 0 <= leaf_index < tree_size
    ):
        raise ValueError("invalid inclusion proof position")
    if not isinstance(path, list) or not path:
        raise ValueError("inclusion proof path must not be empty")
    if any(not isinstance(value, bytes) or len(value) != 32 for value in path):
        raise ValueError("inclusion proof path hashes must be 32 bytes")

    fn, sn = leaf_index, tree_size - 1
    root = sha256(b"\x00" + entry).digest()
    for value in path:
        if sn == 0:
            raise ValueError("inclusion proof path is too long")
        if fn & 1 or fn == sn:
            root = sha256(b"\x01" + value + root).digest()
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            root = sha256(b"\x01" + root + value).digest()
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof path is too short")
    return root


def _verify_rfc9162_receipt(
    receipt: Sign1Message,
    service_key: PublicKeyTypes,
    statement: bytes,
) -> None:
    vdp = receipt.uhdr.get(396)
    if not isinstance(vdp, dict) or set(vdp) != {-1}:
        raise ValueError("receipt vdp must contain only inclusion proofs")
    proofs = vdp[-1]
    if not isinstance(proofs, list) or not proofs:
        raise ValueError("receipt must contain at least one inclusion proof")

    entry = sha256(statement).digest()
    payload = receipt.payload
    receipt.key = CoseKey.from_pem_public_key(
        service_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
    )
    for proof in proofs:
        if not isinstance(proof, bytes):
            raise ValueError("receipt inclusion proofs must be byte strings")
        root = _rfc9162_root(entry, proof)
        if payload is not None and payload != root:
            continue
        receipt.payload = root
        if receipt.verify_signature():
            return
    raise ValueError("receipt signature is invalid")


def verify_receipt(
    receipt: bytes,
    service_key: PublicKeyTypes,
    input_signed_statement: bytes,
) -> None:
    parsed = Sign1Message.decode(receipt)
    vds = parsed.phdr.get(COSE_HEADER_PARAM_VDS)

    if type(vds) is not int:
        raise ValueError(f"unsupported receipt vds: {vds}")

    if vds == VDS_RFC9162_SHA256:
        _verify_rfc9162_receipt(parsed, service_key, input_signed_statement)
        return

    if vds == VDS_CCF:
        ccf.cose.verify_receipt(
            receipt,
            service_key,  # type: ignore[arg-type]
            sha256(input_signed_statement).digest(),
        )
        return

    raise ValueError(f"unsupported receipt vds: {vds}")


def verify_transparent_statement(
    transparent_statement: bytes,
    service_trust_store: TrustStore,
    input_signed_statement: bytes,
) -> list:
    st = Sign1Message.decode(transparent_statement)
    receipt_details = []
    for receipt in st.uhdr[crypto.SCITTReceipts]:
        service_key = service_trust_store.get_key(receipt)
        verify_receipt(receipt, service_key, input_signed_statement)

        # ccf.cose.verify_receipt should be improved to return full detail from the receipt
        # at which point the following parsing can be removed and the details can be returned directly from the verify_receipt function.
        parsed = Sign1Message.decode(receipt)
        issuer = None
        iat = None
        if CWTClaims in parsed.phdr:
            cwt = parsed.phdr[CWTClaims]
            issuer = cwt.get(CWT_ISS)
            iat = cwt.get(CWT_IAT)

        # Extract txid from ccf.v1 protected header
        sigtxid = None
        ccf_v1 = parsed.phdr.get("ccf.v1")
        if isinstance(ccf_v1, dict):
            sigtxid = ccf_v1.get("txid")

        # Extract registration txid from internal-evidence in inclusion proof leaf
        regtxid = None
        uhdr = parsed.uhdr
        if 396 in uhdr:
            inclusion_proofs = uhdr[396].get(-1, [])
            if inclusion_proofs:
                proof = cbor2.loads(inclusion_proofs[0])
                if isinstance(proof, dict):
                    leaf = proof.get(1)
                    if leaf and len(leaf) > 1:
                        ce = leaf[1]
                        parts = ce.split(":") if isinstance(ce, str) else []
                        if len(parts) >= 2:
                            regtxid = parts[1]

        receipt_details.append(
            {
                "iss": issuer,
                "iat": iat,
                "sigtxid": sigtxid,
                "regtxid": regtxid,
            }
        )
    return receipt_details


class StaticTrustStore(TrustStore):
    """
    A static trust store based on an explicit key, trusted COSE keys from
    /.well-known/scitt-keys, or DER-encoded service certificates.
    """

    trust_store_keys: dict = {}

    def __init__(
        self,
        cose_keys: Optional[list] = None,
        certificates: Optional[list] = None,
        key: Optional[PublicKeyTypes] = None,
    ):
        self.trust_store_keys = {}
        self.key = key

        # Load keys from COSE_Key_Set (from /.well-known/scitt-keys)
        if cose_keys:
            for cose_key_dict in cose_keys:
                cose_key = CoseKey.from_dict(cose_key_dict)  # type: ignore[var-annotated]
                kid = cose_key.kid
                if isinstance(kid, str):
                    kid = kid.encode()
                # Convert COSE_Key to cryptography public key
                pub_key = self._cose_key_to_cryptography_key(cose_key)
                self.trust_store_keys[kid] = pub_key

        # Load keys from DER-encoded certificates (legacy format)
        if certificates:
            for cert_der in certificates:
                cert = load_der_x509_certificate(cert_der, default_backend())
                key = cert.public_key()
                # Compute kid as hex-encoded SHA256 of public key DER
                kid = (
                    sha256(
                        key.public_bytes(
                            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                        )
                    )
                    .digest()
                    .hex()
                    .encode()
                )
                self.trust_store_keys[kid] = key

    @property
    def services(self):
        return {}

    @staticmethod
    def _cose_key_to_cryptography_key(cose_key: CoseKey) -> PublicKeyTypes:
        """Convert a pycose CoseKey to a cryptography public key."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            SECP384R1,
            SECP521R1,
            EllipticCurvePublicNumbers,
        )
        from pycose.keys.curves import P256, P384, P521

        # Map COSE curve to cryptography curve
        curve_map = {
            P256: SECP256R1(),
            P384: SECP384R1(),
            P521: SECP521R1(),
        }

        curve = curve_map.get(cose_key.crv)  # type: ignore[attr-defined] # CodeQL [SM04458] The curve_map is using the approved cryptographic curves P256, P384, and P521. Anything other than it will be rejected and not used for verification, so it does not pose a security risk.
        if curve is None:
            raise ValueError(f"Unsupported curve: {cose_key.crv}")  # type: ignore[attr-defined]

        x_int = int.from_bytes(cose_key.x, "big")  # type: ignore[attr-defined]
        y_int = int.from_bytes(cose_key.y, "big")  # type: ignore[attr-defined]
        pub_numbers = EllipticCurvePublicNumbers(x_int, y_int, curve)
        return pub_numbers.public_key(default_backend())

    @staticmethod
    def load(path: Path) -> "StaticTrustStore":
        """
        Populate a static trust store from a directory containing:
        - CBOR files with COSE_Key_Set (from /.well-known/scitt-keys)
        - JSON files with service certificates (legacy format for backwards compatibility)
        """
        cose_keys = []
        certificates = []

        # Load CBOR files (COSE_Key_Set from /.well-known/scitt-keys)
        for cbor_path in path.glob("**/*.cbor"):
            with open(cbor_path, "rb") as f:
                data = cbor2.loads(f.read())
            # COSE_Key_Set is an array of COSE_Key maps
            if isinstance(data, list):
                cose_keys.extend(data)

        # Load JSON files (legacy format with service certificates)
        for json_path in path.glob("**/*.json"):
            with open(json_path, encoding="utf-8") as json_file:
                data = json.load(json_file)

            def _extract_certificates(param: dict):
                cert_b64 = param.get("serviceCertificate")
                if cert_b64:
                    certificates.append(base64.b64decode(cert_b64))

            # If the JSON file contains a list of parameters, extract from each
            params = data.get("parameters")
            if params and isinstance(params, list):
                for param in params:
                    _extract_certificates(param)
            # Otherwise, assume the JSON file contains a single set of parameters
            else:
                _extract_certificates(data)

        return StaticTrustStore(
            cose_keys=cose_keys if cose_keys else None,
            certificates=certificates if certificates else None,
        )

    def get_key(self, receipt: bytes) -> PublicKeyTypes:
        if self.key is not None:
            return self.key
        parsed = Sign1Message.decode(receipt)
        kid = parsed.phdr[KID]
        return self.trust_store_keys[kid]


class DynamicTrustStoreClient:
    """
    A client for retrieving public keys from a transparency service identified by an issuer.
    """

    clients: Dict[str, httpx.Client] = {}
    confidential_ledger_certs: Dict[str, str] = {}

    def __init__(self, forced_httpclient: Optional[httpx.Client] = None):
        self.retries = 5
        # forced client is used in testing
        self._forced_httpclient = forced_httpclient

    def _client(self, cadata: Optional[str] = None) -> httpx.Client:
        if self._forced_httpclient is not None:
            return self._forced_httpclient

        if cadata:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(cadata=cadata)
            transport = httpx.HTTPTransport(verify=ssl_context, retries=self.retries)
        else:
            transport = httpx.HTTPTransport(retries=self.retries)
        return httpx.Client(transport=transport)

    def _client_for_issuer(self, issuer: str) -> httpx.Client:
        """
        Lightweight caching of clients based on issuer.
        """
        if issuer not in self.clients:
            if self.is_confidential_ledger_issuer(issuer):
                pem = self.get_confidential_ledger_tls_pem(issuer)
                self.confidential_ledger_certs[issuer] = pem
                self.clients[issuer] = self._client(cadata=pem)
            else:
                self.clients[issuer] = self._client()
        return self.clients[issuer]

    def _assert_tls_in_jwks(self, tls_pem: str, jwks: dict):
        """Parse JSON web keys to find the KID of the TLS certificate public key."""
        if not tls_pem:
            raise ValueError("TLS PEM certificate is required")
        if not jwks:
            raise ValueError("JWKS is required")
        if not "keys" in jwks:
            raise ValueError("JWKS does not contain 'keys'")
        cert = x509.load_pem_x509_certificate(tls_pem.encode(), default_backend())
        cert_digest = (
            sha256(
                cert.public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
            )
            .digest()
            .hex()
        )
        jwks_keys_digests = []
        for jwks_key in jwks["keys"]:
            try:
                pem_b = jwk.JWK.from_json(json.dumps(jwks_key)).export_to_pem()
                pub_key = load_pem_public_key(pem_b, default_backend())
                pubhash = (
                    sha256(
                        pub_key.public_bytes(
                            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                        )
                    )
                    .digest()
                    .hex()
                )
                jwks_keys_digests.append(pubhash)
            except Exception as e:
                print(f"Warning: Could not parse JWKS key: {e}")

        if cert_digest not in jwks_keys_digests:
            raise ValueError(f"TLS public key digest {cert_digest} not found in JWKS")

    def get_jwks(self, issuer: str) -> dict:
        """
        Retrieve the JWKS from the issuer.
        """
        transparency_configuration = self.get_configuration(issuer)
        transparency_configuration.raise_for_status()
        config_response = cbor2.loads(transparency_configuration.content)
        jwks_uri = config_response["jwks_uri"]
        jwks_response = self._client_for_issuer(issuer).get(
            jwks_uri, headers={"Accept": "application/json"}
        )
        jwks_response.raise_for_status()
        jwks = jwks_response.json()

        # If issuer is a Confidential Ledger issuer, ensure the TLS certificate public key is in the JWKS.
        # This step adds an additional layer of trustworthiness of the public keys used for verification.
        if self.is_confidential_ledger_issuer(issuer):
            pem = self.confidential_ledger_certs.get(issuer)
            if pem is None:
                raise ValueError(f"No TLS certificate for issuer {issuer}.")
            self._assert_tls_in_jwks(pem, jwks)

        return jwks

    def get_configuration(self, issuer: str):
        """
        Retrieve the transparency configuration from the issuer.
        """
        if not issuer:
            raise ValueError("Issuer cannot be empty")

        return self._client_for_issuer(issuer).get(
            "https://" + issuer + "/.well-known/transparency-configuration",
            headers={"Accept": "application/cbor"},
        )

    def is_confidential_ledger_issuer(self, issuer: str) -> bool:
        return issuer.endswith(".confidential-ledger.azure.com")

    def get_confidential_ledger_tls_pem(self, issuer: str):
        """
        Retrieve the TLS certificate for a Confidential Ledger issuer.
        """
        if not issuer:
            raise ValueError("Issuer is required")
        service_name = issuer.split(".")[0]
        identity_client = ConfidentialLedgerCertificateClient()  # type: ignore
        network_identity = identity_client.get_ledger_identity(ledger_id=service_name)
        if not network_identity or "ledgerTlsCertificate" not in network_identity:
            raise ValueError(f"No TLS certificate found for issuer: {issuer}")
        return network_identity["ledgerTlsCertificate"]


class DynamicTrustStore(TrustStore):
    """
    A dynamic trust store, based on a single service identity used to retrieve
    all keys from the service's transparency configuration endpoint.
    """

    def __init__(self, client: Optional[DynamicTrustStoreClient] = None):
        if client is None:
            client = DynamicTrustStoreClient()
        self.client = client

    @property
    def services(self):
        raise NotImplementedError()

    def get_key(self, receipt: bytes) -> PublicKeyTypes:
        """
        Look up a service's public key based on the protected headers from a receipt.
        """
        parsed = Sign1Message.decode(receipt)
        cwt = parsed.phdr[CWTClaims]
        key_id = parsed.phdr[KID]
        issuer = cwt[CWT_ISS]
        jwk_set = self.client.get_jwks(issuer)
        jwks = jwk_set["keys"]
        keys = {key["kid"].encode(): key for key in jwks}
        if key_id not in keys:
            raise ValueError(f"Key ID {key_id} not found in JWKS for issuer {issuer}")
        key = keys[key_id]
        pem_key = jwk.JWK.from_json(json.dumps(key)).export_to_pem()
        key = load_pem_public_key(pem_key, default_backend())
        return key  # type: ignore
