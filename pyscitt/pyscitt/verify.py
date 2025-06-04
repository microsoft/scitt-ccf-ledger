# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Dict, Optional

import cbor2
import ccf.cose
import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
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
from .crypto import CWT_ISS, CWTClaims


@dataclass
class ServiceParameters:
    tree_algorithm: str
    signature_algorithm: str
    certificate: bytes
    service_id: Optional[str] = None

    @staticmethod
    def from_dict(data) -> "ServiceParameters":
        """
        Decode service parameters as returned by the /parameters endpoint.
        """
        return ServiceParameters(
            tree_algorithm=data["treeAlgorithm"],
            signature_algorithm=data["signatureAlgorithm"],
            certificate=base64.b64decode(data["serviceCertificate"]),
            service_id=data["serviceId"],
        )

    def as_dict(self) -> Dict[str, str]:
        result = {
            "treeAlgorithm": self.tree_algorithm,
            "signatureAlgorithm": self.signature_algorithm,
            "serviceCertificate": base64.b64encode(self.certificate).decode("ascii"),
        }
        if self.service_id is not None:
            result["serviceId"] = self.service_id
        return result


class TrustStore(ABC):
    @property
    @abstractmethod
    def services(self):
        pass

    @abstractmethod
    def get_key(self, receipt: bytes) -> CertificatePublicKeyTypes:
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


def verify_transparent_statement(
    transparent_statement: bytes,
    service_trust_store: TrustStore,
    input_signed_statement: bytes,
):
    st = Sign1Message.decode(transparent_statement)
    for receipt in st.uhdr[crypto.SCITTReceipts]:
        service_key = service_trust_store.get_key(receipt)
        ccf.cose.verify_receipt(
            receipt, service_key, sha256(input_signed_statement).digest()
        )


class StaticTrustStore(TrustStore):
    """
    A static trust store, based on a list of trusted service certificates.
    """

    services: Dict[str, ServiceParameters] = {}
    trust_store_keys: dict = {}

    def __init__(self, services: Dict[str, ServiceParameters]):
        self.services = services
        for _, service_params in self.services.items():
            cert = load_der_x509_certificate(
                service_params.certificate, default_backend()
            )
            key = cert.public_key()
            kid = (
                sha256(
                    key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                )
                .digest()
                .hex()
                .encode()
            )
            self.trust_store_keys[kid] = key

    @staticmethod
    def load(path: Path) -> "StaticTrustStore":
        """
        Populate a static trust store from a directory. Each JSON file in the
        directory corresponds to a trusted service identity.
        """
        store = {}
        for path in path.glob("**/*.json"):
            with open(path) as f:
                data = json.load(f)

            def _parse_service_param(param: dict):
                service_id = param.get("serviceId")
                if not isinstance(service_id, str) or not service_id:
                    raise ValueError("serviceId must be a non-empty string")

                if service_id in store:
                    raise ValueError(
                        f"Duplicate service ID while reading trust store: {service_id}"
                    )

                store[service_id] = ServiceParameters.from_dict(param)

            # If the JSON file contains a list of parameters, parse each one (as returned by /parameters/historic)
            params = data.get("parameters")
            if params and isinstance(params, list):
                for param in params:
                    _parse_service_param(param)
            # Otherwise, assume the JSON file contains a single set of parameters (as returned by /parameters)
            else:
                _parse_service_param(data)

        return StaticTrustStore(store)

    def get_key(self, receipt: bytes) -> CertificatePublicKeyTypes:
        parsed = Sign1Message.decode(receipt)
        kid = parsed.phdr[KID]
        return self.trust_store_keys[kid]


class DynamicTrustStore(TrustStore):
    """
    A dynamic trust store, based on a single service identity used to retrieve
    all keys from the service's transparency configuration endpoint.
    """

    def __init__(self, client=None):
        if client is None:
            client = DynamicTrustStoreClient()
        self.client = client

    @property
    def services(self):
        raise NotImplementedError()

    def get_key(self, receipt: bytes) -> CertificatePublicKeyTypes:
        parsed = Sign1Message.decode(receipt)
        cwt = parsed.phdr[CWTClaims]
        issuer = cwt[CWT_ISS]
        jwk_set = self.client.get_jwks(issuer)
        jwk_set.raise_for_status()
        jwks = jwk_set.json()["keys"]
        keys = {key["kid"].encode(): key for key in jwks}
        key = keys[parsed.phdr[KID]]
        pem_key = jwk.JWK.from_json(json.dumps(key)).export_to_pem()
        key = load_pem_public_key(pem_key, default_backend())
        return key  # type: ignore


class DynamicTrustStoreClient:
    """
    A client for retrieving public keys from a transparency service identified by an issuer.
    """

    clients: Dict[str, httpx.Client] = {}

    def __init__(self):
        self.retries = 5

    def _client(self, cadata: Optional[str] = None) -> httpx.Client:
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
                self.clients[issuer] = self._client(cadata=pem)
            else:
                self.clients[issuer] = self._client()
        return self.clients[issuer]

    def get_jwks(self, issuer: str) -> httpx.Response:
        """
        Retrieve the JWKS from the issuer.
        """
        transparency_configuration = self.get_configuration(issuer)
        transparency_configuration.raise_for_status()
        config_response = cbor2.loads(transparency_configuration.content)
        jwks_uri = config_response["jwks_uri"]
        return self._client_for_issuer(issuer).get(
            jwks_uri, headers={"Accept": "application/json"}
        )

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
        if not self.is_confidential_ledger_issuer(issuer):
            raise ValueError("Issuer is not a Confidential Ledger issuer")
        service_name = issuer.split(".")[0]
        response = self._client().get(
            f"https://identity.confidential-ledger.core.azure.com/ledgerIdentity/{service_name}",
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        ledger_identity = response.json()
        if "ledgerTlsCertificate" not in ledger_identity:
            raise ValueError("TLS certificate not found in ledger identity")
        if not isinstance(ledger_identity["ledgerTlsCertificate"], str):
            raise ValueError("TLS certificate is not a string")
        if "-----BEGIN CERTIFICATE-----" not in ledger_identity["ledgerTlsCertificate"]:
            raise ValueError("TLS certificate is not in PEM format")
        return ledger_identity["ledgerTlsCertificate"]
