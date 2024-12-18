# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Dict, Optional, Union

import cbor2
import ccf.cose
import pycose
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_der_x509_certificate
from pycose.headers import KID
from pycose.keys.cosekey import CoseKey
from pycose.messages import Sign1Message

from . import crypto, did
from .crypto import SCITTIssuer
from .receipt import Receipt


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
    def lookup(self, phdr) -> ServiceParameters:
        """
        Look up a service's parameters based on the protected headers from a
        receipt. Raises an exception if not matching service is found.
        """
        raise NotImplementedError()


def verify_cose_sign1(buf: bytes, cert_pem: str):
    msg = Sign1Message.decode(buf)
    msg.key = msg.key = CoseKey.from_pem_public_key(cert_pem)
    if not msg.verify_signature():
        raise ValueError("signature is invalid")


def verify_receipt(
    buf: bytes,
    service_trust_store: TrustStore,
    receipt: Union[Receipt, bytes, None] = None,
) -> None:
    msg = Sign1Message.decode(buf)

    if isinstance(receipt, Receipt):
        decoded_receipt = receipt
    else:
        if receipt is None:
            embedded_receipt = crypto.get_last_embedded_receipt_from_cose(buf)
            if not embedded_receipt:
                raise ValueError("No embedded receipt found in COSE message")
            parsed_receipt = cbor2.loads(embedded_receipt)
        else:
            parsed_receipt = cbor2.loads(receipt)

        decoded_receipt = Receipt.from_cose_obj(parsed_receipt)

    service_params = service_trust_store.lookup(decoded_receipt.phdr)
    decoded_receipt.verify(msg, service_params)


def get_kid(cose_sign1: bytes) -> bytes:
    parsed_receipt = Sign1Message.decode(cose_sign1)
    return parsed_receipt.phdr[KID]


def verify_transparent_statement(
    transparent_statement: bytes,
    service_trust_store: TrustStore,
    input_signed_statement: bytes,
):
    trust_store_keys = {}
    for _, service_params in service_trust_store.services.items():
        cert = load_der_x509_certificate(service_params.certificate, default_backend())
        key = cert.public_key()
        kid = (
            sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            .digest()
            .hex()
            .encode()
        )
        trust_store_keys[kid] = key

    st = Sign1Message.decode(transparent_statement)
    for receipt in st.uhdr[crypto.SCITTReceipts]:
        kid = get_kid(receipt)
        service_key = trust_store_keys[kid]
        ccf.cose.verify_receipt(
            receipt, service_key, sha256(input_signed_statement).digest()
        )


class StaticTrustStore(TrustStore):
    """
    A static trust store, based on a list of trusted service certificates.
    """

    services: Dict[str, ServiceParameters] = {}

    def __init__(self, services: Dict[str, ServiceParameters]):
        self.services = services

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

    def lookup(self, phdr) -> ServiceParameters:
        if "service_id" not in phdr:
            raise ValueError("Receipt does not have a service identity.")

        service_id = phdr["service_id"]
        if service_id in self.services:
            return self.services[service_id]
        else:
            raise ValueError(f"Unknown service identity {service_id!r}")
