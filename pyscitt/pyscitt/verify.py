# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

import cbor2
import pycose
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_pem_x509_certificate
from pycose.keys.ec2 import EC2Key
from pycose.keys.rsa import RSAKey
from pycose.messages import Sign1Message

from . import crypto, did
from .crypto import COSE_HEADER_PARAM_ISSUER, COSE_HEADER_PARAM_SCITT_RECEIPTS
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
    @abstractmethod
    def lookup(self, phdr) -> ServiceParameters:
        """
        Look up a service's parameters based on the protected headers from a
        receipt. Raises an exception if not matching service is found.
        """
        raise NotImplementedError()


def verify_cose_sign1(buf: bytes, cert_pem: str):
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    key = cert.public_key()

    cose_key: Union[EC2Key, RSAKey]
    if isinstance(key, RSAPublicKey):
        cose_key = crypto.from_cryptography_rsakey_obj(key)
    elif isinstance(key, EllipticCurvePublicKey):
        cose_key = crypto.from_cryptography_eckey_obj(key)
    else:
        raise NotImplementedError("unsupported key type")

    msg = Sign1Message.decode(buf)
    msg.key = cose_key
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
            parsed_receipts = msg.uhdr[COSE_HEADER_PARAM_SCITT_RECEIPTS]
            # For now, assume there is only one receipt
            assert len(parsed_receipts) == 1
            parsed_receipt = parsed_receipts[0]
        else:
            parsed_receipt = cbor2.loads(receipt)

        decoded_receipt = Receipt.from_cose_obj(parsed_receipt)

    # check if the header struct contains mrenclave header
    assert "enclave_measurement" in decoded_receipt.phdr
    service_params = service_trust_store.lookup(decoded_receipt.phdr)
    decoded_receipt.verify(msg, service_params)


class StaticTrustStore(TrustStore):
    """
    A static trust store, based on a list of trusted service certificates.
    """

    services: Dict[str, ServiceParameters]

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

            service_id = data.get("serviceId")
            if not isinstance(service_id, str) or not service_id:
                raise ValueError("serviceId must be a non-empty string")

            if service_id in store:
                raise ValueError(
                    f"Duplicate service ID while reading trust store: {service_id}"
                )

            store[service_id] = ServiceParameters.from_dict(data)

        return StaticTrustStore(store)

    def lookup(self, phdr) -> ServiceParameters:
        if "service_id" not in phdr:
            raise ValueError("Receipt does not have a service identity.")

        service_id = phdr["service_id"]
        if service_id in self.services:
            return self.services[service_id]
        else:
            raise ValueError(f"Unknown service identity {service_id!r}")


class DIDDocumentTrustStore(TrustStore):
    """
    A trust store backed by a single DID-document.

    The trust store will use the KID found in the protected headers to select
    the appropriate assertion method from the document.
    """

    document: dict

    def __init__(self, document: dict):
        self.document = document

    def lookup(self, phdr) -> ServiceParameters:
        issuer = phdr.get(COSE_HEADER_PARAM_ISSUER)
        if issuer != self.document.get("id"):
            raise ValueError(
                f"Incorrect issuer {issuer!r}, expected {self.document['id']}"
            )

        if pycose.headers.KID in phdr:
            kid = phdr[pycose.headers.KID].decode("ascii")
        else:
            kid = None

        method = did.find_assertion_method(self.document, kid)
        jwk = method["publicKeyJwk"]
        # TODO parse jwk without using x5c as well
        if len(jwk.get("x5c", [])) < 1:
            raise ValueError("Missing x5c parameter in service JWK")
        certificate = base64.b64decode(jwk["x5c"][0])

        return ServiceParameters("CCF", "ES256", certificate)


class DIDResolverTrustStore(TrustStore):
    """
    A trust store which uses the issuer found in receipts to dynamically
    resolve the service parameters.

    The trust store does not restrict which issuers are allowed, only that the
    receipt signature matches the identifier.
    """

    def __init__(self, resolver: Optional[did.Resolver] = None):
        if resolver is not None:
            self.resolver = resolver
        else:
            self.resolver = did.Resolver()

    def lookup(self, phdr) -> ServiceParameters:
        if COSE_HEADER_PARAM_ISSUER not in phdr:
            raise ValueError("Receipt does not have an issuer")

        issuer = phdr[COSE_HEADER_PARAM_ISSUER]
        document = self.resolver.resolve(issuer)

        return DIDDocumentTrustStore(document).lookup(phdr)
