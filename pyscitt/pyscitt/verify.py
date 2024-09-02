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
        issuer = phdr.get(SCITTIssuer)
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
        if SCITTIssuer not in phdr:
            raise ValueError("Receipt does not have an issuer")

        issuer = phdr[SCITTIssuer]
        document = self.resolver.resolve(issuer)

        return DIDDocumentTrustStore(document).lookup(phdr)
