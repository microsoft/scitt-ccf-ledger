# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Union

import cbor2
import pycose
from pycose.messages import Sign1Message

from . import did
from .crypto import (
    COSE_HEADER_PARAM_ISSUER,
    COSE_HEADER_PARAM_SCITT_RECEIPTS,
    Pem,
    cert_der_to_pem,
    convert_jwk_to_pem,
    get_cert_public_key,
)
from .receipt import Receipt


@dataclass
class ServiceParameters:
    tree_algorithm: str
    signature_algorithm: str
    public_key: Pem

    @staticmethod
    def from_json(data) -> "ServiceParameters":
        print(data["serviceCertificate"])
        public_key = get_cert_public_key(
            cert_der_to_pem(base64.b64decode(data["serviceCertificate"]))
        )
        return ServiceParameters(
            tree_algorithm=data["treeAlgorithm"],
            signature_algorithm=data["signatureAlgorithm"],
            public_key=public_key,
        )


class TrustStore(ABC):
    @abstractmethod
    def lookup(self, phdr) -> ServiceParameters:
        ...


def verify_cose_sign1(buf: bytes, cert_pem: str):
    key_type = get_cert_key_type(cert_pem)
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    key = cert.public_key()
    if key_type == "rsa":
        cose_key = from_cryptography_rsakey_obj(key)
    else:
        cose_key = from_cryptography_eckey_obj(key)

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

    service_params = service_trust_store.lookup(decoded_receipt.phdr)
    decoded_receipt.verify(msg, service_params)


class StaticTrustStore(TrustStore):
    services: Dict[str, ServiceParameters]

    def __init__(self, services: Dict[str, ServiceParameters]):
        self.services = services

    @staticmethod
    def load(path: Path) -> "StaticTrustStore":
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

            store[service_id] = ServiceParameters.from_json(data)

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
    document: dict

    def __init__(self, document: dict):
        self.document = document

    def lookup(self, phdr) -> ServiceParameters:
        if pycose.headers.KID in phdr:
            kid = phdr[pycose.headers.KID].decode("ascii")
        else:
            kid = None

        method = did.find_assertion_method(self.document, kid)
        key = convert_jwk_to_pem(method["publicKeyJwk"])
        return ServiceParameters("CCF", "ES256", key)


class DIDResolverTrustStore:
    def __init__(self):
        self.resolver = did.Resolver()

    def lookup(self, phdr) -> ServiceParameters:
        if COSE_HEADER_PARAM_ISSUER not in phdr:
            raise ValueError("Receipt does not have an issuer")

        issuer = phdr[COSE_HEADER_PARAM_ISSUER]
        document = self.resolver.resolve(issuer)

        return DIDDocumentTrustStore(document).resolve(phdr)
