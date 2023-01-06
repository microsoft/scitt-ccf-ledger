# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Tuple

import cbor2
import ccf.receipt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_der_x509_certificate
from pycose.messages import Sign1Message
from pycose.messages.cosebase import CoseBase

from . import crypto

HEADER_PARAM_TREE_ALGORITHM = "tree_alg"
TREE_ALGORITHM_CCF = "CCF"


def hdr_as_dict(phdr: list) -> dict:
    """
    Return a representation of a list of COSE header parameters that
    is amenable to pretty-printing.
    """
    display = lambda v: v.__name__ if hasattr(v, "__name__") else v
    return {display(k): display(v) for k, v in phdr.items()}


@dataclass
class LeafInfo:
    internal_hash: bytes
    internal_data: bytes

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> "LeafInfo":
        return cls(*cose_obj)

    def digest(self, claims_digest: bytes) -> bytes:
        internal_data_digest = hashlib.sha256(self.internal_data).digest()
        return hashlib.sha256(
            self.internal_hash + internal_data_digest + claims_digest
        ).digest()


class ReceiptContents(ABC):
    @abstractmethod
    def verify(self, tbs: bytes, service_params: dict):
        pass

    @abstractmethod
    def as_dict(self) -> dict:
        pass

    @classmethod
    def from_cose_obj(self, headers: dict, cose_obj: Any) -> "ReceiptContents":
        if headers.get(HEADER_PARAM_TREE_ALGORITHM) == TREE_ALGORITHM_CCF:
            return CCFReceiptContents.from_cose_obj(cose_obj)
        else:
            raise ValueError("unsupported tree algorithm, cannot decode receipt")


@dataclass
class CCFReceiptContents(ReceiptContents):
    signature: bytes
    node_certificate: bytes
    inclusion_proof: list
    leaf_info: LeafInfo

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> "ReceiptContents":
        return cls(
            cose_obj[0], cose_obj[1], cose_obj[2], LeafInfo.from_cose_obj(cose_obj[3])
        )

    def root(self, claims_digest: bytes) -> bytes:
        leaf = self.leaf_info.digest(claims_digest).hex()

        proof = []
        for [left, hash_] in self.inclusion_proof:
            if left:
                proof.append({"left": hash_.hex()})
            else:
                proof.append({"right": hash_.hex()})

        return bytes.fromhex(ccf.receipt.root(leaf, proof))

    def verify(self, tbs: bytes, service_params: dict):
        if service_params.get("treeAlgorithm") != "CCF":
            raise ValueError("treeAlgorithm must be CCF")
        if service_params.get("signatureAlgorithm") != "ES256":
            raise ValueError("signatureAlgorithm must be ES256")

        service_cert_der = base64.b64decode(service_params["serviceCertificate"])
        service_cert = load_der_x509_certificate(service_cert_der, default_backend())

        node_cert = load_der_x509_certificate(self.node_certificate, default_backend())
        if not isinstance(node_cert.public_key(), ec.EllipticCurvePublicKey):
            raise ValueError("Invalid node public key algorithm")

        claims_digest = hashlib.sha256(tbs).digest()

        root = self.root(claims_digest).hex()

        # The CCF module expects a base64 signature, in ASN1/DER format.
        signature = crypto.convert_p1363_signature_to_dss(self.signature)
        b64signature = base64.b64encode(signature).decode()

        ccf.receipt.verify(root, b64signature, node_cert)
        ccf.receipt.check_endorsement(node_cert, service_cert)

    def as_dict(self) -> dict:
        """
        Return a representation of the receipt that is amenable to
        pretty-printing.
        """
        proof = []
        for [left, h] in self.inclusion_proof:
            if left:
                proof.append({"left": h.hex()})
            else:
                proof.append({"right": h.hex()})

        return {
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "node_certificate": base64.b64encode(self.node_certificate).decode("ascii"),
            "inclusion_proof": proof,
            "leaf_info": {
                "internal_hash": self.leaf_info.internal_hash.hex(),
                "internal_data": self.leaf_info.internal_data.decode("ascii"),
            },
        }


@dataclass
class Receipt:
    phdr_encoded: bytes
    phdr: dict
    contents: ReceiptContents

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> "Receipt":
        phdr_encoded = cose_obj.pop(0)
        phdr = CoseBase._parse_header(cbor2.loads(phdr_encoded), True)
        contents = ReceiptContents.from_cose_obj(phdr, cose_obj.pop(0))

        return Receipt(phdr_encoded, phdr, contents)

    @classmethod
    def decode(cls, data: bytes) -> "Receipt":
        return cls.from_cose_obj(cbor2.loads(data))

    def countersign_structure(self, claim: Sign1Message) -> bytes:
        context = "CounterSignatureV2"
        countersign_structure = [
            context,
            claim.phdr_encoded,
            self.phdr_encoded,
            b"",  # no external AAD
            claim.payload,
            [claim.signature],
        ]
        return cbor2.dumps(countersign_structure)

    def verify(self, claim: Sign1Message, service_params: dict):
        tbs = self.countersign_structure(claim)
        self.contents.verify(tbs, service_params)

    def as_dict(self) -> dict:
        """
        Return a representation of the protected headers that is amenable
        to pretty-printing.
        """
        return {
            "protected": hdr_as_dict(self.phdr),
            "contents": self.contents.as_dict(),
        }
