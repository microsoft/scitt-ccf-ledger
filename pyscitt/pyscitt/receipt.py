# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import cbor2
import ccf.receipt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate
from pycose.messages import Sign1Message
from pycose.messages.cosebase import CoseBase

from . import crypto

if TYPE_CHECKING:
    from .verify import ServiceParameters

HEADER_PARAM_TREE_ALGORITHM = "tree_alg"
TREE_ALGORITHM_CCF = "CCF"


def hdr_as_dict(phdr: dict) -> dict:
    """
    Return a representation of a list of COSE header parameters that
    is amenable to pretty-printing.
    """

    def display(item):
        if hasattr(item, "__name__"):
            return item.__name__
        if type(item) is bytes:
            return item.hex()
        return item

    # Decode KID into a 'readable' text string if present.
    hdr_dict = {display(k): display(v) for k, v in phdr.items()}
    if hdr_dict.get("KID"):
        hdr_dict["KID"] = bytes.fromhex(hdr_dict["KID"]).decode()

    return hdr_dict


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
    def verify(self, tbs: bytes, service: "ServiceParameters"):
        pass

    @abstractmethod
    def as_dict(self) -> dict:
        pass

    @classmethod
    def from_cose_obj(self, headers: dict, cose_obj: Any) -> "ReceiptContents":
        if headers.get(HEADER_PARAM_TREE_ALGORITHM) == TREE_ALGORITHM_CCF:
            return CCFReceiptContents(
                cose_obj[0],
                cose_obj[1],
                cose_obj[2],
                LeafInfo.from_cose_obj(cose_obj[3]),
            )
        else:
            raise ValueError("unsupported tree algorithm, cannot decode receipt")


@dataclass
class CCFReceiptContents(ReceiptContents):
    signature: bytes
    node_certificate: bytes
    inclusion_proof: list
    leaf_info: LeafInfo

    def root(self, claims_digest: bytes) -> bytes:
        leaf = self.leaf_info.digest(claims_digest).hex()

        proof = []
        for [left, hash_] in self.inclusion_proof:
            if left:
                proof.append({"left": hash_.hex()})
            else:
                proof.append({"right": hash_.hex()})

        return bytes.fromhex(ccf.receipt.root(leaf, proof))

    def verify(self, tbs: bytes, service: "ServiceParameters"):
        if service.tree_algorithm != "CCF":
            raise ValueError("treeAlgorithm must be CCF")
        if service.signature_algorithm != "ES256":
            raise ValueError("signatureAlgorithm must be ES256")

        claims_digest = hashlib.sha256(tbs).digest()

        service_cert = load_der_x509_certificate(service.certificate)
        node_cert = load_der_x509_certificate(self.node_certificate)
        if not isinstance(node_cert.public_key(), ec.EllipticCurvePublicKey):
            raise ValueError("Invalid node public key algorithm")

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
        return cls.from_cose_obj(cbor2.loads(data))  # type: ignore[arg-type]

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

    def verify(self, claim: Sign1Message, service_params: "ServiceParameters"):
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
