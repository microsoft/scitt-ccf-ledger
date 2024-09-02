# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import datetime
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import cbor2
import ccf.receipt
from cbor2 import CBORError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate
from pycose.headers import KID, X5chain, X5t
from pycose.messages import Sign1Message
from pycose.messages.cosebase import CoseBase

from . import crypto

if TYPE_CHECKING:
    from .verify import ServiceParameters

HEADER_PARAM_TREE_ALGORITHM = "tree_alg"
TREE_ALGORITHM_CCF = "CCF"

# Include SCITT-specific COSE header attributes to be recognized by pycose
# Registered COSE headers are in https://www.iana.org/assignments/cose/cose.xhtml
# Draft SCITT-specific headers are in https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/


def display_cbor_val(item: Any) -> str:
    """Convert a CBOR item to a string for pretty-printing."""
    out = str(item)
    if hasattr(item, "__name__"):
        out = item.__name__
    elif isinstance(item, datetime.datetime):
        out = item.isoformat()
    elif type(item) is bytes:
        out = item.hex()
    return out


def cbor_as_dict(cbor_obj: Any, cbor_obj_key: Any = None) -> Any:
    """
    Return a printable representation of a CBOR object.
    """

    # pycose will use class instances for known and registered headers instead of ints
    if hasattr(cbor_obj_key, "identifier"):
        if cbor_obj_key.identifier == crypto.SCITTReceipts.identifier:
            parsed_receipts = []
            for item in cbor_obj:
                if type(item) is bytes:
                    receipt_as_dict = Receipt.decode(item).as_dict()
                else:
                    receipt_as_dict = Receipt.from_cose_obj(item).as_dict()
            parsed_receipts.append(receipt_as_dict)
            return parsed_receipts
        if cbor_obj_key.identifier == X5chain.identifier:
            return [base64.b64encode(cert).decode("ascii") for cert in cbor_obj]
        if cbor_obj_key.identifier == KID.identifier:
            return cbor_obj.decode()
        if cbor_obj_key.identifier == X5t.identifier:
            return {"alg": cbor_obj[0], "hash": cbor_obj[1].hex()}

    if isinstance(cbor_obj, list):
        if not cbor_obj_key:
            cbor_obj_key = "idx"
        out_key = display_cbor_val(cbor_obj_key)
        return {
            display_cbor_val(f"{out_key}_{idx}"): cbor_as_dict(v, f"{out_key}_{idx}")
            for idx, v in enumerate(cbor_obj)
        }

    if isinstance(cbor_obj, dict):
        return {display_cbor_val(k): cbor_as_dict(v, k) for k, v in cbor_obj.items()}

    # attempt to decode nested cbor
    if type(cbor_obj) is bytes:
        try:
            decoded = cbor2.loads(cbor_obj)
            return cbor_as_dict(decoded, cbor_obj_key)
        except (CBORError, UnicodeDecodeError):
            pass

    # otherwise return as is
    return display_cbor_val(cbor_obj)


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
            "protected": cbor_as_dict(self.phdr),
            "contents": self.contents.as_dict(),
        }
