# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import datetime
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Union

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
COMMON_CWT_KEYS_MAP = {
    1: "iss",
    2: "sub",
    3: "aud",
    4: "exp",
    5: "nbf",
    6: "iat",
    7: "cti",
}


def display_cwt_key(item: Any) -> Union[int, str]:
    """Convert a CWT key to a string for pretty-printing."""
    out = str(item)
    return COMMON_CWT_KEYS_MAP.get(item, out)


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


def cbor_to_printable(cbor_obj: Any, cbor_obj_key: Any = None) -> Any:
    """
    Return a printable representation of a CBOR object.
    """

    # pycose will use class instances for known and registered headers instead of ints
    if hasattr(cbor_obj_key, "identifier"):
        if cbor_obj_key.identifier == crypto.SCITTReceipts.identifier:
            parsed_receipts = []
            for item in cbor_obj:
                if type(item) is bytes:
                    try:
                        parsed = Sign1Message.decode(item)
                        receipt_as_dict = {
                            "protected": cbor_to_printable(parsed.phdr),
                            "unprotected": cbor_to_printable(parsed.uhdr),
                            "payload": (
                                base64.b64encode(parsed.payload).decode("ascii") if parsed.payload else None
                            ),
                        }
                    except Exception:
                        receipt_as_dict = {
                            "error": "Failed to parse receipt",
                            "cbor": item.hex(),
                        }
                else:
                    try:
                        receipt_as_dict = Receipt.from_cose_obj(item).as_dict()
                    except Exception:
                        receipt_as_dict = {
                            "error": "Failed to parse receipt",
                            "cbor": item,
                        }
                parsed_receipts.append(receipt_as_dict)
            return parsed_receipts
        if cbor_obj_key.identifier == crypto.CWTClaims.identifier:
            return {
                display_cwt_key(k): cbor_to_printable(v, k) for k, v in cbor_obj.items()
            }
        if cbor_obj_key.identifier == X5chain.identifier:
            return [base64.b64encode(cert).decode("ascii") for cert in cbor_obj]
        if cbor_obj_key.identifier == KID.identifier:
            return cbor_obj.hex()
        if cbor_obj_key.identifier == X5t.identifier:
            return {"alg": cbor_obj[0], "hash": cbor_obj[1].hex()}

    if isinstance(cbor_obj, list):
        if not cbor_obj_key:
            cbor_obj_key = "idx"
        out_key = display_cbor_val(cbor_obj_key)
        return {
            display_cbor_val(f"{out_key}_{idx}"): cbor_to_printable(
                v, f"{out_key}_{idx}"
            )
            for idx, v in enumerate(cbor_obj)
        }

    if isinstance(cbor_obj, dict):
        return {
            display_cbor_val(k): cbor_to_printable(v, k) for k, v in cbor_obj.items()
        }

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
            "protected": cbor_to_printable(self.phdr),
            "contents": self.contents.as_dict(),
        }
