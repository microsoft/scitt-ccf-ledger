# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import cbor2
import ccf.receipt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import Certificate, load_der_x509_certificate
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
    def verify(self, tbs: bytes, service: "crypto.ServiceParameters"):
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

    def verify(self, tbs: bytes, service: "crypto.ServiceParameters"):
        if service.tree_algorithm != "CCF":
            raise ValueError("treeAlgorithm must be CCF")
        if service.signature_algorithm != "ES256":
            raise ValueError("signatureAlgorithm must be ES256")

        claims_digest = hashlib.sha256(tbs).digest()

        root = self.root(claims_digest).hex()

        node_cert = load_der_x509_certificate(self.node_certificate)
        ccf.receipt.verify(root, signature, node_cert)
        self._check_node_cert(node_cert, service)

    @staticmethod
    def _check_node_cert(cert: Certificate, service: "crypto.ServiceParameters"):
        digest_alg = cert.signature_hash_algorithm
        digester = hashes.Hash(digest_alg)
        digester.update(cert.tbs_certificate_bytes)
        digest = digester.finalize()

        public_key = load_pem_public_key(service.public_key.encode("ascii"))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Invalid node public key algorithm")

        public_key.verify(cert.signature, digest, ec.ECDSA(utils.Prehashed(digest_alg)))

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

    def verify(self, claim: Sign1Message, service: "crypto.ServiceParameters"):
        tbs = self.countersign_structure(claim)
        self.contents.verify(tbs, service)

    def as_dict(self) -> dict:
        """
        Return a representation of the protected headers that is amenable
        to pretty-printing.
        """
        return {
            "protected": hdr_as_dict(self.phdr),
            "contents": self.contents.as_dict(),
        }
