# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import datetime
import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional, Union
from urllib.parse import unquote

import cbor2
import ccf.receipt
from cbor2 import CBORError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate
from pycose.headers import KID, X5chain, X5t
from pycose.messages import Sign1Message
from pycose.messages.cosebase import CoseBase

from . import crypto

HEADER_PARAM_TREE_ALGORITHM = "tree_alg"
TREE_ALGORITHM_CCF = "CCF"
COSE_INCLUSION_PROOFS_LABEL = 396
COSE_INCLUSION_PROOF_VDP_LABEL = -1
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


def decode_inclusion_proofs(uhdr: dict) -> dict:
    """
    Decode the CBOR-encoded verifiable data proofs found in the unprotected
    header of a receipt, so that their contents (including the leaf's
    internal-evidence, which carries the registration transaction id) can be
    displayed rather than shown as an opaque byte string.

    Returns the header, modified in place where decoding was possible.
    """
    proofs = uhdr.get(COSE_INCLUSION_PROOFS_LABEL)
    if not isinstance(proofs, dict):
        return uhdr

    vdps = proofs.get(COSE_INCLUSION_PROOF_VDP_LABEL)
    if not isinstance(vdps, list):
        return uhdr

    decoded = []
    for vdp in vdps:
        try:
            decoded.append(cbor2.loads(vdp) if isinstance(vdp, bytes) else vdp)
        except CBORError:
            decoded.append(vdp)
    proofs[COSE_INCLUSION_PROOF_VDP_LABEL] = decoded
    return uhdr


def parse_internal_evidence(
    internal_evidence: Union[str, bytes, None],
) -> Optional[str]:
    """
    Extract the registration transaction id from a leaf's internal-evidence,
    which has the form "ce:<txid>:<digest>".
    """
    if isinstance(internal_evidence, bytes):
        try:
            internal_evidence = internal_evidence.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(internal_evidence, str):
        return None

    parts = internal_evidence.split(":")
    return parts[1] if len(parts) >= 2 else None


def extract_registration_txid(uhdr: dict) -> Optional[str]:
    """
    Extract the registration transaction id from the internal-evidence of the
    inclusion proof leaf, which has the form "ce:<txid>:<digest>".

    Accepts a header whose proofs are still CBOR-encoded, or one already
    decoded by decode_inclusion_proofs().
    """
    proofs = uhdr.get(COSE_INCLUSION_PROOFS_LABEL)
    if not isinstance(proofs, dict):
        return None

    vdps = proofs.get(COSE_INCLUSION_PROOF_VDP_LABEL) or []
    if not vdps:
        return None

    proof = vdps[0]
    if isinstance(proof, bytes):
        try:
            proof = cbor2.loads(proof)
        except CBORError:
            return None
    if not isinstance(proof, dict):
        return None

    leaf = proof.get(1)
    if not leaf or len(leaf) < 2:
        return None

    return parse_internal_evidence(leaf[1])


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}(:[0-9]{1,5})?$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:[0-9]{1,5})?$"
)
TXID_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")


def is_hostname(value: Optional[str]) -> bool:
    """
    Whether a string is a bare hostname, and so can safely be used as the
    authority of a URL.

    Issuers come from unverified input, so anything carrying a scheme, port,
    userinfo, path, query or fragment must be rejected: such a string would
    otherwise address a host other than the one it appears to name.
    """
    if not value:
        return False
    return HOSTNAME_PATTERN.match(value) is not None


def issuer_host(issuer: Optional[str]) -> Optional[str]:
    """
    The hostname of the service identified by a receipt issuer, or None when
    the issuer does not address a service, as is the case for did:x509, or
    does not name a host on its own.

    Issuers are usually already a hostname, but legacy CCF receipts identify
    the service with a did:web, whose method-specific identifier is the host
    with its path segments separated by colons.
    """
    if not issuer:
        return None
    if issuer.startswith("did:web:"):
        # Only the first segment of a did:web is the host, the rest is a path
        # which the SCRAPI endpoints below do not use.
        issuer = unquote(issuer[len("did:web:") :].split(":")[0])
    elif issuer.startswith("did:"):
        return None
    return issuer if is_hostname(issuer) else None


def entry_urls(issuer: Optional[str], regtxid: Optional[str]) -> dict:
    """
    Build the URLs at which the receipt and the transparent statement for a
    registered entry can be retrieved, following SCRAPI's /entries/{txid} and
    /entries/{txid}/statement endpoints.

    The issuer of a receipt identifies the service that registered the
    statement, so it can be used to address that service.
    """
    host = issuer_host(issuer)
    if not host or not regtxid or not TXID_PATTERN.match(regtxid):
        return {"receipt": None, "transparent_statement": None}

    entry = f"https://{host}/entries/{regtxid}"
    return {"receipt": entry, "transparent_statement": f"{entry}/statement"}


def extract_receipt_details(parsed: Sign1Message) -> dict:
    """
    Extract the identifying details of a receipt: its issuer and issuance time
    from the CWT claims, the transaction id in which it was signed from the
    ccf.v1 protected header, and the transaction id in which the statement was
    registered from the inclusion proof.
    """
    issuer = None
    iat = None
    cwt = parsed.phdr.get(crypto.CWTClaims)
    if isinstance(cwt, dict):
        issuer = cwt.get(crypto.CWT_ISS)
        iat = cwt.get(crypto.CWT_IAT)

    sigtxid = None
    ccf_v1 = parsed.phdr.get("ccf.v1")
    if isinstance(ccf_v1, dict):
        sigtxid = ccf_v1.get("txid")

    return {
        "iss": issuer,
        "iat": iat,
        "sigtxid": sigtxid,
        "regtxid": extract_registration_txid(parsed.uhdr),
    }


def is_receipt(parsed: Sign1Message) -> bool:
    """
    Whether a decoded COSE message is a receipt, that is whether it carries an
    inclusion proof. A signed statement which has not been registered is not.
    """
    return isinstance(parsed.uhdr.get(COSE_INCLUSION_PROOFS_LABEL), dict)


def summarise_receipt_details(detail: dict) -> dict:
    """
    Turn the raw details of a receipt into a structured, printable summary,
    including the URLs at which the receipt and the transparent statement can
    be retrieved.
    """
    issuer = detail.get("iss")
    iat = detail.get("iat")
    regtxid = detail.get("regtxid")
    return {
        "issuer": issuer,
        "registration_txid": regtxid,
        "signature_txid": detail.get("sigtxid"),
        "issued_at": iat,
        "issued_at_utc": (
            datetime.datetime.fromtimestamp(iat, tz=datetime.timezone.utc).isoformat()
            if iat
            else None
        ),
        "urls": entry_urls(issuer, regtxid),
    }


def receipt_summary(parsed: Sign1Message) -> dict:
    """
    Structured summary of a decoded receipt.
    """
    return summarise_receipt_details(extract_receipt_details(parsed))


def legacy_receipt_details(receipt: "Receipt") -> dict:
    """
    Extract the identifying details of a legacy CCF receipt, which is an
    untagged COSE_Sign1 whose service identity, registration time and
    inclusion proof are carried outside of the CWT claims.
    """
    regtxid = None
    leaf_info = getattr(receipt.contents, "leaf_info", None)
    if leaf_info is not None:
        regtxid = parse_internal_evidence(leaf_info.internal_data)

    return {
        "iss": receipt.phdr.get(crypto.SCITTIssuer),
        "iat": receipt.phdr.get("registration_time"),
        "sigtxid": None,
        "regtxid": regtxid,
    }


def summarise_encoded_receipt(item: bytes) -> dict:
    """
    Structured summary of an encoded receipt, in either the current COSE
    format or the legacy CCF one.
    """
    try:
        return receipt_summary(Sign1Message.decode(item))
    except Exception:
        pass
    try:
        return summarise_receipt_details(legacy_receipt_details(Receipt.decode(item)))
    except Exception:
        return {"error": "Failed to parse receipt"}


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
                            "unprotected": cbor_to_printable(
                                decode_inclusion_proofs(parsed.uhdr)
                            ),
                            "payload": (
                                base64.b64encode(parsed.payload).decode("ascii")
                                if parsed.payload
                                else None
                            ),
                        }
                    except Exception:
                        # Legacy CCF receipts are untagged and are not COSE_Sign1.
                        try:
                            receipt_as_dict = Receipt.decode(item).as_dict()
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
    def verify(self, tbs: bytes, service: Any):
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

    def verify(self, tbs: bytes, service: Any):
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

    def verify(self, claim: Sign1Message, service_params: Any):
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
