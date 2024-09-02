# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, List, Union

import cbor2
from pycose.messages import CoseMessage, Sign1Message
from pycose.messages.cosebase import CoseBase

if TYPE_CHECKING:
    from .client import BaseClient

from .crypto import SCITTFeed, SCITTIssuer
from .receipt import ReceiptContents, cbor_as_dict
from .verify import ServiceParameters


class bitvector:
    def __init__(self, data):
        self.data = data

    def __getitem__(self, i):
        assert i < self.size()
        return bool(self.data[i // 8] & (0x80 >> (i % 8)))

    def prefix(self, n):
        assert n < self.size()

        data = [0] * len(self.data)
        for i in range(n // 8):
            data[i] = self.data[i]

        padding = 0x80 >> (n % 8)
        mask = ~(padding - 1)

        i = n // 8
        data[i] = (self.data[i] & mask) | padding

        return bytes(data)

    def size(self):
        return len(self.data) * 8

    def bit_count(self):
        return sum(self[i] for i in range(self.size()))


@dataclass
class Path:
    positions: bytes
    hashes: List[bytes]

    def __post_init__(self):
        positions = bitvector(self.positions)
        if positions.bit_count() != len(self.hashes):
            raise ValueError(
                f"Expected {positions.bit_count()} hashes, got {len(self.hashes)} instead"
            )

    def hash(self, index: bytes, leaf: bytes) -> bytes:
        positions = bitvector(self.positions)
        hashes = reversed(self.hashes)
        index_bits = bitvector(index)

        current = leaf
        for i in reversed(range(256)):
            if positions[i]:
                node = hashlib.sha256(index_bits.prefix(i))
                if index_bits[i]:
                    node.update(next(hashes))
                    node.update(current)
                else:
                    node.update(current)
                    node.update(next(hashes))
                current = node.digest()
        return current


@dataclass
class ReadReceipt:
    tree_headers: dict
    leaf_headers: dict
    tree_hdr_encoded: bytes
    leaf_hdr_encoded: bytes
    proof: Path
    tree_receipt: ReceiptContents

    @classmethod
    def from_cose_obj(cls, cose_obj: list) -> "ReadReceipt":
        tree_hdr_encoded = cose_obj.pop(0)
        leaf_hdr_encoded = cose_obj.pop(0)
        path = Path(*cose_obj.pop(0))

        tree_hdr = CoseBase._parse_header(cbor2.loads(tree_hdr_encoded), True)
        leaf_hdr = CoseBase._parse_header(cbor2.loads(leaf_hdr_encoded), True)
        tree_receipt = ReceiptContents.from_cose_obj(tree_hdr, cose_obj.pop(0))

        return ReadReceipt(
            tree_hdr, leaf_hdr, tree_hdr_encoded, leaf_hdr_encoded, path, tree_receipt
        )

    @classmethod
    def decode(cls, data: bytes):
        return cls.from_cose_obj(cbor2.loads(data))  # type: ignore[arg-type]

    def verify(
        self, claim: Union[Sign1Message, bytes], service_params: ServiceParameters
    ):
        if isinstance(claim, bytes):
            claim_ = CoseMessage.decode(claim)
            assert isinstance(claim_, Sign1Message)
            claim = claim_

        tbs = self.tree_tbs(claim)
        self.tree_receipt.verify(tbs, service_params)

    def tree_tbs(self, claim: Sign1Message) -> bytes:
        context = "SCITT"
        structure = [context, self.tree_hdr_encoded, self.root(claim)]
        return cbor2.dumps(structure)

    def root(self, claim: Sign1Message) -> bytes:
        index = self.claim_index(claim)
        leaf = self.leaf_hash(index, claim)
        return self.proof.hash(index, leaf)

    @classmethod
    def claim_index(cls, claim: Sign1Message):
        issuer = claim.get_attr(SCITTIssuer)
        feed = claim.get_attr(SCITTFeed, "")
        return hashlib.sha256(cbor2.dumps([issuer, feed])).digest()

    def leaf_hash(self, index: bytes, claim: Sign1Message) -> bytes:
        digest = hashlib.sha256(self.leaf_tbs(claim)).digest()
        return hashlib.sha256(index + digest).digest()

    def leaf_tbs(self, claim: Sign1Message) -> bytes:
        context = "CounterSignatureV2"
        structure = [
            context,
            claim.phdr_encoded,
            self.leaf_hdr_encoded,
            b"",  # no external AAD
            claim.payload,
            [claim.signature],
        ]
        return cbor2.dumps(structure)

    def as_dict(self) -> dict:
        return {
            "tree_headers": cbor_as_dict(self.tree_headers),
            "leaf_headers": cbor_as_dict(self.leaf_headers),
            "proof": {
                "positions": self.proof.positions.hex(),
                "hashes": [h.hex() for h in self.proof.hashes],
            },
            "tree_receipt": self.tree_receipt.as_dict(),
        }


@dataclass
class TreeReceipt:
    headers_encoded: bytes
    headers: dict
    root: bytes
    receipt_contents: ReceiptContents

    @classmethod
    def decode(cls, data: bytes) -> "TreeReceipt":
        cose_obj = cbor2.loads(data)
        headers_encoded = cose_obj.pop(0)  # type: ignore[attr-defined]
        headers = CoseBase._parse_header(cbor2.loads(headers_encoded), True)
        root = cose_obj.pop(0)  # type: ignore[attr-defined]
        receipt_contents = ReceiptContents.from_cose_obj(headers, cose_obj.pop(0))  # type: ignore[attr-defined]
        return TreeReceipt(headers_encoded, headers, root, receipt_contents)

    @property
    def upper_bound_seqno(self) -> int:
        return self.headers["upper_bound_seqno"]


class PrefixTreeClient:
    client: "BaseClient"

    def __init__(self, client: "BaseClient"):
        self.client = client

    def flush(self):
        def is_indexed(data: bytes, upper_bound_seqno: int) -> bool:
            return TreeReceipt.decode(data).upper_bound_seqno >= upper_bound_seqno

        info = self.client.post("/prefix_tree/flush", wait_for_confirmation=True).json()

        # The confirmation we get from the flush is not quite enough for the
        # results to be visible, since it may take some time for the indexer to
        # process the commit.
        #
        # Query the indexer until its upper bound is greater or equal to what
        # we got when flushing. We also need to handle the NoPrefixTree 404 error,
        # which can happen on a fresh service.
        self.client.get_historical(
            "/prefix_tree",
            retry_on=[
                (HTTPStatus.NOT_FOUND, "NoPrefixTree"),
                lambda r: r.is_success
                and not is_indexed(r.content, info["upper_bound"]),
            ],
        )
        return info

    def debug(self) -> dict:
        return self.client.get("/prefix_tree/debug").json()

    def get_read_receipt(self, issuer: str, feed: str, *, decode=True):
        response = self.client.get_historical(f"/read_receipt/{issuer}/{feed}")
        if decode:
            return ReadReceipt.decode(response.content)
        else:
            return response.content
