# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from pycose import algorithms, headers
from pycose.messages import Sign1Message

from pyscitt import crypto
from pyscitt.client import Client


class TestNonCanonicalEncoding:
    @pytest.fixture
    def claim(self, did_web):
        """Create a signed claim, with protected headers encoded non-canonically."""

        identity = did_web.create_identity()

        attributes = {
            headers.Algorithm.identifier: algorithms.Es256.identifier,
            headers.ContentType.identifier: "text/plain",
            crypto.COSE_HEADER_PARAM_ISSUER: identity.issuer,
        }

        # pycose and cbor2 use canonical encoding, which we explicitly want to avoid here.
        # We encode the protected header manually, using inefficient encodings:
        # - 0xba marks the start of a map, with a uint32 length
        # - 0x1a marks a uint32, which we use to encode the keys of the map.
        # For simplicity we defer to cbor2 to encode values. We have enough non-canonicity already.
        protected = bytes([0xBA]) + len(attributes).to_bytes(4, "big")
        protected += b"".join(
            bytes([0x1A]) + k.to_bytes(4, "big") + cbor2.dumps(v)
            for k, v in attributes.items()
        )
        print(protected.hex(), attributes, cbor2.loads(protected))
        assert cbor2.loads(protected) == attributes
        assert protected != cbor2.dumps(attributes)

        payload = b"Hello World"
        key = crypto.cose_private_key_from_pem(identity.private_key)

        # The rest is pretty standard COSE signing: create the TBS, sign it,
        # piece everything together to create the message. The following line
        # is the only step that must really be canonically encoded by every party.
        tbs = cbor2.dumps(["Signature1", protected, b"", payload])
        signature = algorithms.Es256.sign(key, tbs)
        message = [protected, dict(), payload, signature]
        return cbor2.dumps(cbor2.CBORTag(Sign1Message.cbor_tag, message))

    def test_submit_claim(self, client: Client, trust_store, claim):
        """The ledger should accept claims even if not canonically encoded."""
        client.submit_claim(claim)

    @pytest.mark.xfail(
        reason="pycose does not preserve the original encoding (https://github.com/TimothyClaeys/pycose/pull/91)",
        raises=InvalidSignature,
    )
    def test_verify_receipt(self, client: Client, trust_store, claim):
        """We should be able to verify the produced receipt."""
        # Once the xfail is fixed, this test can be merged with test_submit_claim.
        receipt = client.submit_claim(claim).receipt
        crypto.verify_cose_with_receipt(claim, trust_store, receipt)

    def test_embed_receipt(self, client: Client, trust_store, claim):
        """When embedding a receipt in a claim, the ledger should not affect the original encoding."""
        tx = client.submit_claim(claim).tx
        embedded = client.get_claim(tx, embed_receipt=True)

        original_pieces = cbor2.loads(claim).value
        updated_pieces = cbor2.loads(embedded).value

        # Any part of the message that is cryptographically bound needs to be preserved.
        # These are respectively, the protected header, the payload and the signature.
        assert original_pieces[0] == updated_pieces[0]
        assert original_pieces[2] == updated_pieces[2]
        assert original_pieces[3] == updated_pieces[3]
