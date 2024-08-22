# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import struct
from io import BytesIO

import cbor2
import pycose
import pytest
from pycose.messages import Sign1Message

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.crypto import cert_pem_to_der
from pyscitt.verify import verify_receipt

from .infra.assertions import service_error
from .infra.x5chain_certificate_authority import X5ChainCertificateAuthority


class NonCanonicalEncoder(cbor2.encoder.CBOREncoder):  # type: ignore[name-defined]
    """
    A variant of cbor2's encoder that introduces deliberate non-canonical
    encodings.

    For most payloads, even setting the canonical flag on cbor2's encoder to
    False produces messages that are canonical anyway, simply as these are also
    the most compact encoding.

    This class goes out of its way to produce inefficiently encoded message.

    Note that this derives from cbor2.encoder.CBOREncoder, which is different
    than cbor2.CBOREncoder. The former is the Python implementation, whereas
    the latter may be implemented in C, and we can't override its
    implementation.
    """

    def __init__(self, fp):
        super().__init__(fp, canonical=False)

        # There are two definitions in the C and Python modules. Make sure we support either.
        self._encoders[cbor2.CBORTag] = self._encoders[cbor2.encoder.CBORTag]
        self._encoders[cbor2.CBORSimpleValue] = self._encoders[
            cbor2.encoder.CBORSimpleValue
        ]

    def encode_length(self, major_tag, length):
        # All lengths are encoded using 8 bytes, regardless of the value, for
        # maximum inefficiency. This function gets called to encode integer
        # values too, so the same applies.
        self._fp_write(struct.pack(">BQ", (major_tag << 5) | 27, length))


def cbor_encode(obj, *, canonical=True):
    with BytesIO() as fp:
        if canonical:
            cbor2.CBOREncoder(fp, canonical=canonical).encode(obj)
        else:
            NonCanonicalEncoder(fp).encode(obj)
        return fp.getvalue()


@pytest.mark.parametrize(
    "value",
    [
        0,
        42,
        [],
        [42],
        "Hello",
        b"World",
    ],
)
def test_cbor_encoder_hack(value):
    """
    Make sure our non-canonical encoding hack actually works.

    It should produce a different encoding than the original encoder, yet still
    roundtrip to the same value.
    """
    encoding = cbor_encode(value, canonical=False)
    assert encoding != cbor_encode(value, canonical=True)
    assert cbor2.loads(encoding) == value


Algorithm = pycose.headers.Algorithm.identifier
ContentType = pycose.headers.ContentType.identifier
X5chain = pycose.headers.X5chain.identifier
KID = pycose.headers.KID.identifier


def sign(signer: crypto.Signer, payload: bytes, parameters: dict, *, canonical=True):
    """
    Sign a COSE Sign1 envelope.

    This function is similar to `crypto.sign_claimset`, but it bypasses pycose
    allowing us to encode invalid messages that pycose would refuse to encode.

    Default values for common parameters will be added automatically if not
    already part of `parameters`. If a parameter needs to be completely omitted
    from the message, its value in the `parameters` dictionary can be set to
    None.
    """

    algorithm = pycose.algorithms.CoseAlgorithm.from_id(signer.algorithm)
    parameters.setdefault(Algorithm, algorithm.identifier)
    parameters.setdefault(ContentType, "text/plain")

    if signer.x5c is not None:
        parameters.setdefault(
            X5chain,
            [cert_pem_to_der(x5) for x5 in signer.x5c],
        )
    if signer.kid is not None:
        parameters.setdefault(KID, signer.kid.encode("utf-8"))
    if signer.issuer is not None:
        parameters.setdefault(crypto.COSE_HEADER_PARAM_ISSUER, signer.issuer)

    # The caller can set a parameter to None to stop this function from adding
    # defaults, but we don't want those None to be encoded, so we filter them
    # out here.
    parameters = {k: v for k, v in parameters.items() if v is not None}

    encoded_headers = cbor_encode(parameters, canonical=canonical)

    key = crypto.cose_private_key_from_pem(signer.private_key)

    tbs = cbor_encode(["Signature1", encoded_headers, b"", payload], canonical=True)
    signature = algorithm.sign(key, tbs)
    message = [encoded_headers, dict(), payload, signature]
    return cbor_encode(
        cbor2.CBORTag(Sign1Message.cbor_tag, message), canonical=canonical
    )


class TestNonCanonicalEncoding:
    @pytest.fixture
    def claim(self, did_web):
        """Create a signed claim, with protected headers encoded non-canonically."""

        identity = did_web.create_identity()
        return sign(identity, b"Hello World", {}, canonical=False)

    def test_submit_claim(self, client: Client, trust_store, claim):
        """The ledger should accept claims even if not canonically encoded."""
        receipt = client.submit_claim_and_confirm(claim).receipt
        verify_receipt(claim, trust_store, receipt)

    def test_embed_receipt(self, client: Client, trust_store, claim):
        """
        When embedding a receipt in a claim, the ledger should not affect the
        encoding of byte-string pieces.
        """
        tx = client.submit_claim_and_confirm(claim).tx
        embedded = client.get_claim(tx, embed_receipt=True)

        original_pieces = cbor2.loads(claim).value  # type: ignore[attr-defined]
        updated_pieces = cbor2.loads(embedded).value  # type: ignore[attr-defined]

        # Any part of the message that is cryptographically bound needs to be preserved.
        # These are respectively, the protected header, the payload and the signature.
        assert original_pieces[0] == updated_pieces[0]
        assert original_pieces[2] == updated_pieces[2]
        assert original_pieces[3] == updated_pieces[3]

    def test_no_buffer_overflow_when_embedding_receipt(self, client: Client, did_web):
        """
        When embedding a receipt in a claim, we should have a sufficiently large buffer
        to accommodate the claim and the receipt. This test creates a claim that is
        500KB in size and embeds the receipt in it.
        The receipt should be embedded in the claim without any issues.
        """

        identity = did_web.create_identity()

        # Create a claim of 500KB in size
        size = int(1024 * 1024 * 0.5)
        claim = crypto.sign_claimset(identity, bytes(size), "binary/octet-stream")

        tx = client.submit_claim_and_confirm(claim).tx
        embedded = client.get_claim(tx, embed_receipt=True)

        original_claim_array = cbor2.loads(claim).value  # type: ignore[attr-defined]
        updated_claim_array = cbor2.loads(embedded).value  # type: ignore[attr-defined]

        # Check that the protected header, the payload and the signature are preserved.
        assert original_claim_array[0] == updated_claim_array[0]
        assert original_claim_array[2] == updated_claim_array[2]
        assert original_claim_array[3] == updated_claim_array[3]


class TestHeaderParameters:
    @pytest.fixture(scope="class")
    def identity(self, did_web):
        return did_web.create_identity()

    @pytest.fixture(scope="class")
    def submit(self, client, identity):
        def f(parameters, *, signer=identity):
            return client.submit_claim_and_confirm(sign(signer, b"Hello", parameters))

        return f

    def test_algorithm(self, submit):
        # We only support integer algorithm identifiers
        with service_error("Failed to decode protected header"):
            submit({Algorithm: "foo"})

        with service_error("Missing algorithm in protected header"):
            submit({Algorithm: None})

    def test_kid(self, submit, identity):
        # This works because our DID document only has a single key.
        submit({KID: None})
        submit({KID: identity.kid.encode("utf-8")})

        with service_error("Failed to decode protected header"):
            # The KID needs to be a byte string.
            submit({KID: identity.kid})

        with service_error("kid must start with '#'"):
            assert identity.kid.startswith("#")
            submit({KID: identity.kid[1:].encode("utf-8")})

    def test_content_type(self, submit):
        # This comes from the CoAP Content-Format registry, and is defined as
        # `text/plain; charset=utf-8` (not that it matters, since the ledger
        # doesn't use the value).
        submit({ContentType: 0})

        submit({ContentType: "text/plain"})

        with service_error("Missing cty in protected header"):
            submit({ContentType: None})

        with service_error("Content-type must be of type text string or int64"):
            # Note this is a byte string, not text string
            submit({ContentType: b"text/plain"})

    def test_x5chain(
        self, submit, client: Client, trusted_ca: X5ChainCertificateAuthority
    ):
        signer = trusted_ca.create_identity(length=1, kty="ec", alg="ES256")
        assert signer.x5c is not None and len(signer.x5c) == 2

        with service_error("x5chain array length was 0"):
            submit({X5chain: []}, signer=signer)

        # Unfortunately, this throws an error during validation because the
        # service requires full chains (including the root CA), and doesn't
        # support self-signed EE certs either. This means we have no way of
        # testing the full submission flow with an x5chain of length 1.
        # We still test that we can at least make it past decoding.
        with service_error("chain must include at least one CA certificate"):
            submit(
                {X5chain: cert_pem_to_der(signer.x5c[0])},
                signer=signer,
            )

        # Technically, the standard disallows this, as chains of length 1
        # should be encoded as a plain bstr, not wrapped in a list. A number of
        # implementations get this wrong though (including Notary), so we
        # explicitly allow it.
        with service_error("chain must include at least one CA certificate"):
            submit(
                {X5chain: [cert_pem_to_der(signer.x5c[0])]},
                signer=signer,
            )

        submit(
            {X5chain: [cert_pem_to_der(c) for c in signer.x5c]},
            signer=signer,
        )

        with service_error("x5chain in COSE header is not array or byte string"):
            submit(
                {X5chain: "Not a bstr"},
                signer=signer,
            )

        with service_error("Next item in x5chain was not of type byte string"):
            submit(
                {X5chain: ["Not a bstr"]},
                signer=signer,
            )

        with service_error("Next item in x5chain was not of type byte string"):
            submit(
                {X5chain: [cert_pem_to_der(signer.x5c[0]), "Not a bstr"]},
                signer=signer,
            )

        with service_error("Could not parse certificate"):
            submit(
                {X5chain: [b"Garbage leaf", cert_pem_to_der(signer.x5c[1])]},
                signer=signer,
            )

        with service_error("Could not parse certificate"):
            submit(
                {X5chain: [cert_pem_to_der(signer.x5c[0]), b"Garbage root"]},
                signer=signer,
            )
