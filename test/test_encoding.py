# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import struct
from io import BytesIO

import cbor2
import pycose
import pytest
from pycose.keys.cosekey import CoseKey
from pycose.messages import Sign1Message

from pyscitt import crypto
from pyscitt.client import Client
from pyscitt.crypto import CWT_ISS, CWTClaims, cert_pem_to_der
from pyscitt.verify import verify_transparent_statement

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

    This function is similar to `crypto.sign_statement`, but it bypasses pycose
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

    # set
    if signer.issuer is not None:
        parameters[CWTClaims.identifier] = {CWT_ISS: signer.issuer}

    # The caller can set a parameter to None to stop this function from adding
    # defaults, but we don't want those None to be encoded, so we filter them
    # out here.
    parameters = {k: v for k, v in parameters.items() if v is not None}

    encoded_headers = cbor_encode(parameters, canonical=canonical)

    key = CoseKey.from_pem_private_key(signer.private_key)

    tbs = cbor_encode(["Signature1", encoded_headers, b"", payload], canonical=True)
    signature = algorithm.sign(key, tbs)
    message = [encoded_headers, dict(), payload, signature]
    return cbor_encode(
        cbor2.CBORTag(Sign1Message.cbor_tag, message), canonical=canonical
    )


class TestNonCanonicalEncoding:
    @pytest.fixture
    def signed_statement(self, trusted_ca):
        """Create a signed statement, with protected headers encoded non-canonically."""

        identity = trusted_ca.create_identity(alg="ES256", kty="ec")
        return sign(identity, b"Hello World", {}, canonical=False)

    @pytest.mark.skip(
        "Payloads are accepted, but uhdr stripping results in canonicalisation, and so the receipt cannot match"
    )
    def test_submit_signed_statement(
        self, client: Client, trust_store, signed_statement
    ):
        """The ledger should accept signed statements even if not canonically encoded."""
        transparent_statement = client.register_signed_statement(
            signed_statement
        ).response_bytes
        verify_transparent_statement(
            transparent_statement, trust_store, signed_statement
        )


class TestHeaderParameters:
    @pytest.fixture(scope="class")
    def identity(self, trusted_ca):
        return trusted_ca.create_identity(
            length=1, alg="ES256", kty="ec", ec_curve="P-256", add_eku="2.999"
        )

    @pytest.fixture(scope="class")
    def submit(self, client, identity):
        def f(parameters, *, signer=identity):
            return client.register_signed_statement(sign(signer, b"Hello", parameters))

        return f

    def test_algorithm(self, submit):
        # We only support integer algorithm identifiers
        with service_error("Failed to decode protected header"):
            submit({Algorithm: "foo"})

        with service_error("Missing algorithm in protected header"):
            submit({Algorithm: None})

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
        self,
        submit,
        client: Client,
        trusted_ca: X5ChainCertificateAuthority,
        configure_service,
    ):
        configure_service(
            {"policy": {"policyScript": "export function apply() { return true; }"}}
        )

        signer = trusted_ca.create_identity(
            length=1, kty="ec", alg="ES256", add_eku="2.999"
        )
        assert signer.x5c is not None and len(signer.x5c) == 2

        with service_error("x5chain array length was 0"):
            submit({X5chain: []}, signer=signer)

        with service_error("certificate chain too short"):
            submit(
                {X5chain: cert_pem_to_der(signer.x5c[0])},
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

        with service_error("OpenSSL error"):
            submit(
                {X5chain: [cert_pem_to_der(signer.x5c[0]), b"Garbage root"]},
                signer=signer,
            )
