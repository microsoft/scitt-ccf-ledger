# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ccf.cose import create_cose_sign1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pyscitt.client import MemberAuthenticationMethod


class LocalKeySignClient(MemberAuthenticationMethod):
    def __init__(self, cert: str, key: str) -> None:
        self.cert = cert
        self.key = key
        self.private_key = load_pem_private_key(
            key.encode("ascii"),
            password=None,
        )

    def cose_sign(self, data: bytes, cose_headers: dict) -> bytes:
        """Generates a COSE payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes
        :param cose_headers: The headers to include in the COSE payload.
        :type cose_headers: dict

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """

        assert self.cert, "No identity public certificate available for this identity"
        assert self.key, "No identity private key available for this identity"

        return create_cose_sign1(
            payload=data,
            key_priv_pem=self.key,
            cert_pem=self.cert,
            additional_protected_header=cose_headers,
        )

    def http_sign(self, data: bytes):
        """
        Generates a HTTP signing payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """

        assert isinstance(self.private_key, (EllipticCurvePrivateKey))
        digest_algo = {256: hashes.SHA256(), 384: hashes.SHA384()}[
            self.private_key.curve.key_size
        ]
        signature = self.private_key.sign(
            signature_algorithm=ec.ECDSA(algorithm=digest_algo), data=data
        )
        return signature
