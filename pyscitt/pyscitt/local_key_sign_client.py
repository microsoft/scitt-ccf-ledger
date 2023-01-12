# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from loguru import logger as LOG

from pyscitt.client import MemberAuthenticationMethod


class LocalKeySignClient(MemberAuthenticationMethod):
    def __init__(self, cert: str, key: str) -> None:
        self.cert = cert
        self.key = key
        self.private_key = load_pem_private_key(
            key.encode("ascii"),
            password=None,
        )

    def sign(self, data: bytes) -> bytes:
        digest_algo = {256: hashes.SHA256(), 384: hashes.SHA384()}[
            self.private_key.curve.key_size
        ]
        signature = self.private_key.sign(
            signature_algorithm=ec.ECDSA(algorithm=digest_algo), data=data
        )
        return signature
