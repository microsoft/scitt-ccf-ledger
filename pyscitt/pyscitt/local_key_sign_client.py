# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from loguru import logger as LOG

from pyscitt.client import MemberAuthenticationMethod

from . import crypto


class localKeySignClient(MemberAuthenticationMethod):
    def __init__(self, cert: str, key: str) -> None:
        self.key_id = crypto.get_cert_fingerprint(cert)
        self.private_key = load_pem_private_key(
            key.encode("ascii"),
            password=None,
            backend=default_backend(),
        )

    def get_key_id(self) -> bytes:
        return self.key_id

    def sign(self, data: bytes) -> bytes:
        digest_algo = {256: hashes.SHA256(), 384: hashes.SHA384()}[
            self.private_key.curve.key_size
        ]
        signature = self.private_key.sign(
            signature_algorithm=ec.ECDSA(algorithm=digest_algo), data=data
        )
        return signature
