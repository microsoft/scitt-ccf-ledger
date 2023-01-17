# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import List, Tuple

from pyscitt import crypto
from pyscitt.crypto import Pem


class X5ChainCertificateAuthority:
    def __init__(self, cn: str = "localhost", **kwargs):
        self.cn = cn
        self.algorithm = kwargs.pop("alg")
        self.root_key_pem, _ = crypto.generate_keypair(**kwargs)
        self.root_cert_pem = crypto.generate_cert(self.root_key_pem, cn=cn, ca=True)

    @property
    def cert_bundle(self) -> str:
        return self.root_cert_pem

    def create_identity(self, length: int, **kwargs) -> crypto.Signer:
        """
        Create a new identity for x5c signer
        """
        algorithm = kwargs.pop("alg")
        x5c, private_key = self.create_chain(length, **kwargs)
        return crypto.Signer(private_key, algorithm=algorithm, x5c=x5c)

    def create_chain(self, length: int, **kwargs) -> Tuple[List[Pem], Pem]:
        x5c = [self.root_cert_pem]
        private_key = self.root_key_pem

        for i in range(length):
            next_private_key, _ = crypto.generate_keypair(**kwargs)
            ca = i < length
            cert_pem = crypto.generate_cert(
                next_private_key, x5c[-1], private_key, ca=ca
            )
            x5c.append(cert_pem)
            private_key = next_private_key

        return x5c[::-1], private_key
