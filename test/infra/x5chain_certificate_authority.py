# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import List, Tuple

from pyscitt import crypto
from pyscitt.crypto import Pem


class X5ChainCertificateAuthority:
    def __init__(self, **kwargs):
        self.root_key_pem, _ = crypto.generate_keypair(**kwargs)
        self.root_cert_pem = crypto.generate_cert(self.root_key_pem, ca=True)

    @property
    def cert_bundle(self) -> str:
        return self.root_cert_pem

    def create_identity(
        self, *, alg: str, length: int = 1, ca: bool = False, **kwargs
    ) -> crypto.Signer:
        """
        Create a new identity for x5c signer
        """
        x5c, private_key = self.create_chain(length=length, ca=ca, **kwargs)
        return crypto.Signer(private_key, algorithm=alg, x5c=x5c)

    def create_chain(
        self, *, length: int = 1, ca: bool = False, **kwargs
    ) -> Tuple[List[Pem], Pem]:
        assert length > 0
        generate_cert_kwargs = {}
        # Unlike the rest of the kwargs, which are handed over to the keypair generation
        # call, add_eku is passed to the certificate generation call.
        add_eku = "add_eku"
        if add_eku in kwargs:
            generate_cert_kwargs[add_eku] = kwargs[add_eku]
            del kwargs[add_eku]

        chain = [(self.root_cert_pem, self.root_key_pem)]
        for i in range(length):
            private_key, _ = crypto.generate_keypair(**kwargs)
            cert_pem = crypto.generate_cert(
                private_key_pem=private_key,
                issuer=chain[-1],
                ca=(i < length - 1) or ca,
                **generate_cert_kwargs
            )
            chain.append((cert_pem, private_key))

        _, private_key = chain[-1]
        return [cert for (cert, _) in reversed(chain)], private_key
