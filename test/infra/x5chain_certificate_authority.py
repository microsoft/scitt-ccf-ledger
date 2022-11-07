# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pyscitt import crypto


class X5ChainCertificateAuthority:
    def __init__(self, host: str = "localhost", **kwargs):
        self.host = host
        self.algorithm = kwargs.pop("alg")
        self.root_key_pem, _ = crypto.generate_keypair(**kwargs)
        self.root_cert_pem = crypto.generate_cert(self.root_key_pem, cn=host, ca=True)

    @property
    def cert_bundle(self) -> str:
        return self.root_cert_pem

    def create_identity(self, x5c_len: int, **kwargs) -> crypto.Signer:
        """
        Create a new identity for x5c signer

        """
        algorithm = kwargs.pop("alg")
        x5c, x5c_priv_key_list = self.create_x5c_node_pem(
            self.root_key_pem, self.root_cert_pem, x5c_len, **kwargs
        )
        return crypto.Signer(x5c_priv_key_list[0], algorithm=algorithm, x5c=x5c)

    def create_x5c_node_pem(
        self,
        root_priv_key_pem: crypto.Pem,
        root_cert_pem: crypto.Pem,
        x5c_len: int,
        **kwargs
    ):
        x5c = [root_cert_pem]
        x5c_priv_key_list = [root_priv_key_pem]
        for i in range(1, x5c_len):
            priv_key_pem, _ = crypto.generate_keypair(**kwargs)
            ca = i < x5c_len - 1
            cert_pem = crypto.generate_cert(
                priv_key_pem, x5c[-1], x5c_priv_key_list[-1], ca=ca
            )
            x5c.append(cert_pem)
            x5c_priv_key_list.append(priv_key_pem)
        return x5c[::-1], x5c_priv_key_list[::-1]
