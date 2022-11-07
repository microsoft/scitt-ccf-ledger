# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from pyscitt import crypto


class JwtIssuer:
    def __init__(self, name="example.com"):
        self.name = name
        self.key, _ = crypto.generate_rsa_keypair(2048)
        self.cert = crypto.generate_cert(self.key, cn=name)
        self.key_id = crypto.get_cert_fingerprint(self.cert)

    def create_token(self, claims={}):
        return crypto.create_jwt(claims, self.key, self.key_id)

    def create_proposal(self) -> dict:
        return {
            "actions": [
                {
                    "name": "set_jwt_issuer",
                    "args": {
                        "issuer": self.name,
                        "auto_refresh": False,
                        "key_filter": "all",
                        "jwks": crypto.create_jwks(self.cert, self.key_id),
                    },
                }
            ],
        }
