# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time

from pyscitt import crypto


class JwtIssuer:
    def __init__(self, name="example.com"):
        self.name = name
        self.key, _ = crypto.generate_rsa_keypair()
        self.cert = crypto.generate_cert(self.key, cn=name)
        self.key_id = crypto.get_cert_fingerprint(self.cert)

    def create_token(self, claims={}):
        # Add required claims if not already present
        # https://github.com/microsoft/CCF/pull/4786

        # JWT formats times as NumericDate, which is a JSON numeric value counting seconds sine the epoch
        now = int(time.time())
        if "nbf" not in claims:
            # Insert default Not Before claim, valid from ~10 seconds ago
            claims["nbf"] = now - 10
        if "exp" not in claims:
            # Insert default Expiration Time claim, valid for ~1hr
            claims["exp"] = now + 3600
        if "iss" not in claims:
            # Insert default Expiration Time claim, valid for ~1hr
            claims["iss"] = self.name
        return crypto.create_jwt(claims, self.key, self.key_id)

    def create_proposal(self) -> dict:
        return {
            "actions": [
                {
                    "name": "set_jwt_issuer",
                    "args": {
                        "issuer": self.name,
                        "auto_refresh": False,
                        "jwks": crypto.create_jwks(self.cert, self.key_id),
                    },
                }
            ],
        }
