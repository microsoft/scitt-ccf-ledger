# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Dict, Optional

from ccf.cose import create_cose_sign1

from pyscitt.client import MemberAuthenticationMethod


class LocalKeySignClient(MemberAuthenticationMethod):
    def __init__(self, cert: str, key: str) -> None:
        self.cert = cert
        self.key = key

    def cose_sign(self, data: bytes, cose_headers: Optional[Dict] = None) -> bytes:
        """Generates a COSE payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes
        :param cose_headers: The headers to include in the COSE payload.
        :type cose_headers: Optional[Dict]

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """

        assert self.cert, "No identity public certificate available for this identity"
        assert self.key, "No identity private key available for this identity"

        # Use the CCF library to generate the COSE payload
        return create_cose_sign1(
            payload=data,
            key_priv_pem=self.key,
            cert_pem=self.cert,
            additional_protected_header=cose_headers,
        )
