# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_pem_x509_certificate

from . import crypto


class KeyVaultSignClient:
    """MemberIdentity implementation that uses Azure Key Vault."""

    def __init__(self, akv_sign_configuration_dict: dict):
        self._vault_name = akv_sign_configuration_dict["keyVaultName"]
        self._vault_url = f"https://{self._vault_name}.vault.azure.net"
        self._identity_certificate_name = akv_sign_configuration_dict["certificateName"]
        self._identity_certificate_version = akv_sign_configuration_dict[
            "certificateVersion"
        ]
        self.credential = DefaultAzureCredential()
        cert_client = CertificateClient(
            vault_url=self._vault_url, credential=self.credential
        )
        self.cert = self._decode_certificate(
            cert_client.get_certificate_version(
                certificate_name=self._identity_certificate_name,
                version=self._identity_certificate_version,
            )
        )
        self.key_id = crypto.get_cert_fingerprint(self.cert)

    @staticmethod
    def _decode_certificate(cert: KeyVaultCertificate) -> str:
        decoded = base64.b64encode(cert.cer).decode()  # type: ignore
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{decoded}\n-----END CERTIFICATE-----"
        return cert_pem

    def sign(self, data: bytes):
        key_client = KeyClient(vault_url=self._vault_url, credential=self.credential)

        key = key_client.get_key(
            name=self._identity_certificate_name,
            version=self._identity_certificate_version,
        )

        crypto_client = CryptographyClient(key, credential=self.credential)

        # The signatures returned by AKV are returned as a JWS signature and encoded in
        # base64url format and are not directly compatible with the signatures supported by CCF.
        # See https://github.com/microsoft/CCF/blob/master/doc/members/jws_to_der.py
        # for original conversion code.
        # digest_to_sign = hashlib.sha384(digest.encode()).digest()
        signature_algorithm = SignatureAlgorithm.es384
        cert = load_pem_x509_certificate(self.cert.encode("ascii"), default_backend())

        digest_to_sign = hashlib.new(cert.signature_hash_algorithm.name, data).digest()

        sign_result = crypto_client.sign(
            algorithm=signature_algorithm, digest=digest_to_sign
        )

        # return sign_result, key.id
        # See https://github.com/microsoft/CCF/blob/master/doc/members/jws_to_der.py
        # for original conversion code.
        jws_raw = sign_result.signature
        jws_raw_len = len(jws_raw)
        r = int.from_bytes(jws_raw[: jws_raw_len // 2], byteorder="big")
        s = int.from_bytes(jws_raw[jws_raw_len // 2 :], byteorder="big")
        return encode_dss_signature(r, s)

    def get_key_id(self) -> bytes:
        return self.key_id
