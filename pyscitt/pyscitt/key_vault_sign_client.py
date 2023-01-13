# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_pem_x509_certificate

from pyscitt.client import MemberAuthenticationMethod

from . import crypto


class KeyVaultSignClient(MemberAuthenticationMethod):
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
        self.cert = self._encode_certificate(
            cert_client.get_certificate_version(
                certificate_name=self._identity_certificate_name,
                version=self._identity_certificate_version,
            )
        )

    @staticmethod
    def _encode_certificate(cert: KeyVaultCertificate) -> str:
        assert isinstance(cert.cer, bytes)
        decoded = base64.b64encode(cert.cer).decode()
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{decoded}\n-----END CERTIFICATE-----"
        return cert_pem

    def sign(self, data: bytes):
        key_client = KeyClient(vault_url=self._vault_url, credential=self.credential)
        key = key_client.get_key(
            name=self._identity_certificate_name,
            version=self._identity_certificate_version,
        )
        crypto_client = CryptographyClient(key, credential=self.credential)
        cert = load_pem_x509_certificate(self.cert.encode("ascii"))
        assert isinstance(cert.public_key, (EllipticCurvePublicKey))
        key_size = cert.public_key().curve.key_size
        signature_algorithm = "ES" + str(key_size)
        hash_algorithm = "sha" + str(key_size)
        digest_to_sign = hashlib.new(hash_algorithm, data).digest()
        sign_result = crypto_client.sign(
            algorithm=signature_algorithm, digest=digest_to_sign
        )
        return crypto.convert_p1363_signature_to_dss(sign_result.signature)
