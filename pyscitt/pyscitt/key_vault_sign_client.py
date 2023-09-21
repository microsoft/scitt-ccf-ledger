# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from ccf.cose import create_cose_sign1_finish, create_cose_sign1_prepare
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import load_pem_x509_certificate

from pyscitt.client import MemberAuthenticationMethod

from . import crypto

ALGORITHMS = {
    256: ("ES256", "sha256"),
    384: ("ES384", "sha384"),
    521: ("ES512", "sha384"),
}


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
        assert isinstance(cert.cer, bytearray)
        decoded = base64.b64encode(cert.cer).decode()
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{decoded}\n-----END CERTIFICATE-----"
        return cert_pem

    def _get_crypto_client(self):
        key_client = KeyClient(vault_url=self._vault_url, credential=self.credential)
        key = key_client.get_key(
            name=self._identity_certificate_name,
            version=self._identity_certificate_version,
        )
        crypto_client = CryptographyClient(key, credential=self.credential)
        return crypto_client

    def cose_sign(self, data: bytes, cose_headers: dict) -> bytes:
        """Generates a COSE payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes
        :param cose_headers: The headers to include in the COSE payload.
        :type cose_headers: dict

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """

        tbs = create_cose_sign1_prepare(
            payload=data,
            cert_pem=self.cert,
            additional_protected_header=cose_headers,
        )

        digest_to_sign = base64.b64decode(tbs["value"].encode())

        algorithm = SignatureAlgorithm(tbs["alg"])

        crypto_client = self._get_crypto_client()

        sign_result = crypto_client.sign(
            algorithm=SignatureAlgorithm(algorithm), digest=digest_to_sign
        )

        return create_cose_sign1_finish(
            payload=data,
            cert_pem=self.cert,
            signature=base64.urlsafe_b64encode(sign_result.signature).decode(),
            additional_protected_header=cose_headers,
        )

    def http_sign(self, data: bytes):
        """
        Generates a HTTP signing payload for the specified request with the specified headers.

        https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#signing

        :param data: The intended body for the HTTP request.
        :type data: bytes

        :return: The full payload, with signature, to be sent to CCF.
        :rtype: bytes
        """

        crypto_client = self._get_crypto_client()
        cert = load_pem_x509_certificate(self.cert.encode("ascii"))
        pub_key = cert.public_key()
        assert isinstance(pub_key, (EllipticCurvePublicKey))
        key_size = pub_key.curve.key_size
        signature_algorithm, hash_algorithm = ALGORITHMS[key_size]

        digest_to_sign = hashlib.new(hash_algorithm, data).digest()
        sign_result = crypto_client.sign(
            algorithm=SignatureAlgorithm(signature_algorithm), digest=digest_to_sign
        )
        return crypto.convert_p1363_signature_to_dss(sign_result.signature)
