# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import hashlib

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from pyasn1.codec.der.encoder import encode
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.univ import Integer, Sequence

from . import crypto


class _DERSignature(Sequence):
    """Internal helper class for decoding AKV signature for CCF."""

    componentType = NamedTypes(
        NamedType("r", Integer()),
        NamedType("s", Integer()),
    )


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

    def sign_with_identity(self, digest: bytes):
        # credential = DefaultAzureCredential()
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

        digest_to_sign = {
            "sha256": hashlib.sha256(digest).digest(),
            "sha384": hashlib.sha384(digest).digest(),
        }[cert.signature_hash_algorithm.name]

        sign_result = crypto_client.sign(
            algorithm=signature_algorithm, digest=digest_to_sign
        )

        # return sign_result, key.id
        # See https://github.com/microsoft/CCF/blob/master/doc/members/jws_to_der.py
        # for original conversion code.
        jws_raw = sign_result.signature
        jws_raw_len = len(jws_raw)

        der_signature = _DERSignature()
        der_signature["r"] = int.from_bytes(
            jws_raw[: int(jws_raw_len / 2)], byteorder="big"
        )
        der_signature["s"] = int.from_bytes(
            jws_raw[-int(jws_raw_len / 2) :], byteorder="big"
        )
        return encode(der_signature)

    def get_key_id(self) -> bytes:
        return self.key_id

    def sign(self, data: bytes) -> bytes:
        signature = self.sign_with_identity(data)
        return signature
