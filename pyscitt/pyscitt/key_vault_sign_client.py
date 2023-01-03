import base64
import hashlib
import json
from azure.identity import DefaultAzureCredential
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Integer, Sequence
from pyasn1.codec.der.encoder import encode

from azure.keyvault.certificates import (
    CertificateClient,
    KeyVaultCertificate
)
from azure.keyvault.keys import (
    KeyClient
    )
from azure.keyvault.keys.crypto import (
    CryptographyClient,
    SignatureAlgorithm,
)

class _DERSignature(Sequence):
    """Internal helper class for decoding AKV signature for CCF."""
    componentType = NamedTypes(
        NamedType("r", Integer()),
        NamedType("s", Integer()),
    )

class KeyVaultSignClient():
    """MemberIdentity implementation that uses Azure Key Vault."""

    def __init__(self, akv_sign_configuration: str):
        akv_sign_configuration_dict = json.loads(akv_sign_configuration)
        self._vault_name = akv_sign_configuration_dict['keyVaultName']
        self._vault_url = f"https://{self._vault_name}.vault.azure.net"
        self._identity_certificate_name = akv_sign_configuration_dict['cetificateName']
        self._identity_certificate_version = akv_sign_configuration_dict['cetificateVersion']
        self._identity_private_curve_key_size = akv_sign_configuration_dict['privateCurveKeySize']
    
    @staticmethod
    def _decode_certificate(cert: KeyVaultCertificate) -> str:
        decoded = base64.b64encode(cert.cer).decode()  # type: ignore

        styled_cert = "-----BEGIN CERTIFICATE-----\n"
        for index in range(0, len(decoded), 64):
            if index + 64 > len(decoded):
                styled_cert += decoded[index:]
            else:
                styled_cert += decoded[index : index + 64]
            styled_cert += "\n"
        styled_cert += "-----END CERTIFICATE-----"
        return styled_cert

    def sign_with_idetity(self, digest: bytes):
        credential = DefaultAzureCredential()
        key_client = KeyClient(vault_url=self._vault_url, credential=credential)
        cert_client = CertificateClient(vault_url=self._vault_url, credential=credential)

        key = key_client.get_key(
                        name=self._identity_certificate_name,
                        version=self._identity_certificate_version,
                    )
                    
        cert = cert_client.get_certificate_version(
            certificate_name=self._identity_certificate_name,
            version=self._identity_certificate_version
            )

        crypto_client = CryptographyClient(key, credential=credential)

        # The signatures returned by AKV are returned as a JWS signature and encoded in
        # base64url format and are not directly compatible with the signatures supported by CCF.
        sign_result = None
        signature_algorithm = SignatureAlgorithm.es384
        # See https://github.com/microsoft/CCF/blob/master/doc/members/jws_to_der.py
        # for original conversion code.
        # digest_to_sign = hashlib.sha384(digest.encode()).digest()

        digest_to_sign = {
            256: hashlib.sha256(digest).digest(), 
            384: hashlib.sha384(digest).digest()
            }[self._identity_private_curve_key_size]
            
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
        output_buf = encode(der_signature)
        return output_buf, self._decode_certificate(cert)