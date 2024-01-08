# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import base64
import json
import re
from enum import Enum
from pathlib import Path
from typing import List, Optional

import pycose.headers
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_pem_x509_certificate

from pyscitt.key_vault_sign_client import KeyVaultSignClient

from .. import crypto, did


class RegistrationInfoType(Enum):
    TEXT = "text"
    BYTES = "bytes"
    INT = "int"


class RegistrationInfoArgument:
    type: RegistrationInfoType
    name: str
    content: str

    # This won't support names that contain an '=' or ':'.
    # This is probably fine for the time being, but we should have a scheme to escape those.
    PATTERN = re.compile("((?P<type>[^=:]+):)?" "(?P<name>[^=:]+)=" "(?P<content>.*)")

    def __init__(self, value: str):
        match = self.PATTERN.fullmatch(value)
        if not match:
            raise argparse.ArgumentTypeError(
                f"'{value}' is not a valid registration info argument"
            )

        type_ = match.group("type")
        if type_ is None:
            self.type = RegistrationInfoType.TEXT
        else:
            try:
                self.type = RegistrationInfoType(type_)
            except Exception as e:
                raise argparse.ArgumentTypeError(
                    f"'{type}' is not a valid registration info type"
                ) from None

        self.name = match.group("name")
        self.content = match.group("content")

    def value(self) -> crypto.RegistrationInfoValue:
        if self.content.startswith("@"):
            data = Path(self.content[1:]).read_bytes()
        else:
            data = self.content.encode("ascii")

        if self.type is RegistrationInfoType.INT:
            return int(data.decode("utf-8"))
        elif self.type is RegistrationInfoType.TEXT:
            return data.decode("utf-8")
        elif self.type is RegistrationInfoType.BYTES:
            return data


def _parse_x5c_file(x5c_path: str) -> List[str]:
    # Load x509 root certificates
    with open(x5c_path, "rb") as f:
        cacert_data = f.read()

    certs = []
    while cacert_data:
        pemcert, _, cacert_data = cacert_data.partition(b"-----END CERTIFICATE-----\n")
        pemcert += b"-----END CERTIFICATE-----\n"
        certs.append(pemcert.decode())
    return certs


def create_signer_from_arguments(
    key_path: Path,
    did_doc_path: Optional[Path],
    kid: Optional[str],
    issuer: Optional[str],
    algorithm: Optional[str],
    x5c_path: Optional[str],
) -> crypto.Signer:
    key = crypto.load_private_key(key_path)

    if did_doc_path:
        if issuer or algorithm:
            raise ValueError(
                "The --issuer and --alg flags may not be used together with a DID document."
            )

        with open(did_doc_path) as f:
            did_doc = json.load(f)
        return did.get_signer(key, did_doc, kid)
    elif x5c_path:
        ca_certs = _parse_x5c_file(x5c_path)

        return crypto.Signer(key, algorithm=algorithm, x5c=ca_certs)
    else:
        return crypto.Signer(key, issuer, kid, algorithm)


def sign_claims(
    claims_path: Path,
    key_path: Path,
    out_path: Path,
    did_doc_path: Optional[Path],
    issuer: Optional[str],
    content_type: str,
    algorithm: Optional[str],
    kid: Optional[str],
    feed: Optional[str],
    registration_info_args: List[RegistrationInfoArgument],
    x5c_path: Optional[str],
    akv_configuration_path: Optional[Path],
):
    # If a Key Vault configuration is provided, we sign with AKV
    if akv_configuration_path:
        if not x5c_path:
            raise ValueError(
                "The --x5c flag must be provided when signing with Azure Key Vault."
            )

        # Parse the AKV configuration file
        akv_sign_configuration_dict = json.loads(akv_configuration_path.read_text())

        # Parse the x5c file containing the x509 CA certificates
        ca_certs = _parse_x5c_file(x5c_path)

        kv_client = KeyVaultSignClient(akv_sign_configuration_dict)
        signed_claims = kv_client.cose_sign(
            claims_path.read_bytes(),
            {
                pycose.headers.ContentType: content_type,
                pycose.headers.X5chain: [crypto.cert_pem_to_der(x5) for x5 in ca_certs],
            },
        )
    else:
        signer = create_signer_from_arguments(
            key_path, did_doc_path, kid, issuer, algorithm, x5c_path
        )
        claims = claims_path.read_bytes()
        registration_info = {arg.name: arg.value() for arg in registration_info_args}

        signed_claims = crypto.sign_claimset(
            signer, claims, content_type, feed, registration_info
        )

    print(f"Writing {out_path}")
    out_path.write_bytes(signed_claims)


def cli(fn):
    parser = fn(description="Sign a claimset")
    parser.add_argument(
        "--claims", type=Path, required=True, help="Path to claims file"
    )
    parser.add_argument(
        "--key", type=Path, required=False, help="Path to PEM-encoded private key"
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path for signed claimset (must end in .cose)",
    )

    # Signing with a Key Vault certificate
    parser.add_argument(
        "--akv-configuration",
        type=Path,
        help="Path to an Azure key vault configuration file. The configuration is a JSON file containing the following fields: keyVaultName, certificateName, certificateVersion.",
    )

    # Signing with an existing DID document
    parser.add_argument("--did-doc", type=Path, help="Path to DID document")

    # Ad-hoc signing, without any on-disk document
    parser.add_argument("--issuer", help="Issuer stored in envelope header")
    parser.add_argument("--alg", help="Signing algorithm to use.")
    parser.add_argument("--x5c", help="Path to PEM-encoded certificate authority")

    parser.add_argument("--content-type", required=True, help="Content type of claims")
    parser.add_argument("--kid", help='Key ID ("kid" field) to use if multiple')
    parser.add_argument("--feed", help='Optional "feed" stored in envelope header')
    parser.add_argument(
        "--registration-info",
        metavar="[TYPE:]NAME=CONTENT",
        action="append",
        type=RegistrationInfoArgument,
        default=[],
        help="""
        Optional registration information to be stored in the envelope header.
        The flag may be specified multiple times, once per registration info entry.
        If content has the form `@file.txt`, the data will be read from the specified file instead.
        The type must be one of `text`, `bytes` or `int`. If not specified, the type defaults to text.
        """,
    )

    parser.set_defaults(
        func=lambda args: sign_claims(
            args.claims,
            args.key,
            args.out,
            args.did_doc,
            args.issuer,
            args.content_type,
            args.alg,
            args.kid,
            args.feed,
            args.registration_info,
            args.x5c,
            args.akv_configuration,
        )
    )

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
