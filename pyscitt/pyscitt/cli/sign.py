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

from .. import crypto


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


def sign_statement(
    statement_path: Path,
    key_path: Path,
    out_path: Path,
    issuer: Optional[str],
    content_type: str,
    algorithm: Optional[str],
    kid: Optional[str],
    feed: Optional[str],
    registration_info_args: List[RegistrationInfoArgument],
    x5c_path: Optional[str],
    akv_configuration_path: Optional[Path],
    uses_cwt: bool = False,
):
    if not x5c_path:
        raise ValueError("The --x5c flag must be provided")
    ca_certs = _parse_x5c_file(x5c_path)

    # If a Key Vault configuration is provided, we sign with AKV
    if akv_configuration_path:
        # Parse the AKV configuration file
        akv_sign_configuration_dict = json.loads(akv_configuration_path.read_text())
        kv_client = KeyVaultSignClient(akv_sign_configuration_dict)
        signed_statement = kv_client.cose_sign(
            statement_path.read_bytes(),
            {
                pycose.headers.ContentType: content_type,
                pycose.headers.X5chain: [crypto.cert_pem_to_der(x5) for x5 in ca_certs],
            },
        )
    else:
        key = crypto.load_private_key(key_path)
        signer = crypto.Signer(
            key, kid=kid, issuer=issuer, algorithm=algorithm, x5c=ca_certs
        )
        statement = statement_path.read_bytes()
        registration_info = {arg.name: arg.value() for arg in registration_info_args}
        signed_statement = crypto.sign_statement(
            signer, statement, content_type, feed, registration_info, cwt=uses_cwt
        )

    print(f"Writing {out_path}")
    out_path.write_bytes(signed_statement)


def cli(fn):
    parser = fn(description="Sign a statement")
    parser.add_argument(
        "--statement", type=Path, required=True, help="Path to statement file"
    )
    parser.add_argument(
        "--key", type=Path, required=False, help="Path to PEM-encoded private key"
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path for signed statement (must end in .cose)",
    )

    # TODO: remove akv configuration is it is not used anymore and is untested
    parser.add_argument(
        "--akv-configuration",
        type=Path,
        help="Path to an Azure key vault configuration file. The configuration is a JSON file containing the following fields: keyVaultName, certificateName, certificateVersion.",
    )

    # Ad-hoc signing, without any on-disk document
    parser.add_argument(
        "--uses-cwt",
        action="store_true",
        help="Put issuer and feed information under CWT header as required in SCITT",
    )
    parser.add_argument("--issuer", help="Issuer stored in envelope header")
    parser.add_argument("--alg", help="Signing algorithm to use.")
    parser.add_argument("--x5c", help="Path to PEM-encoded certificate authority")
    parser.add_argument(
        "--content-type", required=True, help="Content type of statement"
    )
    parser.add_argument("--kid", help='Key ID ("kid" field) to use if multiple')
    parser.add_argument("--feed", help='Optional "feed" stored in envelope header')

    # TODO: remove --registration-info support as this is not part of SCITT anymore
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
        func=lambda args: sign_statement(
            args.statement,
            args.key,
            args.out,
            args.issuer,
            args.content_type,
            args.alg,
            args.kid,
            args.feed,
            args.registration_info,
            args.x5c,
            args.akv_configuration,
            args.uses_cwt,
        )
    )

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
