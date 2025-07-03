# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
from pathlib import Path
from typing import List, Optional

from .. import crypto


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
    x5c_path: Optional[str],
    uses_cwt: bool = False,
):
    if not x5c_path:
        raise ValueError("The --x5c flag must be provided")
    ca_certs = _parse_x5c_file(x5c_path)

    key = crypto.load_private_key(key_path)
    signer = crypto.Signer(
        key, kid=kid, issuer=issuer, algorithm=algorithm, x5c=ca_certs
    )
    statement = statement_path.read_bytes()
    signed_statement = crypto.sign_statement(
        signer, statement, content_type, feed, cwt=uses_cwt
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
            args.x5c,
            args.uses_cwt,
        )
    )

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
