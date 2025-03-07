# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from loguru import logger

from .x5chain_certificate_authority import X5ChainCertificateAuthority


def generate_ca_cert_and_key(
    output_dir: str,
    alg: str,
    key_type: str,
    ec_curve: str,
    key_filename: str = "cacert_privk.pem",
    cacert_filename: str = "cacert.pem",
    eku: str = "",
):
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Create a new X5ChainCertificateAuthority instance
    cert_authority = X5ChainCertificateAuthority(kty=key_type)

    # Create a new identity with the input parameters
    if eku:
        identity = cert_authority.create_identity(
            alg=alg, kty=key_type, ec_curve=ec_curve, add_eku=eku
        )
    else:
        identity = cert_authority.create_identity(
            alg=alg, kty=key_type, ec_curve=ec_curve
        )

    # Write the private key to a file
    output_key_file = f"{output_dir}/{key_filename}"
    logger.info(f"Writing private key to {output_key_file}")
    with open(output_key_file, "w") as f:
        f.write(identity.private_key)

    # Write the ca cert to a file
    cert_bundle = b""

    if not identity.x5c:
        raise ValueError("No x5c field in identity")

    for cert in identity.x5c:
        pemcert = x509.load_pem_x509_certificate(cert.encode())
        cert_bundle += pemcert.public_bytes(serialization.Encoding.PEM)

    output_cacert_file = f"{output_dir}/{cacert_filename}"
    logger.info(f"Writing cacert to {output_cacert_file}")
    with open(output_cacert_file, "wb") as f:
        f.write(cert_bundle)


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Generate a sample pair of CA cert and associated private key."
    )
    parser.add_argument(
        "--output-dir", type=str, help="The directory to output the generated files to."
    )
    parser.add_argument(
        "--alg",
        type=str,
        help="The algorithm to use to generate the certificate chain.",
        default="ES256",
    )
    parser.add_argument(
        "--key-type",
        type=str,
        help="The key type to use to generate the certificate chain",
        default="ec",
    )
    parser.add_argument(
        "--ec-curve",
        type=str,
        help="The Elliptic Curve to use for the key.",
        default="P-256",
    )
    parser.add_argument(
        "--eku",
        type=str,
        help="Extended Key Usage to add to the end entity certificate, e.g. '1.3.6.1.5.5.7.3.36'",
    )
    args = parser.parse_args()

    # Generate the CA cert and key
    generate_ca_cert_and_key(
        args.output_dir, args.alg, args.key_type, args.ec_curve, eku=args.eku
    )
