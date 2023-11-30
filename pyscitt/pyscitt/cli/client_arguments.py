# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
from pathlib import Path

from pyscitt.key_vault_sign_client import KeyVaultSignClient
from pyscitt.local_key_sign_client import LocalKeySignClient

from ..client import Client

CCF_URL_DEFAULT = "https://127.0.0.1:8000"
CCF_SANDBOX_WORKSPACE = Path("workspace")
CCF_MEMBER_KEY_DEFAULT = CCF_SANDBOX_WORKSPACE / "member0_privk.pem"
CCF_MEMBER_CERT_DEFAULT = CCF_SANDBOX_WORKSPACE / "member0_cert.pem"


def add_client_arguments(
    parser: argparse.ArgumentParser,
    *,
    with_member_auth: bool = False,
    with_auth_token: bool = False,
    development_only: bool = False,
):
    """
    Add command-line arguments to an argparse parser, such that a client instance can be configured.

    with_member_auth:
        If True, required flag arguments for a member certificate and private key will be added
        to the parser.

    with_auth_token:
        If True, an optional flag argument allowing a bearer token to be specified will be added
        to the parser.

    development_only:
        If True, the server's TLS certificate is never verified, and no --development flag is added
        to the parser.
    """

    parser.add_argument("--url", help="CCF service URL", default=CCF_URL_DEFAULT)
    parser.add_argument(
        "--cacert",
        help="Path to certificate file (must be in PEM format) to verify the CCF service",
        default=None,
    )
    if development_only:
        # We always add a hidden --development flag that defaults to True.
        # This helps provide a uniform interface for scripts and tests.
        parser.add_argument(
            "-k",
            "--development",
            action="store_true",
            help=argparse.SUPPRESS,
            default=True,
        )
    else:
        parser.add_argument(
            "-k",
            "--development",
            action="store_true",
            help="Do not verify the self-signed network certificate",
        )

    if with_member_auth:
        parser.add_argument(
            "--member-key",
            default=CCF_MEMBER_KEY_DEFAULT,
            type=Path,
            help="Path to CCF member key file",
        )
        parser.add_argument(
            "--member-cert",
            default=CCF_MEMBER_CERT_DEFAULT,
            type=Path,
            help="Path to CCF member certificate file",
        )
        parser.add_argument(
            "--akv-configuration",
            type=Path,
            help="Path to CCF member Azure key vault configuration file",
        )

    if with_auth_token:
        parser.add_argument("--auth-token", help="JWT bearer token")


def create_client(args: argparse.Namespace):
    """
    Create a client instance from the result of parsing command-line arguments.

    This assumes the argument parser was configured with the `add_client_arguments` function.
    """
    kwargs = {
        "url": args.url,
        "cacert": args.cacert,
        "development": args.development,
    }

    if "akv_configuration" in args and args.akv_configuration:
        akv_configuration = args.akv_configuration.read_text()
        akv_sign_configuration_dict = json.loads(akv_configuration)
        kwargs["member_auth"] = KeyVaultSignClient(akv_sign_configuration_dict)
    elif "member_cert" in args:
        cert = args.member_cert.read_text()
        key = args.member_key.read_text()
        kwargs["member_auth"] = LocalKeySignClient(cert, key)

    if "auth_token" in args:
        kwargs["auth_token"] = args.auth_token

    return Client(**kwargs)
