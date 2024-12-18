# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
from pathlib import Path
from typing import Optional

from ..client import Client
from ..verify import StaticTrustStore, verify_transparent_statement
from .client_arguments import add_client_arguments, create_client


def retrieve_signed_claimsets(
    client: Client,
    base_path: Path,
    from_seqno: Optional[int],
    to_seqno: Optional[int],
    service_trust_store_path: Optional[Path],
):
    base_path.mkdir(parents=True, exist_ok=True)

    if service_trust_store_path:
        service_trust_store = StaticTrustStore.load(service_trust_store_path)
    else:
        service_trust_store = None

    for tx in client.enumerate_statements(start=from_seqno, end=to_seqno):
        claim = client.get_claim(tx)
        path = base_path / f"{tx}.cose"

        if service_trust_store:
            verify_transparent_statement(claim, service_trust_store, claim)

        with open(path, "wb") as f:
            f.write(claim)


def cli(fn):
    parser = fn(
        description="Retrieve signed claimsets from a SCITT CCF Ledger together with receipts"
    )
    add_client_arguments(parser)
    parser.add_argument(
        "path", type=Path, help="Folder to store signed claimsets and receipts"
    )
    parser.add_argument(
        "--from", dest="from_seqno", type=int, help="Start seqno (optional)"
    )
    parser.add_argument("--to", dest="to_seqno", type=int, help="End seqno (optional)")
    parser.add_argument(
        "--service-trust-store",
        type=Path,
        help="Folder containing JSON parameter files of SCITT services to trust",
    )
    parser.add_argument(
        "--embed-receipt",
        action="store_true",
        default=False,
        help="Whether to include the receipt in the signed claimset under the unprotected header. Default is False.",
    )

    def cmd(args):
        client = create_client(args)
        retrieve_signed_claimsets(
            client,
            args.path,
            args.from_seqno,
            args.to_seqno,
            args.service_trust_store,
        )

    parser.set_defaults(func=cmd)
    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
