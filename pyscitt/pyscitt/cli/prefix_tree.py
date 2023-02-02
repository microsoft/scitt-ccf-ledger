# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path
from typing import Optional

from pycose.messages import CoseMessage

from .. import crypto, prefix_tree
from ..client import Client
from ..crypto import COSE_HEADER_PARAM_FEED, COSE_HEADER_PARAM_ISSUER
from ..verify import StaticTrustStore
from .client_arguments import add_client_arguments, create_client


def prefix_tree_flush(client: Client):
    data = client.prefix_tree.flush()
    print(json.dumps(data, indent=2))


def prefix_tree_debug(client: Client):
    data = client.prefix_tree.debug()
    print(json.dumps(data, indent=2))


def prefix_tree_get_receipt(
    client: Client,
    claim_path: Optional[Path],
    issuer: Optional[str],
    feed: Optional[str],
    output: Optional[Path],
    service_trust_store_path: Path,
):
    if claim_path:
        claim = CoseMessage.decode(claim_path.read_bytes())

        issuer = claim.phdr[COSE_HEADER_PARAM_ISSUER]
        feed = claim.phdr[COSE_HEADER_PARAM_FEED]
    elif not issuer or not feed:
        raise ValueError("Either a claim or an issuer and feed must be specified.")

    receipt_data = client.prefix_tree.get_read_receipt(issuer, feed, decode=False)
    if output:
        with open(output, "wb") as f:
            f.write(receipt_data)

    receipt = prefix_tree.ReadReceipt.decode(receipt_data)
    print(json.dumps(receipt.as_dict(), indent=2))

    if claim_path and service_trust_store_path:
        service_trust_store = StaticTrustStore.load(service_trust_store_path)
        service_params = service_trust_store.lookup(receipt.tree_headers)
        receipt.verify(claim, service_params)


def cli(fn):
    parser = fn(description="Manipulate the prefix tree")
    sub = parser.add_subparsers(help="Action to execute", required=True)

    p = sub.add_parser(
        "debug", description="Display an internal representation of the prefix tree"
    )
    add_client_arguments(p)
    p.set_defaults(func=lambda args: prefix_tree_debug(create_client(args)))

    p = sub.add_parser("flush", description="Flush pending entries to the prefix tree")
    add_client_arguments(p)
    p.set_defaults(func=lambda args: prefix_tree_flush(create_client(args)))

    p = sub.add_parser(
        "receipt",
        description="Fetch a read receipt, either by issuer and feed or for an existing claim.",
    )
    add_client_arguments(p)

    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--claim",
        type=Path,
        help="Look up a read-receipt corresponding to the given claim.",
    )
    group.add_argument("--issuer", help="Look up a read-receipt by issuer and feed.")
    p.add_argument("--feed")
    p.add_argument("--output", type=Path, help="Output path to receipt file")
    p.add_argument(
        "--service-trust-store",
        type=Path,
        help="Folder containing JSON parameter files of SCITT services to trust",
    )
    p.set_defaults(
        func=lambda args: prefix_tree_get_receipt(
            create_client(args),
            args.claim,
            args.issuer,
            args.feed,
            args.output,
            args.service_trust_store,
        )
    )
