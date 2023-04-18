# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
from pathlib import Path
from typing import Optional

from ..verify import StaticTrustStore, verify_contract_receipt


def validate_cose_with_receipt(
    cose_path: Path, receipt_path: Optional[Path], service_trust_store_path: Path
):
    service_trust_store = StaticTrustStore.load(service_trust_store_path)

    cose = cose_path.read_bytes()

    if receipt_path is None:
        receipt = None
    else:
        receipt = receipt_path.read_bytes()

    verify_contract_receipt(cose, service_trust_store, receipt)
    print(f"COSE document is valid: {cose_path}")


def cli(fn):
    parser = fn(description="Validate a COSE_Sign document using a receipt")
    parser.add_argument("cose", type=Path, help="Path to COSE file")
    parser.add_argument(
        "--receipt",
        type=Path,
        help="Optional path to receipt, otherwise read from COSE headers",
    )
    parser.add_argument(
        "--service-trust-store",
        required=True,
        type=Path,
        help="Folder containing JSON parameter files of SCITT services to trust",
    )

    def cmd(args):
        validate_cose_with_receipt(args.cose, args.receipt, args.service_trust_store)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
