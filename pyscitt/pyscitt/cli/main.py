# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse

from . import (
    create_did_web,
    embed_receipt_in_cose,
    governance,
    pretty_receipt,
    retrieve_signed_claims,
    sign_claims,
    submit_signed_claims,
    upload_did_web_doc_to_github,
    validate_cose,
)

COMMANDS = [
    ("create-did-web", create_did_web),
    ("upload-did-web-github", upload_did_web_doc_to_github),
    ("sign", sign_claims),
    ("submit", submit_signed_claims),
    ("retrieve", retrieve_signed_claims),
    ("pretty-receipt", pretty_receipt),
    ("embed-receipt", embed_receipt_in_cose),
    ("validate", validate_cose),
    ("governance", governance),
]


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    for name, module in COMMANDS:
        getattr(module, "cli")(lambda *args, **kw: sub.add_parser(name, *args, **kw))
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_usage()
    else:
        args.func(args)


if __name__ == "__main__":
    main()
