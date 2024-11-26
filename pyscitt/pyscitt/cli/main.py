# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse

from . import (
    embed_receipt_in_cose,
    governance,
    pretty_receipt,
    register,
    retrieve_signed_claims,
    sign,
    split_payload,
    upload_did_web_doc_to_github,
    validate_cose,
)

COMMANDS = [
    ("upload-did-web-github", upload_did_web_doc_to_github),
    ("sign", sign),
    ("submit", register),
    ("retrieve", retrieve_signed_claims),
    ("split-payload", split_payload),
    ("pretty-receipt", pretty_receipt),
    ("embed-receipt", embed_receipt_in_cose),
    ("validate", validate_cose),
    ("governance", governance),
]


def main(argv=None):
    parser = argparse.ArgumentParser()
    # Hide commands used for testing through metavar
    # https://github.com/python/cpython/issues/67037
    # https://docs.python.org/3/library/argparse.html#sub-commands
    sub = parser.add_subparsers(
        metavar="{submit,retrieve,pretty-receipt,embed-receipt,validate,split-payload}",
        help="""Choose one of the available commands to run. 
                                Use the --help flag to see the options for each command.
                                For instance 'scitt submit --help' will show the options for the submit command.
                                """,
    )
    for name, module in COMMANDS:
        getattr(module, "cli")(lambda *args, **kw: sub.add_parser(name, *args, **kw))
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_usage()
    else:
        args.func(args)


if __name__ == "__main__":
    main()
