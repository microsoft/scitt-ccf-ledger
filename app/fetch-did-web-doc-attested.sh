#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -x

# This script invokes attested-fetch, and, if successful, POSTs the response
# back to the CCF app. The callback URL to the CCF app is given as a command
# line argument.

# TODO remove this again once CCF logs output from subprocesses
exec >  >(tee -i /tmp/scitt-fetch-did-web-doc-attested.log)
exec 2>&1

AFETCH_DIR="/tmp/scitt"
url=$1
nonce=$2
callback_url=$3

exec python3 "${AFETCH_DIR}/fetch-did-web-doc.py" \
    "${url}" "${nonce}" "${callback_url}"
