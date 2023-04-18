#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

TMP_DIR1=tmp/$GITHUB_USER1

echo "Signing contract..."

CONTENT_TYPE="application/cose"

scitt sign-contract \
    --contract tmp/contracts/2.$1.cose \
    --content-type "$CONTENT_TYPE" \
    --did-doc $TMP_DIR1/did.json \
    --key $TMP_DIR1/key.pem \
    --out $TMP_DIR1/contract.cose \
    --add-signature 
