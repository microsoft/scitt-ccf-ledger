#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

TMP_DIR=tmp/$GITHUB_USER

echo "Signing contract..."

CONTENT_TYPE="application/json"

scitt sign-contract \
    --contract ./demo/contract/contract.json \
    --content-type "$CONTENT_TYPE" \
    --did-doc $TMP_DIR/did.json \
    --key $TMP_DIR/key.pem \
    --feed "covid-modeling" \
    --participant-info "did:web:kapilvgit.github.io" \
    --participant-info "did:web:kapilv78.github.io" \
    --out $TMP_DIR/contract.cose
