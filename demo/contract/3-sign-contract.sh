#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

TMP_DIR=tmp/$GITHUB_USER

while getopts ":c:" options; do
    case $options in 
        c)contract=$OPTARG;;
    esac
done

echo "Signing contract $contract..."

CONTENT_TYPE="application/json"

scitt sign-contract \
    --claims $contract \
    --content-type "$CONTENT_TYPE" \
    --did-doc $TMP_DIR/did.json \
    --key $TMP_DIR/key.pem \
    --out $TMP_DIR/contract.cose
