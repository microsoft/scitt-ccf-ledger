#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

TMP_DIR=tmp/github

CONTENT_TYPE="application/json"
echo '{"subject": "abc", "foo": "bar"}' > $TMP_DIR/claims.json

scitt sign \
    --claims $TMP_DIR/claims.json \
    --content-type "$CONTENT_TYPE" \
    --did-doc $TMP_DIR/did.json \
    --key $TMP_DIR/key.pem \
    --out $TMP_DIR/claims.cose
