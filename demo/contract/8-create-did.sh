#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

: ${GITHUB_USER1:?"variable not set! Please run 'export GITHUB_USER=<YOUR USERNAME>'"}

TMP_DIR=tmp/$GITHUB_USER1
rm -rf $TMP_DIR
mkdir -p $TMP_DIR
scitt create-did-web --url https://$GITHUB_USER1.github.io --out-dir $TMP_DIR
scitt upload-did-web-github $TMP_DIR/did.json

