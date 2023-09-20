#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

: ${TDC_USERNAME:?"variable not set! Please run 'export GITHUB_USER=<YOUR USERNAME>'"}

TMP_DIR=tmp/$TDC_USERNAME
rm -rf $TMP_DIR
mkdir -p $TMP_DIR
scitt create-did-web --url https://$TDC_USERNAME.github.io --out-dir $TMP_DIR
scitt upload-did-web-github $TMP_DIR/did.json

