#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

: ${TDP_USERNAME:?"variable not set! Please run 'export TDP_USERNAME=<YOUR USERNAME>'"}

TMP_DIR=tmp/$TDP_USERNAME
rm -rf $TMP_DIR
mkdir -p $TMP_DIR
scitt create-did-web --url https://$TDP_USERNAME.github.io --out-dir $TMP_DIR
scitt upload-did-web-github $TMP_DIR/did.json
