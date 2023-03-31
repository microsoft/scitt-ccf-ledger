#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

SCITT_TRUST_STORE=tmp/trust_store

TMP_DIR=tmp/$GITHUB_USER

scitt validate $TMP_DIR/contract.cose \
    --receipt $TMP_DIR/contract.receipt.cbor \
    --service-trust-store $SCITT_TRUST_STORE
