#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

SCITT_TRUST_STORE=tmp/trust_store

TMP_DIR=tmp/github

scitt validate $TMP_DIR/claims.cose \
    --receipt $TMP_DIR/claims.receipt.cbor \
    --service-trust-store $SCITT_TRUST_STORE
