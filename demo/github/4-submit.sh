#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

SCITT_URL=${SCITT_URL:-"https://127.0.0.1:8000"}
SCITT_TRUST_STORE=tmp/trust_store

TMP_DIR=tmp/github

scitt submit $TMP_DIR/claims.cose \
    --receipt $TMP_DIR/claims.receipt.cbor \
    --url "$SCITT_URL" \
    --service-trust-store $SCITT_TRUST_STORE \
    --development
