#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CONTRACT_URL=${CONTRACT_URL:-"https://127.0.0.1:8000"}
TRUST_STORE=tmp/trust_store

TMP_DIR=tmp/$TDP_USERNAME

scitt retrieve-contracts ./tmp/contracts \
    --url $CONTRACT_URL \
    --service-trust-store $TRUST_STORE \
    --from $1 \
    --to $1
    --development
