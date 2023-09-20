#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

TRUST_STORE=tmp/trust_store

TMP_DIR=tmp/$TDP_USERNAME

scitt validate-contract $TMP_DIR/contract.cose \
    --receipt $TMP_DIR/contract.receipt.cbor \
    --service-trust-store $TRUST_STORE
