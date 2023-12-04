#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Simple script to generate a signed claim to submit to the SCITT ledger

set -e

# Variables
: "${CACERT_PATH:?"variable not set. Please define the path to the CA certificate PEM file"}"
: "${PRIVATE_KEY_PATH:?"variable not set. Please define the path to the private key PEM file"}"
: "${CLAIM_CONTENT_PATH:?"variable not set. Please define the path to the json/txt file to use as content for the claim"}"
: "${COSE_CLAIMS_OUTPUT_PATH:?"variable not set. Please define the path where the COSE claim will be saved to"}"

CLAIM_CONTENT_TYPE=${CLAIM_CONTENT_TYPE:-"application/json"}

echo -e "\nSetting up environment"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt

# Create and sign claim with the provided content
echo -e "\nCreating and signing claim"
scitt sign \
    --claims "$CLAIM_CONTENT_PATH" \
    --content-type "$CLAIM_CONTENT_TYPE" \
    --key "$PRIVATE_KEY_PATH" \
    --x5c "$CACERT_PATH" \
    --out "$COSE_CLAIMS_OUTPUT_PATH"

echo -e "\nScript completed successfully"
