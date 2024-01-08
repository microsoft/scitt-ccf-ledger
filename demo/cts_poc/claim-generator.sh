#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Simple, generic script to generate a signed claim to submit to the SCITT ledger using various methods.

set -e

# Variables
: "${CLAIM_CONTENT_PATH:?"variable not set. Please define the path to the json/txt file to use as content for the claim"}"
: "${COSE_CLAIMS_OUTPUT_PATH:?"variable not set. Please define the path where the COSE claim will be saved to"}"
: "${SIGNING_METHOD:?"variable not set. Please define the signing method to use. Options are: did, cacert, akv"}"

# Optional variable to set the content type of the claim
CLAIM_CONTENT_TYPE=${CLAIM_CONTENT_TYPE:-"application/json"}

# Optional variables to provide a DID document, a x509 PEM certificate, a private key, and an AKV configuration file for signing
PRIVATE_KEY_PATH=${PRIVATE_KEY_PATH:-""}
DID_DOC_PATH=${DID_DOC_PATH:-""}
CACERT_PATH=${CACERT_PATH:-""}
AKV_CONFIG_PATH=${AKV_CONFIG_PATH:-""}

echo -e "\nSetting up environment"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt

# Create and sign claim with the provided content
echo -e "\nCreating and signing claim"

if [ "$SIGNING_METHOD" = "did" ]; then
    echo "Using DID document for signing"
    scitt sign \
        --claims "$CLAIM_CONTENT_PATH" \
        --content-type "$CLAIM_CONTENT_TYPE" \
        --key "$PRIVATE_KEY_PATH" \
        --did-doc "$DID_DOC_PATH" \
        --out "$COSE_CLAIMS_OUTPUT_PATH"
elif [ "$SIGNING_METHOD" = "cacert" ]; then
    echo "Using local CA certificate for signing"
    scitt sign \
        --claims "$CLAIM_CONTENT_PATH" \
        --content-type "$CLAIM_CONTENT_TYPE" \
        --key "$PRIVATE_KEY_PATH" \
        --x5c "$CACERT_PATH" \
        --out "$COSE_CLAIMS_OUTPUT_PATH"
elif [ "$SIGNING_METHOD" = "akv" ]; then
    echo "Using AKV configuration for signing"
    scitt sign \
        --claims "$CLAIM_CONTENT_PATH" \
        --content-type "$CLAIM_CONTENT_TYPE" \
        --akv-configuration "$AKV_CONFIG_PATH" \
        --x5c "$CACERT_PATH" \
        --out "$COSE_CLAIMS_OUTPUT_PATH"
else 
    echo "No valid signing method provided. Supported options are: did, cacert, akv"
    exit 1
fi

echo -e "\nScript completed successfully"
