#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Simple script to generate a signed claim to submit to the SCITT ledger, either using a DID document or a x509 CA certificate.

set -e

# Variables
: "${PRIVATE_KEY_PATH:?"variable not set. Please define the path to the private key PEM file"}"
: "${CLAIM_CONTENT_PATH:?"variable not set. Please define the path to the json/txt file to use as content for the claim"}"
: "${COSE_CLAIMS_OUTPUT_PATH:?"variable not set. Please define the path where the COSE claim will be saved to"}"

CLAIM_CONTENT_TYPE=${CLAIM_CONTENT_TYPE:-"application/json"}

# Either provide a DID document, a local x509 certificate, or an AKV configuration file for signing
DID_DOC_PATH=${DID_DOC_PATH:-""}
CACERT_PATH=${CACERT_PATH:-""}
AKV_CONFIG_PATH=${AKV_CONFIG_PATH:-""}

# Validate that either a DID document or the CA certificate or the AKV config is provided
if [ -z "$CACERT_PATH" ] && [ -z "$DID_DOC_PATH" ] && [ -z "$AKV_CONFIG_PATH" ]; then
    echo "Either CACERT_PATH or DID_DOC_PATH or AKV_CONFIG_PATH must be provided"
    exit 1
fi

echo -e "\nSetting up environment"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt

# Create and sign claim with the provided content
echo -e "\nCreating and signing claim"

if [ -n "$DID_DOC_PATH" ]; then
    echo "Using DID document for signing"
    scitt sign \
        --claims "$CLAIM_CONTENT_PATH" \
        --content-type "$CLAIM_CONTENT_TYPE" \
        --key "$PRIVATE_KEY_PATH" \
        --did-doc "$DID_DOC_PATH" \
        --out "$COSE_CLAIMS_OUTPUT_PATH"
elif [ -n "$CACERT_PATH" ]; then
    echo "Using local CA certificate for signing"
    scitt sign \
        --claims "$CLAIM_CONTENT_PATH" \
        --content-type "$CLAIM_CONTENT_TYPE" \
        --key "$PRIVATE_KEY_PATH" \
        --x5c "$CACERT_PATH" \
        --out "$COSE_CLAIMS_OUTPUT_PATH"
elif [ -n "$AKV_CONFIG_PATH" ]; then
    echo "Using AKV configuration for signing"
    scitt sign \
        --claims "$CLAIM_CONTENT_PATH" \
        --content-type "$CLAIM_CONTENT_TYPE" \
        --akv-configuration "$AKV_CONFIG_PATH" \
        --out "$COSE_CLAIMS_OUTPUT_PATH"
else 
    echo "Either CACERT_PATH or DID_DOC_PATH or AKV_CONFIG_PATH must be provided"
    exit 1
fi

echo -e "\nScript completed successfully"
