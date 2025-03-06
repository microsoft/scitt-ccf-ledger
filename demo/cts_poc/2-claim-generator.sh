#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Generic script to generate a signed claim to submit to the SCITT ledger.

set -euo pipefail

# Variables
: "${CLAIM_CONTENT_PATH:?"variable not set. Please define the path to the json/txt file to use as content for the claim"}"
: "${COSE_CLAIMS_OUTPUT_PATH:?"variable not set. Please define the path where the COSE claim will be saved to"}"
: "${DID_X509_ISSUER:?"variable not set. Please define the issuer to use for the claim which will be under CWT header"}"
: "${PRIVATE_KEY_PATH:?"variable not set. Please define the path to the private key to use for signing the claim"}"
: "${CACERT_PATH:?"variable not set. Please define the path to the CA certificate chain to include as x509 header"}"

CLAIM_CONTENT_TYPE=${CLAIM_CONTENT_TYPE:-"application/json"}

if [[ ! "$DID_X509_ISSUER" =~ ^did:x509:.* ]]; then
    echo "Issuer must start with did:x509"
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

scitt sign \
    --statement "$CLAIM_CONTENT_PATH" \
    --content-type "$CLAIM_CONTENT_TYPE" \
    --key "$PRIVATE_KEY_PATH" \
    --x5c "$CACERT_PATH" \
    --issuer "$DID_X509_ISSUER" \
    --out "$COSE_CLAIMS_OUTPUT_PATH" \
    --uses-cwt

echo -e "\nScript completed successfully"
