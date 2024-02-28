#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Client script to submit a claim to the SCITT ledger and verify the receipt 

set -e

# Variables
: "${COSE_CLAIMS_PATH:?"variable not set. Please define the path to the COSE claim to register into the ledger"}"
: "${OUTPUT_FOLDER:?"variable not set. Please define the output folder to use to store script artifacts"}"

SCITT_URL=${SCITT_URL:-"https://127.0.0.1:8000"}

# Create output folder
mkdir -p "$OUTPUT_FOLDER"

echo -e "\nSetting up environment"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt

# Get service parameters
echo -e "\nGetting service parameters"
SERVICE_PARAMS_FOLDER="$OUTPUT_FOLDER"/service_params
mkdir -p "$SERVICE_PARAMS_FOLDER"

curl -k -f "$SCITT_URL"/parameters > "$SERVICE_PARAMS_FOLDER"/scitt.json

echo -e "\nSubmitting claim to the ledger and getting receipt for the committed transaction"
RECEIPT_FOLDER="$OUTPUT_FOLDER"/receipts
mkdir -p "$RECEIPT_FOLDER"
RECEIPT_PATH="$RECEIPT_FOLDER"/claims.receipt.cbor

# Submit signed claim
scitt submit "$COSE_CLAIMS_PATH" \
    --receipt "$RECEIPT_PATH" \
    --url "$SCITT_URL" \
    --development

# Get entries with embedded receipts
echo -e "\nGetting all entries with embedded receipts"
scitt retrieve "$RECEIPT_FOLDER" \
    --url "$SCITT_URL" \
    --service-trust-store "$SERVICE_PARAMS_FOLDER" \
    --development

# View receipt
echo -e "\nViewing decoded receipt content"
scitt pretty-receipt "$RECEIPT_PATH"

# Verify receipt
echo -e "\nVerifying receipt"
scitt validate "$COSE_CLAIMS_PATH" \
    --receipt "$RECEIPT_PATH" \
    --service-trust-store "$SERVICE_PARAMS_FOLDER"

echo -e "\nScript completed successfully"
