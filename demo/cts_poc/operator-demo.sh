#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Script to setup and configure a SCITT CCF instance with custom parameters

set -e

# Variables
: "${MEMBER_CERT_PATH:?"variable not set. Please define the path to the CCF member certificate PEM file"}"
: "${MEMBER_KEY_PATH:?"variable not set. Please define the path to the CCF member key PEM file"}"
: "${CACERT_PATH:?"variable not set. Please define the path to the CA certificate PEM file"}"
: "${SCITT_CONFIG_PATH:?"variable not set. Please define the path to SCITT configuration JSON file"}"

SCITT_URL=${SCITT_URL:-"https://127.0.0.1:8000"}

echo -e "\nInstalling pyscitt CLI"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt

echo -e "\nActivating member"

# Send Proposal to activate member
scitt governance activate_member \
    --url "$SCITT_URL" \
    --member-key "$MEMBER_KEY_PATH" \
    --member-cert "$MEMBER_CERT_PATH" \
    --development

echo -e "\nConfiguring CCF instance"

# Send proposal to set CA certs
scitt governance propose_ca_certs \
    --name x509_roots \
    --ca-certs "$CACERT_PATH" \
    --url "$SCITT_URL" \
    --member-key "$MEMBER_KEY_PATH" \
    --member-cert "$MEMBER_CERT_PATH" \
    --development

# Send proposal to set SCITT configuration 
scitt governance propose_configuration \
    --configuration "$SCITT_CONFIG_PATH" \
    --url "$SCITT_URL" \
    --member-key "$MEMBER_KEY_PATH" \
    --member-cert "$MEMBER_CERT_PATH" \
    --development

echo -e "\Opening the network"

# Get current service certificate
SERVICE_CERT_PATH="service_cert.pem"
curl -k "$SCITT_URL"/node/network | jq -r .service_certificate | head -n -1 > "$SERVICE_CERT_PATH"

# Send the proposal to open the network 
scitt governance propose_open_service \
    --url "$SCITT_URL" \
    --member-key "$MEMBER_KEY_PATH" \
    --member-cert "$MEMBER_CERT_PATH" \
    --next-service-certificate "$SERVICE_CERT_PATH" \
    --development

# Remove the service certificate file
rm "$SERVICE_CERT_PATH"

echo -e "\nScript completed successfully"
