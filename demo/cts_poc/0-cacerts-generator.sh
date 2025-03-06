#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Simple script to generate test CA certificate and private key files.

set -euo pipefail

# Variables
: "${CACERT_OUTPUT_DIR:?"variable not set. Please define the output directory where the CA certificate and private key PEM files will be saved to"}"

CURRENT_DIR=$(dirname "$0")
CUSTOM_EKU="1.3.6.1.5.5.7.3.36"

echo -e "\nSetting up environment"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library and test dependencies
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q -r test/requirements.txt

echo -e "\nCreating CA certificate and key";
python3 -m test.infra.generate_cacert --output-dir "$CACERT_OUTPUT_DIR" --eku "$CUSTOM_EKU";

echo -e "\nCreating instance configuration file";
cp "$CURRENT_DIR/configuration.tmpl.json" "$CACERT_OUTPUT_DIR/configuration.json";

echo -e "Extracting root CA fingerprint";
# find Root CA cert first
awk -v outdir="$CACERT_OUTPUT_DIR" 'BEGIN {c=0} /-----BEGIN CERTIFICATE-----/ {c++} {print > outdir "/chain-cert-" c ".pem"}' "$CACERT_OUTPUT_DIR/cacert.pem"
LAST_CERT_FILE=$(ls $CACERT_OUTPUT_DIR/chain-cert-*.pem | sort -V | tail -n 1)
ROOT_CA_FINGERPRINT_SHA256=$(openssl x509 -in "$LAST_CERT_FILE" -noout -fingerprint -sha256 | sed 's/SHA256 Fingerprint=//g' | sed 's/://g')
echo -e "SHA256 fingerprint: $ROOT_CA_FINGERPRINT_SHA256";

echo -e "Converting fingerprint to url safe base64";
ROOT_CA_FINGERPRINT_BIN_B64=$(python3 -c "import base64; print(base64.urlsafe_b64encode(bytes.fromhex('$ROOT_CA_FINGERPRINT_SHA256')).decode('ascii').strip('='))")
echo -e "Base64 fingerprint: $ROOT_CA_FINGERPRINT_BIN_B64";

echo -e "Updating configuration policy with root CA fingerprint";
sed -i "s/<<ROOT_CA_B64_FINGERPRINT>>/$ROOT_CA_FINGERPRINT_BIN_B64/g" "$CACERT_OUTPUT_DIR/configuration.json"

echo -e "Updating configuration policy with the EKU";
sed -i "s/<<LEAF_EKU>>/$CUSTOM_EKU/g" "$CACERT_OUTPUT_DIR/configuration.json"

echo -e "Writing did:x509 issuer string to file for later use";
echo -n "did:x509:0:sha256:$ROOT_CA_FINGERPRINT_BIN_B64::eku:$CUSTOM_EKU" > "$CACERT_OUTPUT_DIR/issuer.txt"

echo -e "\nScript completed successfully"
