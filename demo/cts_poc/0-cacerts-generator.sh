#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Simple script to generate test CA certificate and private key files.

set -e

# Variables
: "${CACERT_OUTPUT_DIR:?"variable not set. Please define the output directory where the CA certificate and private key PEM files will be saved to"}"

echo -e "\nSetting up environment"
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi

# Activate environment and install pyscitt local library and test dependencies
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q -r test/requirements.txt

# Create CA certificate and private key
echo -e "\nCreating CA certificate PEM files"
exec python3.8 -m test.infra.generate_cacert --output-dir "$CACERT_OUTPUT_DIR"

echo -e "\nScript completed successfully"
