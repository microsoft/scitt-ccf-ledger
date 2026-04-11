#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script launches a single CCF node in sandbox mode.
# It is not secure and must not be used in production.

set -ex

# TODO: Don't use /tmp
SCITT_DIR=/tmp/scitt

CONSTITUTION_DIR=$SCITT_DIR/share/scitt/constitution

# SNP attestation config
SNP_ATTESTATION_CONFIG=${SNP_ATTESTATION_CONFIG:-}

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.12 -m venv "venv"
fi
source venv/bin/activate
echo "Using pip index URL: ${PIP_INDEX_URL:-default}"
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q wheel
pip install --disable-pip-version-check -q -r test/requirements.txt

SNP_ARGS=()
if [ -n "$SNP_ATTESTATION_CONFIG" ]; then
    SNP_ARGS=(--snp-attestation-config "$SNP_ATTESTATION_CONFIG")
fi

exec python3.12 -m test.infra.cchost \
    --port 8000 \
    --cchost $SCITT_DIR/bin/cchost \
    --constitution-file $CONSTITUTION_DIR/validate.js \
    --constitution-file $CONSTITUTION_DIR/apply.js \
    --constitution-file $CONSTITUTION_DIR/resolve.js \
    --constitution-file $CONSTITUTION_DIR/actions.js \
    --constitution-file $CONSTITUTION_DIR/scitt.js \
    "${SNP_ARGS[@]}" \
    "$@"
