#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script launches a single CCF node in sandbox mode.
# It is not secure and must not be used in production.

set -ex

PLATFORM=${PLATFORM:-snp}
CCF_DIR=${CCF_DIR:-/opt/ccf_$PLATFORM}
# TODO: Don't use /tmp
SCITT_DIR=/tmp/scitt

CONSTITUTION_DIR=$SCITT_DIR/share/scitt/constitution

# SNP attestation config
SNP_ATTESTATION_CONFIG=${SNP_ATTESTATION_CONFIG:-}

if [ "$PLATFORM" != "virtual" ] && [ "$PLATFORM" != "snp" ]; then
    echo "Invalid platform: $PLATFORM"
    exit 1
fi

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.12 -m venv "venv"
fi
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q wheel
pip install --disable-pip-version-check -q -r test/requirements.txt

exec python3.12 -m test.infra.cchost \
    --port 8000 \
    --cchost $CCF_DIR/bin/cchost \
    --package $SCITT_DIR/lib/libscitt \
    --constitution-file $CONSTITUTION_DIR/validate.js \
    --constitution-file $CONSTITUTION_DIR/apply.js \
    --constitution-file $CONSTITUTION_DIR/resolve.js \
    --constitution-file $CONSTITUTION_DIR/actions.js \
    --constitution-file $CONSTITUTION_DIR/scitt.js \
    --platform "$PLATFORM" \
    --snp-attestation-config "$SNP_ATTESTATION_CONFIG" \
    "$@"
