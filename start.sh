#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script launches a single CCF node in sandbox mode.
# It is not secure and must not be used in production.

set -ex

PLATFORM=${PLATFORM:-sgx}
CCF_DIR=${CCF_DIR:-/opt/ccf}
# TODO: Don't use /tmp
SCITT_DIR=/tmp/scitt

CONSTITUTION_DIR=$SCITT_DIR/share/scitt/constitution

if [ "$PLATFORM" != "sgx" ] && [ "$PLATFORM" != "virtual" ]; then
    echo "Invalid platform: $PLATFORM"
    exit 1
fi

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi
source venv/bin/activate
pip install --disable-pip-version-check -e ./pyscitt
pip install --disable-pip-version-check -q -r test/requirements.txt

exec python3.8 test/infra/cchost.py \
    --port 8000 \
    --cchost $CCF_DIR/bin/cchost \
    --package $SCITT_DIR/lib/libscitt \
    --constitution-file $CONSTITUTION_DIR/validate.js \
    --constitution-file $CONSTITUTION_DIR/apply.js \
    --constitution-file $CONSTITUTION_DIR/resolve.js \
    --constitution-file $CONSTITUTION_DIR/actions.js \
    --constitution-file $CONSTITUTION_DIR/scitt.js \
    --platform "$PLATFORM" \
    "$@"
