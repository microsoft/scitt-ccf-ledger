#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Optional offline check of CCF receipts with proofbundle.scitt_ccf.
#
# Usage: scripts/proofbundle-check.sh [CAPTURE_DIR]
#
# Checks the receipt vectors in test/proofbundle_check/vectors and, if
# CAPTURE_DIR is given, the receipts that the functional tests produced while
# run_functional_tests.sh ran with PROOFBUNDLE_CHECK=1. Uses a virtual
# environment of its own, so the functional test environment is not changed.
# Off unless called; PROOFBUNDLE_CHECK=0 makes it a no-op.

set -e

if [ "${PROOFBUNDLE_CHECK:-1}" = "0" ]; then
    echo "proofbundle check disabled (PROOFBUNDLE_CHECK=0)"
    exit 0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
CHECK_DIR="$ROOT_DIR/test/proofbundle_check"
VENV=${PROOFBUNDLE_VENV:-"$ROOT_DIR/venv-proofbundle"}

if command -v python3.12 &> /dev/null; then
    PYTHON=python3.12
else
    PYTHON=python3
fi

if [ ! -f "$VENV/bin/activate" ]; then
    $PYTHON -m venv "$VENV"
fi
"$VENV/bin/pip" install --disable-pip-version-check -q -r "$CHECK_DIR/requirements.txt"

ARGS=()
if [ -n "$1" ]; then
    ARGS+=(--captures "$1" --require-captures)
fi

"$VENV/bin/python" -I "$CHECK_DIR/check.py" "${ARGS[@]}"
