#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

if [ ! -f "venv/bin/activate" ]; then
    echo "Setting up python virtual environment."
    python3.8 -m venv "venv"
    source venv/bin/activate 
    pip install --disable-pip-version-check -q -e ./pyscitt
else
    source venv/bin/activate 
fi

scitt "$@"
