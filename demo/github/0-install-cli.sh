#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex 

echo "Installing pyscitt CLI into virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi
source venv/bin/activate 
pip install --disable-pip-version-check -q -e ./pyscitt