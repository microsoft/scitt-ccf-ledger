#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

if [ "$1" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null

echo "-- C/C++ format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-format.sh -f app
else
  "$SCRIPT_DIR"/check-format.sh app
fi

echo "-- Python dependencies"
# Virtual Environment w/ dependencies for Python steps
if [ ! -f "scripts/venv/bin/activate" ]
then
  python3.12 -m venv scripts/venv
fi

source scripts/venv/bin/activate
echo "Using pip index URL: ${PIP_INDEX_URL:-default}"
pip install --disable-pip-version-check -q -U black isort mypy wheel
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q -r test/requirements.txt

echo "-- Python types"
mypy -V
git ls-files | grep -e '\.py$' | xargs mypy

echo "-- Python imports"
isort --version
if [ $FIX -ne 0 ]; then
   git ls-files | grep -e '\.py$' | xargs isort
else
   git ls-files | grep -e '\.py$' | xargs isort --check
fi

echo "-- Python format"
black --version
if [ $FIX -ne 0 ]; then
   git ls-files | grep -e '\.py$' | xargs black
else
   git ls-files | grep -e '\.py$' | xargs black --check
fi

echo "-- Copyright notices headers"
python3.12 "$SCRIPT_DIR"/notice-check.py
