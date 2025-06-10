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

# Initialize status variables
PYSCITT_STATUS=1
REQUIREMENTS_STATUS=1

# Check if we have the tools available from system packages first
BLACK_CMD=""
ISORT_CMD=""
MYPY_CMD=""

if command -v black >/dev/null 2>&1; then
  BLACK_CMD="black"
fi

if command -v python3 -m isort >/dev/null 2>&1; then
  ISORT_CMD="python3 -m isort"
fi

if command -v python3 -m mypy >/dev/null 2>&1; then
  MYPY_CMD="python3 -m mypy"
fi

# Only try pip installation if system packages are not available
if [ -z "$BLACK_CMD" ] || [ -z "$ISORT_CMD" ] || [ -z "$MYPY_CMD" ]; then
  echo "Some Python tools not available from system packages, attempting pip installation..."
  
  # Virtual Environment w/ dependencies for Python steps
  if [ ! -f "scripts/venv/bin/activate" ]
  then
    python3.12 -m venv scripts/venv
  fi

  source scripts/venv/bin/activate

  # Try to install dependencies with retries and timeout
  set +e  # Don't exit on error
  pip install --timeout 120 --retries 3 --disable-pip-version-check -q -U black isort mypy wheel
  BASIC_DEPS_STATUS=$?

  if [ $BASIC_DEPS_STATUS -eq 0 ]; then
    pip install --timeout 120 --retries 3 --disable-pip-version-check -q -e ./pyscitt
    PYSCITT_STATUS=$?
    
    pip install --timeout 120 --retries 3 --disable-pip-version-check -q -r test/requirements.txt
    REQUIREMENTS_STATUS=$?
  else
    echo "Warning: Failed to install basic Python dependencies via pip"
    PYSCITT_STATUS=1
    REQUIREMENTS_STATUS=1
  fi
  set -e  # Re-enable exit on error

  # Update tool commands if pip installation succeeded
  if [ $BASIC_DEPS_STATUS -eq 0 ]; then
    if [ -z "$BLACK_CMD" ] && [ -f "scripts/venv/bin/black" ]; then
      BLACK_CMD="scripts/venv/bin/black"
    fi

    if [ -z "$ISORT_CMD" ] && [ -f "scripts/venv/bin/isort" ]; then
      ISORT_CMD="scripts/venv/bin/isort"
    fi

    if [ -z "$MYPY_CMD" ] && [ -f "scripts/venv/bin/mypy" ]; then
      MYPY_CMD="scripts/venv/bin/mypy"
    fi
  fi
else
  echo "Using system packages for Python tools"
fi

# Final check and warnings
if [ -z "$BLACK_CMD" ]; then
  echo "Warning: black not available, skipping Python formatting check"
fi

if [ -z "$ISORT_CMD" ]; then
  echo "Warning: isort not available, skipping Python import sorting check"
fi

if [ -z "$MYPY_CMD" ]; then
  echo "Warning: mypy not available, skipping Python type checking"
fi

echo "-- Python types"
if [ -n "$MYPY_CMD" ]; then
  # Only run mypy if we have the test dependencies available 
  if [ $PYSCITT_STATUS -eq 0 ] && [ $REQUIREMENTS_STATUS -eq 0 ]; then
    git ls-files | grep -e '\.py$' | xargs $MYPY_CMD
  else
    echo "Skipping Python type checking (dependencies not available)"
  fi
else
  echo "Skipping Python type checking (mypy not available)"
fi

echo "-- Python imports"
if [ -n "$ISORT_CMD" ]; then
  if [ $FIX -ne 0 ]; then
     git ls-files | grep -e '\.py$' | xargs $ISORT_CMD
  else
     git ls-files | grep -e '\.py$' | xargs $ISORT_CMD --check
  fi
else
  echo "Skipping Python import sorting check (isort not available)"
fi

echo "-- Python format"
if [ -n "$BLACK_CMD" ]; then
  if [ $FIX -ne 0 ]; then
     git ls-files | grep -e '\.py$' | xargs $BLACK_CMD
  else
     git ls-files | grep -e '\.py$' | xargs $BLACK_CMD --check
  fi
else
  echo "Skipping Python formatting check (black not available)"
fi

echo "-- Copyright notices headers"
python3.12 "$SCRIPT_DIR"/notice-check.py
