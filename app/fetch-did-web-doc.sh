#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This is a thin wrapper around the fetch-did-web-doc.py script, intended to
# redirect the script's output to a file. Once CCF logs output from
# subprocesses this file won't be necessary anymore.

set -x

exec >  >(tee -i /tmp/scitt-fetch-did-web-doc.log)
exec 2>&1

AFETCH_DIR="/tmp/scitt"

exec python3 "${AFETCH_DIR}/fetch-did-web-doc.py" "$@"
