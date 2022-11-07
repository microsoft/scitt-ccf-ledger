#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

HEADLESS=${HEADLESS:-1}
CCF_URL=${CCF_URL:-"https://127.0.0.1:8000"}
NUM_USERS=${NUM_USERS:-100}
SPAWN_RATE=${SPAWN_RATE:-10} # per second

if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi
source venv/bin/activate
pip install --disable-pip-version-check -q -r test/requirements.txt
export PYTHONPATH="test/"

if [ "$HEADLESS" -eq 1 ]; then
    echo "Running in headless mode"
    args="--headless -t 15"
else
    echo "Running in interactive mode"
    args="--autostart"
fi

locust -f test/load_test/locustfile.py \
    -H "$CCF_URL" -u "$NUM_USERS" -r "$SPAWN_RATE" $args
