#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

DOCKER=${DOCKER:-0}
PLATFORM=virtual

wait_for_service() {
    url=$1
    timeout=120
    while ! curl -s -f -k "$url" > /dev/null; do
        echo "Waiting for service to be ready..."
        sleep 1
        timeout=$((timeout - 1))
        if [ $timeout -eq 0 ]; then
            echo "Service failed to become ready, exiting"
            exit 1
        fi
    done
}

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3 -m venv "venv"
fi
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q wheel
pip install --disable-pip-version-check -q -r test/requirements.txt

echo "Running fuzz tests..."
export CCF_HOST=${CCF_HOST:-"localhost"}
export CCF_PORT=${CCF_PORT:-8000}
export CCF_URL="https://${CCF_HOST}:${CCF_PORT}"
echo "Service URL: $CCF_URL"

if [ "$DOCKER" = "1" ]; then
    echo "Will use a running docker instance for testing..."
    
    PLATFORM=$PLATFORM ./docker/run-dev.sh &
    CCF_NETWORK_PID=$!
    trap "kill $CCF_NETWORK_PID" EXIT

    wait_for_service "$CCF_URL/parameters"
else
    echo "Will use a built SCITT binary for testing..."
        
    PLATFORM=$PLATFORM ./start.sh &
    # start script will launch cchost process
    trap 'pkill -f cchost' EXIT

    export CCF_URL="https://localhost:8000"
    wait_for_service "$CCF_URL/node/network"

    scitt governance local_development \
        --url "$CCF_URL" \
        --member-key workspace/member0_privk.pem \
        --member-cert workspace/member0_cert.pem;
    
    wait_for_service "$CCF_URL/parameters"
fi

python -m test.fuzz_api_submissions
