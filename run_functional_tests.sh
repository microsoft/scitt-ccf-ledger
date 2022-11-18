#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

DOCKER=${DOCKER:-0}
ENCLAVE_TYPE=${ENCLAVE_TYPE:-release}

# If ELEVATE_PRIVILEGES is non-empty, the functional tests will be run with
# the NET_BIND_SERVICE capability, allowing certain tests that bind
# priviledged ports to run. Note that this isn't necessary in our CI
# environment, as Docker makes all ports unpriviledged anyway. Requires sudo
# access and libcap2-bin to be installed.
ELEVATE_PRIVILEGES=${ELEVATE_PRIVILEGES:-}

if [ "$DOCKER" = "1" ]; then
    export CCF_HOST=${CCF_HOST:-"localhost"}
    export CCF_PORT=${CCF_PORT:-8000}
    export CCF_URL="https://${CCF_HOST}:${CCF_PORT}"

    ./docker/run-dev.sh &
    CCF_NETWORK_PID=$!
    trap "kill $CCF_NETWORK_PID" EXIT

    # Turn off pytest output capture to allow test logs to be interleaved with
    # the docker logs.
    TEST_ARGS="-s"
else
    SCITT_DIR=/tmp/scitt
    TEST_ARGS="--start-cchost --enclave-type=$ENCLAVE_TYPE --enclave-package=$SCITT_DIR/lib/libscitt --constitution=$SCITT_DIR/share/scitt/constitution"
fi

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi
source venv/bin/activate 
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q -r test/requirements.txt

echo "Running functional tests..."
if [ -n "$ELEVATE_PRIVILEGES" ]; then
    sudo -E --preserve-env=PATH \
        capsh --keep=1 --user=$(id -un) --inh=cap_net_bind_service --addamb=cap_net_bind_service \
        -- -c "pytest ./test -v -rA $TEST_ARGS $(printf "'%s' " "$@")"
else
    pytest ./test -v -rA $TEST_ARGS "$@"
fi
