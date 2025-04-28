#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

DOCKER=${DOCKER:-0}
PLATFORM=${PLATFORM:-snp}

# Variable to enable performance tests
ENABLE_PERF_TESTS=${ENABLE_PERF_TESTS:-}

# SNP attestation config
SNP_ATTESTATION_CONFIG=${SNP_ATTESTATION_CONFIG:-}

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

    # wait until the network is ready
    timeout=120
    while ! curl -s -f -k $CCF_URL/parameters > /dev/null; do
        echo "Waiting for service to be ready..."
        sleep 1
        timeout=$((timeout - 1))
        if [ $timeout -eq 0 ]; then
            echo "Service failed to become ready, exiting"
            exit 1
        fi
    done

    # Turn off pytest output capture to allow test logs to be interleaved with
    # the docker logs.
    TEST_ARGS="-s"
else
    echo "Using regular build for functional tests, expecting SCITT binary to be present."
    SCITT_DIR=/tmp/scitt
    echo "List of files in SCITT_DIR $SCITT_DIR"
    ls -R $SCITT_DIR

    TEST_ARGS="--start-cchost --platform=$PLATFORM --enclave-package=$SCITT_DIR/lib/libscitt --constitution=$SCITT_DIR/share/scitt/constitution --snp-attestation-config=$SNP_ATTESTATION_CONFIG"
fi

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    if command -v python &> /dev/null; then
        PYTHON=python
    elif command -v python3.12 &> /dev/null; then
        PYTHON=python3.12
    else
        echo "Neither python nor python3.12 is available. Please install one of them."
        exit 1
    fi
    $PYTHON -m venv "venv"
fi
source venv/bin/activate
pip install --disable-pip-version-check -q -e ./pyscitt
pip install --disable-pip-version-check -q wheel
pip install --disable-pip-version-check -q -r test/requirements.txt

# Enable performance tests if the variable is set
if [ -n "$ENABLE_PERF_TESTS" ]; then
    TEST_ARGS="$TEST_ARGS --enable-perf"
    echo "Performance tests enabled"
fi

echo "Running functional tests..."
if [ -n "$ELEVATE_PRIVILEGES" ]; then
    sudo -E --preserve-env=PATH \
        capsh --keep=1 --user=$(id -un) --inh=cap_net_bind_service --addamb=cap_net_bind_service \
        -- -c "pytest ./test -v -rA $TEST_ARGS $(printf "'%s' " "$@")"
else
    pytest ./test -v -rA $TEST_ARGS "$@"
fi
