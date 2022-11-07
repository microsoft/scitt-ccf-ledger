#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

DOCKER=${DOCKER:-0}

if [ "$DOCKER" = "1" ]; then
    CCF_HOST=${CCF_HOST:-"localhost"}
    CCF_PORT=${CCF_PORT:-8000}
    CCF_URL="https://${CCF_HOST}:${CCF_PORT}"
else
    CCF_URL=${CCF_URL:-"https://localhost:8000"}
fi

# If ELEVATE_PRIVILEGES is non-empty, the functional tests will be run with
# the NET_BIND_SERVICE capability, allowing certain tests that bind
# priviledged ports to run. Note that this isn't necessary in our CI
# environment, as Docker makes all ports unpriviledged anyway. Requires sudo
# access and libcap2-bin to be installed.
ELEVATE_PRIVILEGES=${ELEVATE_PRIVILEGES:-}

if [ "$DOCKER" = "1" ]; then
    CCF_HOST=$CCF_HOST CCF_PORT=$CCF_PORT \
        ./docker/run-dev.sh &
else
    ./start.sh &
fi

CCF_NETWORK_PID=$!
trap "kill $CCF_NETWORK_PID" EXIT

# wait until the network is ready
timeout=120
while ! curl -s -f -k $CCF_URL/app/parameters > /dev/null; do
    echo "Waiting for service to be ready..."
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -eq 0 ]; then
        echo "Service failed to become ready, exiting"
        exit 1
    fi
done

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi
source venv/bin/activate 
pip install --disable-pip-version-check -q -e ./pyscitt
pip install pytest

export CCF_URL

echo "Running functional tests..."
if [ -n "$ELEVATE_PRIVILEGES" ]; then
    sudo -E --preserve-env=PATH \
        capsh --keep=1 --user=$(id -un) --inh=cap_net_bind_service --addamb=cap_net_bind_service \
        -- -c "pytest ./test -s -rA -v --ignore-glob=*test_perf* $(printf "'%s' " "$@")"
else
    pytest ./test -s -rA -v --ignore-glob=*test_perf* "$@"
fi
