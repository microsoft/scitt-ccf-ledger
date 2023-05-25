#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

if ! command -v python3.8 &> /dev/null; then
    echo "python3.8 could not be found."
    echo "On Ubuntu, run: apt install python3.8 python3.8-venv"
    exit 1
fi

PLATFORM=${PLATFORM:-sgx}
CCF_HOST=${CCF_HOST:-"localhost"}
CCF_PORT=${CCF_PORT:-8000}
CCF_URL="https://${CCF_HOST}:${CCF_PORT}"

DOCKER_TAG=${DOCKER_TAG:-"scitt-ccf-ledger-$PLATFORM"}
CONTAINER_NAME=${CONTAINER_NAME:-"scitt-ccf-ledger-dev-$(date +%s)"}

WORKSPACE=${WORKSPACE:-"workspace/"}

VOLUME_NAME="${CONTAINER_NAME}-vol"

function cleanup() {
    docker stop "$CONTAINER_NAME" || true
    docker rm "$CONTAINER_NAME" || true
    docker volume rm "$VOLUME_NAME" || true
}

trap cleanup EXIT

rm -rf "$WORKSPACE"
mkdir -p "$WORKSPACE"

cp ./docker/dev-config.tmpl.json "$WORKSPACE"/dev-config.json
if [ "$PLATFORM" = "sgx" ]; then
    enclave_platform="SGX"
    enclave_type="Release"
    enclave_file="libscitt.enclave.so.signed"
    DOCKER_FLAGS=(
        "--device" "/dev/sgx_enclave:/dev/sgx_enclave"
        "--device" "/dev/sgx_provision:/dev/sgx_provision"
    )
elif [ "$PLATFORM" = "virtual" ]; then
    enclave_platform="Virtual"
    enclave_type="Virtual"
    enclave_file="libscitt.virtual.so"
    DOCKER_FLAGS=()
fi
sed -i "s/%ENCLAVE_PLATFORM%/$enclave_platform/g" "$WORKSPACE"/dev-config.json
sed -i "s/%ENCLAVE_TYPE%/$enclave_type/g" "$WORKSPACE"/dev-config.json
sed -i "s/%ENCLAVE_FILE%/$enclave_file/g" "$WORKSPACE"/dev-config.json
sed -i "s/%CCF_PORT%/$CCF_PORT/g" "$WORKSPACE"/dev-config.json

cp -r ./app/constitution "$WORKSPACE"

KEYGEN=$(pwd)/docker/keygenerator.sh
pushd "$WORKSPACE"
$KEYGEN --name member0 --gen-enc-key
popd

# Create a volume to store the workspace
# This works reliably on host as well as Docker-in-Docker
docker volume create "$VOLUME_NAME"

# Copy the workspace to the volume
# Note that this requires running a temporary container
# https://stackoverflow.com/a/56085040
tar -C "$WORKSPACE" -c . | docker run --rm \
    -v "$VOLUME_NAME":/host -i \
    --entrypoint "" \
    "$DOCKER_TAG" tar -C /host -x

# Determine networking flags
if [ "$DOCKER_IN_DOCKER" = "1" ]; then
    # This assumes that the container we're running in
    # wasn't started with a custom hostname.
    DOCKER_FLAGS+=(
        "--network=container:$(hostname)"
    )
else
    DOCKER_FLAGS+=(
        "--network=host"
    )
fi

# Run CCF
docker run --name "$CONTAINER_NAME" \
    -d \
    "${DOCKER_FLAGS[@]}" \
    -v "$VOLUME_NAME":/host \
    "$DOCKER_TAG" --config /host/dev-config.json

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3.8 -m venv "venv"
fi
source venv/bin/activate 
pip install --disable-pip-version-check -q -e ./pyscitt

timeout=15
while ! curl -s -f -k "$CCF_URL"/node/network > /dev/null; do
    echo "Waiting for CCF to start..."
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -eq 0 ]; then
        echo "CCF failed to start, exiting"
        echo "Docker logs:"
        docker logs "$CONTAINER_NAME"
        exit 1
    fi
done

scitt governance local_development \
    --url "$CCF_URL" \
    --member-key "$WORKSPACE"/member0_privk.pem \
    --member-cert "$WORKSPACE"/member0_cert.pem

echo "SCITT is running: ${CCF_URL}"
# docker logs -f "$CONTAINER_NAME"
