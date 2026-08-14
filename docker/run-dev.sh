#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# Multi-node clusters are handled by a dedicated script, which needs per-node
# configuration and governance to trust the joining nodes.
NODE_COUNT=${NODE_COUNT:-1}
if [ "$NODE_COUNT" -gt 1 ]; then
    exec "$(dirname "$0")/run-dev-cluster.sh" "$@"
fi

echo "Starting a single-node CCF network for development and functional testing."

if ! command -v python &> /dev/null && ! command -v python3.12 &> /dev/null; then
    echo "Neither python nor python3.12 could be found."
    echo "On Azure Linux, run: tdnf install python3.12"
    exit 1
fi

CCF_HOST=${CCF_HOST:-"localhost"}
CCF_PORT=${CCF_PORT:-8000}
CCF_URL="https://${CCF_HOST}:${CCF_PORT}"

DOCKER_TAG=${DOCKER_TAG:-"scitt"}
CONTAINER_NAME=${CONTAINER_NAME:-"scitt-dev-$(date +%s)"}

WORKSPACE=${WORKSPACE:-"workspace/"}

VOLUME_NAME="${CONTAINER_NAME}-vol"

# Resources given to the node. The defaults are deliberately small so that a
# development node leaves the rest of the machine free, but they are the main
# limit on throughput: raise them when measuring performance.
CPUS=${CPUS:-2}
MEMORY=${MEMORY:-2g}

LOG_LEVEL=${LOG_LEVEL:-"info"}

# SNP attestation config
SNP_ATTESTATION_CONFIG=${SNP_ATTESTATION_CONFIG:-}

function cleanup() {
    docker stop "$CONTAINER_NAME" || true
    docker rm "$CONTAINER_NAME" || true
    docker volume rm "$VOLUME_NAME" || true
}

trap cleanup EXIT

rm -rf "$WORKSPACE"
mkdir -p "$WORKSPACE"

cp ./docker/dev-config.tmpl.json "$WORKSPACE"/dev-config.json

sed -i "s/%CCF_PORT%/$CCF_PORT/g" "$WORKSPACE"/dev-config.json

if [ -n "$SNP_ATTESTATION_CONFIG" ]; then
    if [ ! -f "$SNP_ATTESTATION_CONFIG" ]; then
        echo "Error: SNP_ATTESTATION_CONFIG is set to '$SNP_ATTESTATION_CONFIG' but the file does not exist."
        exit 1
    fi
    SNP_ATTESTATION_CONTENT=$(jq '.' "$SNP_ATTESTATION_CONFIG")
    jq --argjson content "$SNP_ATTESTATION_CONTENT" '.attestation = $content' "$WORKSPACE"/dev-config.json > tmp.json && mv tmp.json "$WORKSPACE"/dev-config.json
fi

cp -r ./app/constitution "$WORKSPACE"

echo "Generate keys"
KEYGEN=$(pwd)/docker/keygenerator.sh
pushd "$WORKSPACE"
$KEYGEN --name member0 --gen-enc-key
popd

echo "Create a volume to store the workspace"
# This works reliably on host as well as Docker-in-Docker
docker volume create "$VOLUME_NAME"

echo "Copy the workspace to the volume"
# Note that this requires a temporary container to mount the volume.
# `docker cp` is used rather than piping a tar into the container, because the
# image contains neither `tar` nor a usable package manager to install it with.
# The container is only created, never started, which is enough for `docker cp`
# to write through to the mounted volume.
COPY_HELPER=$(docker create -v "$VOLUME_NAME":/host --entrypoint "" "$DOCKER_TAG" true)
docker cp "$WORKSPACE"/. "$COPY_HELPER":/host
docker rm "$COPY_HELPER" > /dev/null

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

echo "Run CCF with name $CONTAINER_NAME, flags ${DOCKER_FLAGS[*]}, volume name $VOLUME_NAME, tag $DOCKER_TAG, cpus $CPUS, memory $MEMORY"
docker run --name "$CONTAINER_NAME" \
    -d \
    "${DOCKER_FLAGS[@]}" \
    --cpus="$CPUS" \
    --memory="$MEMORY" \
    -v "$VOLUME_NAME":/host \
    --entrypoint "cchost" \
    "$DOCKER_TAG" --config /host/dev-config.json --log-level "$LOG_LEVEL"

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
echo "Using pip index URL: ${PIP_INDEX_URL:-default}"
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
docker logs -f "$CONTAINER_NAME"
