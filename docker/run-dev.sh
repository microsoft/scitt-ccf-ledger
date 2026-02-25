#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

if ! command -v python &> /dev/null && ! command -v python3.12 &> /dev/null; then
    echo "Neither python nor python3.12 could be found."
    echo "On Azure Linux, run: tdnf install python3.12"
    exit 1
fi

PLATFORM=${PLATFORM:-snp}
CCF_HOST=${CCF_HOST:-"localhost"}
CCF_PORT=${CCF_PORT:-8000}
CCF_URL="https://${CCF_HOST}:${CCF_PORT}"

DOCKER_TAG=${DOCKER_TAG:-"scitt-$PLATFORM"}
CONTAINER_NAME=${CONTAINER_NAME:-"scitt-dev-$(date +%s)"}

WORKSPACE=${WORKSPACE:-"workspace/"}

VOLUME_NAME="${CONTAINER_NAME}-vol"

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
if [ "$PLATFORM" = "virtual" ]; then
    enclave_platform="Virtual"
    enclave_type="Virtual"
    enclave_file="libscitt.virtual.so"
    DOCKER_FLAGS=()
elif [ "$PLATFORM" = "snp" ]; then
    enclave_platform="SNP"
    enclave_type="Release"
    enclave_file="libscitt.snp.so"
    DOCKER_FLAGS=()
else 
    echo "Unknown platform: $PLATFORM, must be 'virtual', or 'snp'"
    exit 1
fi
sed -i "s/%ENCLAVE_PLATFORM%/$enclave_platform/g" "$WORKSPACE"/dev-config.json
sed -i "s/%ENCLAVE_TYPE%/$enclave_type/g" "$WORKSPACE"/dev-config.json
sed -i "s/%ENCLAVE_FILE%/$enclave_file/g" "$WORKSPACE"/dev-config.json
sed -i "s/%CCF_PORT%/$CCF_PORT/g" "$WORKSPACE"/dev-config.json

if [ "$PLATFORM" = "snp" ]; then
    if [ -f "$SNP_ATTESTATION_CONFIG" ]; then
        SNP_ATTESTATION_CONTENT=$(jq '.' "$SNP_ATTESTATION_CONFIG")
        jq --argjson content "$SNP_ATTESTATION_CONTENT" '.attestation = $content' "$WORKSPACE"/dev-config.json > tmp.json && mv tmp.json "$WORKSPACE"/dev-config.json
    else
        echo "SNP attestation config file not found or not set: $SNP_ATTESTATION_CONFIG"
        exit 1
    fi
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

echo "Run CCF with name $CONTAINER_NAME, flags ${DOCKER_FLAGS[*]}, volume name $VOLUME_NAME, and tag $DOCKER_TAG"
docker run --name "$CONTAINER_NAME" \
    -d \
    "${DOCKER_FLAGS[@]}" \
    --cpus=1 \
    --memory=2g \
    -v "$VOLUME_NAME":/host \
    --entrypoint "cchost" \
    "$DOCKER_TAG" --config /host/dev-config.json

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
