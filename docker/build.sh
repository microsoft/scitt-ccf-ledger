#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

ENCLAVE_TYPE=${ENCLAVE_TYPE:-release}
SAVE_IMAGE_PATH=${SAVE_IMAGE_PATH:-""}

if [ "$ENCLAVE_TYPE" = "release" ]; then
    DOCKERFILE="enclave.Dockerfile"
elif [ "$ENCLAVE_TYPE" = "virtual" ]; then
    DOCKERFILE="virtual.Dockerfile"
else
    echo "Unknown enclave type: $ENCLAVE_TYPE, must be 'release' or 'virtual'"
    exit 1
fi

git submodule sync
git submodule update --init --recursive

DOCKER_TAG="scitt-ccf-ledger-$ENCLAVE_TYPE"

DOCKER_BUILDKIT=1 docker build -t "$DOCKER_TAG" -f docker/$DOCKERFILE .

if [ -n "$SAVE_IMAGE_PATH" ]; then
    docker save "$DOCKER_TAG" -o "$SAVE_IMAGE_PATH"
fi
