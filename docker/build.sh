#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

PLATFORM=${PLATFORM:-sgx}
SAVE_IMAGE_PATH=${SAVE_IMAGE_PATH:-""}
DOCKER_TAG=${DOCKER_TAG:-"scitt-$PLATFORM"}

if [ "$PLATFORM" = "sgx" ]; then
    DOCKERFILE="enclave.Dockerfile"
elif [ "$PLATFORM" = "virtual" ]; then
    DOCKERFILE="virtual.Dockerfile"
elif [ "$PLATFORM" = "snp" ]; then
    DOCKERFILE="snp.Dockerfile"
else
    echo "Unknown platform: $PLATFORM, must be 'sgx', 'virtual', or 'snp'"
    exit 1
fi

SCITT_VERSION_OVERRIDE=$(git describe --tags --match="*.*.*")

DOCKER_BUILDKIT=1 docker build \
    -t "$DOCKER_TAG" \
    -f docker/$DOCKERFILE \
    --build-arg SCITT_VERSION_OVERRIDE="$SCITT_VERSION_OVERRIDE" \
    .

if [ "$PLATFORM" = "sgx" ]; then
    echo "mrenclave.txt"
    docker run --rm --entrypoint /bin/cat "$DOCKER_TAG" /usr/src/app/mrenclave.txt
fi

if [ -n "$SAVE_IMAGE_PATH" ]; then
    docker save "$DOCKER_TAG" -o "$SAVE_IMAGE_PATH"
fi
