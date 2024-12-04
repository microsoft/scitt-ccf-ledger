#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

PLATFORM=${PLATFORM:-snp}
SAVE_IMAGE_PATH=${SAVE_IMAGE_PATH:-""}
DOCKER_TAG=${DOCKER_TAG:-"scitt-$PLATFORM"}

if [ "$PLATFORM" = "virtual" ]; then
    DOCKERFILE="virtual.Dockerfile"
elif [ "$PLATFORM" = "snp" ]; then
    DOCKERFILE="snp.Dockerfile"
else
    echo "Unknown platform: $PLATFORM, must be 'virtual', or 'snp'"
    exit 1
fi

SCITT_VERSION_OVERRIDE=$(git describe --tags --match="*.*.*")

DOCKER_BUILDKIT=1 docker build \
    -t "$DOCKER_TAG" \
    -f docker/$DOCKERFILE \
    --build-arg SCITT_VERSION_OVERRIDE="$SCITT_VERSION_OVERRIDE" \
    .

if [ -n "$SAVE_IMAGE_PATH" ]; then
    docker save "$DOCKER_TAG" -o "$SAVE_IMAGE_PATH"
fi
