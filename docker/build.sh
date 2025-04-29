#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

PLATFORM=${PLATFORM:-snp}
SAVE_IMAGE_PATH=${SAVE_IMAGE_PATH:-""}
DOCKER_TAG=${DOCKER_TAG:-"scitt-$PLATFORM"}
DOCKERFILE="Dockerfile"

# If platform is not snp or virtual, exit
if [ "$PLATFORM" != "virtual" ] && [ "$PLATFORM" != "snp" ]; then
    echo "Unknown platform: $PLATFORM, must be 'virtual', or 'snp'"
    exit 1
fi

# uses longer version of tags to avoid situations when tag is reassigned to a different commit, e.g. 0.12.1-2-g0b45e35
SCITT_VERSION_OVERRIDE=$(git describe --tags --long)

echo "Building Dockerfile=$DOCKERFILE tag=$DOCKER_TAG SCITT_VERSION_OVERRIDE=$SCITT_VERSION_OVERRIDE"

DOCKER_BUILDKIT=1 docker build \
    -t "$DOCKER_TAG" \
    -f docker/$DOCKERFILE \
    --build-arg SCITT_VERSION_OVERRIDE="$SCITT_VERSION_OVERRIDE" \
    --build-arg CCF_PLATFORM="$PLATFORM" \
    .

echo "Inspecting Docker image $DOCKER_TAG"
docker image inspect "$DOCKER_TAG"

if [ -n "$SAVE_IMAGE_PATH" ]; then  
    echo "Saving image to $SAVE_IMAGE_PATH"
    docker save "$DOCKER_TAG" -o "$SAVE_IMAGE_PATH"
else
    echo "Image was not saved, set SAVE_IMAGE_PATH to save it"
fi
