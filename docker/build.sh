#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

SAVE_IMAGE_PATH=${SAVE_IMAGE_PATH:-""}
DOCKER_TAG=${DOCKER_TAG:-"scitt"}
DOCKERFILE="Dockerfile"
REPRODUCIBLE=${REPRODUCIBLE:-0}

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )

# Reproducible builds must use the canonical build context and arguments, which
# only include committed content. Ordinary development builds keep using the
# working tree so that uncommitted changes are picked up.
if [ "$REPRODUCIBLE" != "0" ]; then
    echo "Building reproducibly via scripts/reproduce-image.sh"
    exec "$ROOT_DIR/scripts/reproduce-image.sh" all "$DOCKER_TAG"
fi

# uses longer version of tags to avoid situations when tag is reassigned to a different commit, e.g. 0.12.1-2-g0b45e35
SCITT_VERSION_OVERRIDE=$(git describe --tags --long --always)
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)

echo "Building Dockerfile=$DOCKERFILE tag=$DOCKER_TAG SCITT_VERSION_OVERRIDE=$SCITT_VERSION_OVERRIDE SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

DOCKER_BUILDKIT=1 docker build \
    -t "$DOCKER_TAG" \
    -f docker/$DOCKERFILE \
    --provenance=false \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --build-arg SCITT_VERSION_OVERRIDE="$SCITT_VERSION_OVERRIDE" \
    .

echo "Inspecting Docker image $DOCKER_TAG"
docker image inspect "$DOCKER_TAG"

if [ -n "$SAVE_IMAGE_PATH" ]; then  
    echo "Saving image to $SAVE_IMAGE_PATH"
    docker save "$DOCKER_TAG" -o "$SAVE_IMAGE_PATH"
else
    echo "Image was not saved, set SAVE_IMAGE_PATH to save it"
fi
