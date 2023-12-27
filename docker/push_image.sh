#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

### Script to build and push a docker image to ACR

set -e

# Variables
ACR=${ACR:-"scittoss"}
BASE_IMAGE_NAME=${BASE_IMAGE_NAME:-"scitt"}
PLATFORM=${PLATFORM:-"sgx"}
TAG=${TAG:-"latest"}

# Derived variables
DOCKER_TAG="$ACR.azurecr.io/$BASE_IMAGE_NAME-$PLATFORM:$TAG"

echo "Building docker image for $PLATFORM platform with tag $DOCKER_TAG"

# Build docker image for SGX
PLATFORM=$PLATFORM DOCKER_TAG=$DOCKER_TAG ./docker/build.sh

# Login to Azure
if az account show > /dev/null; then
  echo "Already logged in to Azure"
else
  echo "Logging in to Azure"
  az login --only-show-errors > /dev/null
fi

# Login to ACR
echo "Logging into ACR $ACR"
az acr login --name $ACR --only-show-errors

echo "Pushing docker image $DOCKER_TAG to ACR $ACR"

# Push docker image to ACR
docker push "$DOCKER_TAG"