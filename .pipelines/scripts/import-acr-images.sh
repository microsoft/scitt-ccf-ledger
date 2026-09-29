#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

###################################################################################################################################################
#
#   This script imports container images from the docker metadata files to a target ACR.
#   It requires the DevOps AzureCLI task to connect to the target ACR and an access token to pull the image from the source ACR.
#
###################################################################################################################################################

set -euo pipefail
echo "Executing import-acr-images.sh"

# Parse arguments
TARGET_ACR=${1:?The target acr name is required}
ACCESS_TOKEN=${2:?An access token for the source ACR is required}

target_dir="$BUILD_SOURCESDIRECTORY"/image-metadata

echo "Target Directory: $target_dir"

ls -l "$target_dir"

# Process each metadata file
for metadata_file in "$target_dir"/*.json; do

    echo "Processing $metadata_file"

    # Extract the image details from the metadata file
    source_registry=$(jq -r '.registry' "$metadata_file")
    image_name=$(jq -r '.repository_name' "$metadata_file")
    tag_name=$(jq -r '.build_tag' "$metadata_file")
    image_digest=$(jq -r '.acr_digest' "$metadata_file")
    image_reference="$image_name:$tag_name"
    # by digest, so staging gets exactly the image this build pushed even if the tag moved
    source_image_full_name="$source_registry/$image_name@$image_digest"

    # waits for each import so a failure fails the job; --force keeps re-runs idempotent
    echo "Importing $source_image_full_name to $TARGET_ACR as $image_reference"
    az acr import --name "$TARGET_ACR" --source "$source_image_full_name" --image "$image_reference" --password "$ACCESS_TOKEN" --force
done

echo "Script import-acr-images.sh completed successfully!"
