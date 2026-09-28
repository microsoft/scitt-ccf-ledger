#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

echo "Executing export-image-rootfs-diff-ids.sh"

target_dir="$BUILD_SOURCESDIRECTORY"/image-metadata
output_dir="$BUILD_SOURCESDIRECTORY"/out/image-rootfs-diff-ids

mkdir -p "$output_dir"

echo "Metadata directory: $target_dir"
echo "Output directory: $output_dir"

for metadata_file in "$target_dir"/*.json; do
    echo "Processing $metadata_file"

    source_registry=$(jq -r '.registry' "$metadata_file")
    image_name=$(jq -r '.repository_name' "$metadata_file")
    tag_name=$(jq -r '.build_tag' "$metadata_file")
    image_digest=$(jq -r '.acr_digest' "$metadata_file")

    if [ -z "$source_registry" ] || [ "$source_registry" = "null" ]; then
        echo "Missing registry in $metadata_file" >&2
        exit 1
    fi

    if [ -z "$image_name" ] || [ "$image_name" = "null" ]; then
        echo "Missing repository_name in $metadata_file" >&2
        exit 1
    fi

    if [ -z "$tag_name" ] || [ "$tag_name" = "null" ]; then
        echo "Missing build_tag in $metadata_file" >&2
        exit 1
    fi

    if [ -z "$image_digest" ] || [ "$image_digest" = "null" ]; then
        echo "Missing acr_digest in $metadata_file" >&2
        exit 1
    fi

    image_reference="$source_registry/$image_name@$image_digest"
    safe_image_name="${image_name//[^A-Za-z0-9_.-]/_}"
    safe_tag_name="${tag_name//[^A-Za-z0-9_.-]/_}"
    local_image_reference="rootfs-diff-ids-$safe_image_name:$safe_tag_name"
    output_prefix="$output_dir/$safe_image_name-$safe_tag_name"
    image_archive="$output_prefix.tar"

    echo "Pulling $image_reference"
    docker pull "$image_reference"
    docker tag "$image_reference" "$local_image_reference"

    echo "Saving $local_image_reference to $image_archive"
    docker save "$local_image_reference" --output "$image_archive"

    IMAGE_ARCHIVE="$image_archive" OUTPUT_PREFIX="$output_prefix" python3 - <<'PY'
import json
import os
import tarfile
from pathlib import PurePosixPath

archive_path = os.environ["IMAGE_ARCHIVE"]
output_prefix = os.environ["OUTPUT_PREFIX"]


def read_json(archive: tarfile.TarFile, path: str):
    member = archive.extractfile(path)
    if member is None:
        raise ValueError(f"{path} is not a regular file")
    return json.load(member)


with tarfile.open(archive_path) as archive:
    names = set(archive.getnames())
    if "manifest.json" in names:
        manifest = read_json(archive, "manifest.json")
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError(f"{archive_path} must contain exactly one image")
        config_path = manifest[0]["Config"]
        config = read_json(archive, config_path)
    elif "index.json" in names:
        index = read_json(archive, "index.json")
        manifests = index.get("manifests", [])
        if len(manifests) != 1:
            raise ValueError(f"{archive_path} must contain exactly one image")
        manifest_digest = manifests[0]["digest"].removeprefix("sha256:")
        manifest_path = str(PurePosixPath("blobs/sha256") / manifest_digest)
        manifest = read_json(archive, manifest_path)
        config_digest = manifest["config"]["digest"].removeprefix("sha256:")
        config_path = str(PurePosixPath("blobs/sha256") / config_digest)
        config = read_json(archive, config_path)
    else:
        raise ValueError(f"{archive_path} is not a supported Docker or OCI image archive")

layers = config.get("rootfs", {}).get("diff_ids")
if not isinstance(layers, list) or not layers:
    raise ValueError(f"{archive_path} has no rootfs.diff_ids")

with open(f"{output_prefix}-image-config.json", "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2, sort_keys=True)
    handle.write("\n")

with open(f"{output_prefix}-rootfs-diff-ids.txt", "w", encoding="utf-8") as handle:
    handle.write("".join(f"{layer}\n" for layer in layers))
PY

    cp "$metadata_file" "$output_prefix-metadata.json"

    echo "rootfs.diff_ids for $image_reference:"
    cat "$output_prefix-rootfs-diff-ids.txt"

    rm -f "$image_archive"
    docker rmi "$local_image_reference"
done

echo "Script export-image-rootfs-diff-ids.sh completed successfully!"
