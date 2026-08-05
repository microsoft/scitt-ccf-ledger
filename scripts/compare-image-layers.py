#!/usr/bin/env python3.12
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import sys
import tarfile
from pathlib import PurePosixPath
from typing import Any


def read_json(archive: tarfile.TarFile, path: str) -> Any:
    member = archive.extractfile(path)
    if member is None:
        raise ValueError(f"{path} is not a regular file")
    return json.load(member)


def read_layers(path: str) -> list[str]:
    with tarfile.open(path) as archive:
        names = set(archive.getnames())
        if "manifest.json" in names:
            manifest = read_json(archive, "manifest.json")
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise ValueError(f"{path} must contain exactly one image")
            config_path = manifest[0]["Config"]
            config = read_json(archive, config_path)
        elif "index.json" in names:
            index = read_json(archive, "index.json")
            manifests = index.get("manifests", [])
            if len(manifests) != 1:
                raise ValueError(f"{path} must contain exactly one image")
            manifest_digest = manifests[0]["digest"].removeprefix("sha256:")
            manifest_path = str(PurePosixPath("blobs/sha256") / manifest_digest)
            manifest = read_json(archive, manifest_path)
            config_digest = manifest["config"]["digest"].removeprefix("sha256:")
            config_path = str(PurePosixPath("blobs/sha256") / config_digest)
            config = read_json(archive, config_path)
        else:
            raise ValueError(f"{path} is not a supported Docker or OCI image archive")

        layers = config.get("rootfs", {}).get("diff_ids")
        if not isinstance(layers, list) or not layers:
            raise ValueError(f"{path} has no rootfs.diff_ids")
        return layers


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <first-image.tar> <second-image.tar>",
            file=sys.stderr,
        )
        return 2

    first = read_layers(sys.argv[1])
    second = read_layers(sys.argv[2])

    print("First image filesystem layers:")
    print("\n".join(first))
    print("Second image filesystem layers:")
    print("\n".join(second))

    if first != second:
        print("The image filesystem layers are not reproducible.", file=sys.stderr)
        return 1

    print("The image filesystem layers are reproducible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
