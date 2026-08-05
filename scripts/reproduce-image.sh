#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Canonical entry point for reproducible container image builds.
#
# Every automated build (GitHub Actions, Azure DevOps) and every third party
# reproduction attempt should go through this script so that they all use
# byte-identical inputs and identical Docker arguments. Keeping the logic here
# rather than duplicating it in pipeline definitions and documentation is what
# stops the three from drifting apart over time.

set -euo pipefail

# Staging directories are cleaned up once, on exit, so that a trap installed by
# one command cannot fire again while another command is running.
REPRO_STAGING_DIR=""

cleanup() {
    if [ -n "${REPRO_STAGING_DIR}" ]; then
        rm -rf "${REPRO_STAGING_DIR}"
    fi
}

trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: scripts/reproduce-image.sh <command> [arguments]

Commands:
  context <archive>                Write a normalized build context archive and
                                   a build-metadata.json file next to it.
  extract <archive> <directory>    Extract a context archive deterministically.
  build <directory> <tag> [args..] Build the image with canonical arguments.
                                   Extra arguments are passed to docker build.
  manifest <tag> <file> [context]  Write a reproduce.json build manifest.
  metadata <file> <key>            Print one build-metadata.json value.
  all [tag] [output-directory]     Run all of the steps above in one go.

Environment:
  SOURCE_DATE_EPOCH        Defaults to the HEAD commit timestamp.
  SCITT_VERSION_OVERRIDE   Defaults to git describe --tags --long --always.
  SOURCE_COMMIT            Defaults to the HEAD commit hash.

The version and timestamp must be supplied explicitly when reproducing a
published image, because re-deriving them from git can yield a different value
than the original build used. Both are recorded in the image itself
(/opt/scitt/share/VERSION) and in the reproduce.json manifest.
EOF
}

repo_root() {
    git rev-parse --show-toplevel
}

# Resolve the build inputs, preferring explicitly provided values so that an
# old image can be rebuilt even after new tags or commits have been created.
# git is only consulted for values that were not supplied, which allows these
# commands to run against an extracted context outside of a git checkout.
resolve_inputs() {
    local root
    root=$(repo_root)

    if [ -z "${SOURCE_COMMIT:-}" ]; then
        SOURCE_COMMIT=$(git -C "${root}" rev-parse HEAD)
    fi
    SOURCE_COMMIT=$(git -C "${root}" rev-parse --verify "${SOURCE_COMMIT}^{commit}")

    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
        SOURCE_DATE_EPOCH=$(git -C "${root}" show -s --format=%ct "${SOURCE_COMMIT}")
    fi
    if [ -z "${SCITT_VERSION_OVERRIDE:-}" ]; then
        SCITT_VERSION_OVERRIDE=$(git -C "${root}" describe --tags --long --always "${SOURCE_COMMIT}")
    fi

    case "${SOURCE_DATE_EPOCH}" in
        '' | *[!0-9]*)
            echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
            exit 1
            ;;
    esac

    export SOURCE_DATE_EPOCH SCITT_VERSION_OVERRIDE SOURCE_COMMIT
}

# Build a context archive from tracked content only, with every source of
# filesystem nondeterminism (ordering, ownership, permissions, timestamps)
# normalized away.
cmd_context() {
    local archive="$1"
    local root staging metadata context_sha256 submodules

    root=$(repo_root)
    resolve_inputs

    archive=$(realpath -m "${archive}")
    metadata="$(dirname "${archive}")/build-metadata.json"
    staging=$(mktemp -d)
    REPRO_STAGING_DIR="${staging}"

    mkdir -p "$(dirname "${archive}")"
    submodules=$(git -C "${root}" ls-tree -r --full-tree "${SOURCE_COMMIT}" |
        awk '$1 == "160000" {print $4}')
    if [ -n "${submodules}" ]; then
        echo "Reproducible contexts do not yet support git submodules:" >&2
        echo "${submodules}" >&2
        exit 1
    fi

    git -C "${root}" archive --format=tar "${SOURCE_COMMIT}" |
        tar --extract --file=- --directory="${staging}"

    tar \
        --create \
        --file="${archive}" \
        --sort=name \
        --format=posix \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        --mode='a-s,u+rwX,go+rX,go-w' \
        --pax-option=delete=atime,delete=ctime \
        --directory="${staging}" \
        .

    context_sha256=$(sha256sum "${archive}" | cut -d ' ' -f 1)
    printf '%s  %s\n' "${context_sha256}" "$(basename "${archive}")" \
        > "${archive}.sha256"

    CONTEXT_SHA256="${context_sha256}" python3 - "${metadata}" <<'PY'
import json
import os
import sys

metadata = {
    "context_sha256": os.environ["CONTEXT_SHA256"],
    "source_commit": os.environ["SOURCE_COMMIT"],
    "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "scitt_version": os.environ["SCITT_VERSION_OVERRIDE"],
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(metadata, f, indent=2, sort_keys=True)
    f.write("\n")
PY

    rm -rf "${staging}"
    REPRO_STAGING_DIR=""

    echo "Wrote ${archive}"
    cat "${metadata}"
}

# Extract into a temporary sibling and rename it into place. Refusing an
# existing destination prevents deleted source files from surviving a rebuild.
cmd_extract() {
    local archive="$1"
    local directory="$2"
    local parent staging

    directory=$(realpath -m "${directory}")
    if [ -e "${directory}" ]; then
        echo "Extraction destination already exists: ${directory}" >&2
        exit 1
    fi

    parent=$(dirname "${directory}")
    mkdir -p "${parent}"
    staging=$(mktemp -d "${parent}/.repro-context.XXXXXX")
    REPRO_STAGING_DIR="${staging}"

    tar \
        --extract \
        --preserve-permissions \
        --file="${archive}" \
        --directory="${staging}"

    mv "${staging}" "${directory}"
    REPRO_STAGING_DIR=""
}

cmd_build() {
    local directory="$1"
    local tag="$2"
    shift 2

    resolve_inputs

    DOCKER_BUILDKIT=1 docker build \
        --platform linux/amd64 \
        --pull \
        --no-cache \
        --force-rm \
        --provenance=false \
        --file "${directory}/docker/Dockerfile" \
        --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        --build-arg SCITT_VERSION_OVERRIDE="${SCITT_VERSION_OVERRIDE}" \
        --tag "${tag}" \
        "$@" \
        "${directory}"
}

dockerfile_arg() {
    local dockerfile="$1"
    local name="$2"

    sed -n "s/^ARG ${name}=\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "${dockerfile}" | head -n1
}

cmd_metadata() {
    local metadata="$1"
    local key="$2"

    python3 - "${metadata}" "${key}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    value = json.load(f)[sys.argv[2]]
if isinstance(value, (dict, list)):
    raise SystemExit(f"{sys.argv[2]} is not a scalar value")
print(value)
PY
}

# Record everything a third party needs to rebuild this exact image, following
# the same idea as the reproduce.json that CCF publishes with its releases.
cmd_manifest() {
    local tag="$1"
    local output="$2"
    local context="${3:-$(repo_root)}"
    local dockerfile="${context}/docker/Dockerfile"
    local base_image image_id layers docker_version buildx_version

    resolve_inputs

    base_image=$(sed -n 's/^FROM \(mcr\.microsoft\.com[^ ]*\).*/\1/p' "${dockerfile}" | head -n1)
    image_id=$(docker image inspect --format '{{.Id}}' "${tag}")
    layers=$(docker image inspect --format '{{range .RootFS.Layers}}{{println .}}{{end}}' "${tag}")
    docker_version=$(docker version --format '{{.Server.Version}}')
    buildx_version=$(docker buildx version 2>/dev/null | head -n1 || echo "unknown")

    mkdir -p "$(dirname "${output}")"
    BASE_IMAGE="${base_image}" \
    CCF_VERSION_VALUE="$(dockerfile_arg "${dockerfile}" CCF_VERSION)" \
    CCF_RPM_SHA256_VALUE="$(dockerfile_arg "${dockerfile}" CCF_RPM_SHA256)" \
    CCF_REPRODUCE_SHA256_VALUE="$(dockerfile_arg "${dockerfile}" CCF_REPRODUCE_SHA256)" \
    TDNF_SNAPSHOTTIME_VALUE="$(dockerfile_arg "${dockerfile}" TDNF_SNAPSHOTTIME)" \
    DOCKER_VERSION_VALUE="${docker_version}" \
    BUILDX_VERSION_VALUE="${buildx_version}" \
    IMAGE_ID="${image_id}" \
    LAYERS="${layers}" \
        python3 - "${output}" <<'PY'
import json
import os
import sys

manifest = {
    "schema_version": 1,
    "source_commit": os.environ["SOURCE_COMMIT"],
    "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "scitt_version": os.environ["SCITT_VERSION_OVERRIDE"],
    "base_image": os.environ["BASE_IMAGE"],
    "ccf_version": os.environ["CCF_VERSION_VALUE"],
    "ccf_rpm_sha256": os.environ["CCF_RPM_SHA256_VALUE"],
    "ccf_reproduce_sha256": os.environ["CCF_REPRODUCE_SHA256_VALUE"],
    "tdnf_snapshottime": os.environ["TDNF_SNAPSHOTTIME_VALUE"],
    "docker_version": os.environ["DOCKER_VERSION_VALUE"],
    "buildx_version": os.environ["BUILDX_VERSION_VALUE"],
    "image_id": os.environ["IMAGE_ID"],
    "layers": os.environ["LAYERS"].splitlines(),
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

    cat "${output}"
}

cmd_all() {
    local tag="${1:-scitt-reproducibility:local}"
    local output="${2:-$(pwd)/reproduction}"
    local context

    mkdir -p "${output}"
    output=$(realpath "${output}")
    context="${output}/context"
    if [ -e "${context}" ]; then
        echo "Reproduction output already contains a context: ${context}" >&2
        echo "Use a new output directory for each reproduction." >&2
        exit 1
    fi

    cmd_context "${output}/docker-context.tar"
    cmd_extract "${output}/docker-context.tar" "${context}"

    SOURCE_COMMIT=$(cmd_metadata "${output}/build-metadata.json" source_commit)
    SOURCE_DATE_EPOCH=$(cmd_metadata "${output}/build-metadata.json" source_date_epoch)
    SCITT_VERSION_OVERRIDE=$(cmd_metadata "${output}/build-metadata.json" scitt_version)
    export SOURCE_COMMIT SOURCE_DATE_EPOCH SCITT_VERSION_OVERRIDE

    cmd_build "${context}" "${tag}"
    cmd_manifest "${tag}" "${output}/reproduce.json" "${context}"
}

main() {
    local command="${1:-}"
    [ $# -gt 0 ] && shift || true

    case "${command}" in
        context) cmd_context "$@" ;;
        extract) cmd_extract "$@" ;;
        build) cmd_build "$@" ;;
        manifest) cmd_manifest "$@" ;;
        metadata) cmd_metadata "$@" ;;
        all) cmd_all "$@" ;;
        -h | --help | help) usage ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
