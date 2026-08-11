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
  toolchain [context]              Check the local builder versions.
  all [tag] [output-directory]     Run all of the steps above in one go.

Environment:
  SOURCE_DATE_EPOCH        Defaults to the HEAD commit timestamp.
  SCITT_VERSION_OVERRIDE   Defaults to git describe --tags --long --always.
  SOURCE_COMMIT            Defaults to the HEAD commit hash.
  STRICT_TOOLCHAIN         Set to 1 to fail, rather than warn, when the
                           builder is newer than the highest verified version.

The version and timestamp must be supplied explicitly when reproducing a
published image, because re-deriving them from git can yield a different value
than the original build used. Both are recorded in the image itself
(/opt/scitt/share/VERSION) and in the reproduce.json manifest.
EOF
}

# Prints the repository root, or nothing when this is not a git checkout.
# Reproducing a published image only needs the recorded build inputs, so the
# absence of a repository is not by itself an error.
repo_root() {
    git rev-parse --show-toplevel 2>/dev/null || true
}

require_repo_root() {
    local root
    root=$(repo_root)
    if [ -z "${root}" ]; then
        echo "This command must run inside a git checkout of the repository." >&2
        exit 1
    fi
    printf '%s' "${root}"
}

# Resolve the build inputs, preferring explicitly provided values so that an
# old image can be rebuilt even after new tags or commits have been created.
# git is only consulted for values that were not supplied, which allows build
# and manifest to run against an extracted context outside of a git checkout,
# using only the values recorded in build-metadata.json or reproduce.json.
resolve_inputs() {
    local root resolved name missing=""

    root=$(repo_root)
    if [ -n "${root}" ]; then
        if [ -z "${SOURCE_COMMIT:-}" ]; then
            SOURCE_COMMIT=$(git -C "${root}" rev-parse HEAD)
        fi
        if resolved=$(git -C "${root}" rev-parse --verify --quiet "${SOURCE_COMMIT}^{commit}"); then
            SOURCE_COMMIT="${resolved}"
        fi
        if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
            SOURCE_DATE_EPOCH=$(git -C "${root}" show -s --format=%ct "${SOURCE_COMMIT}")
        fi
        if [ -z "${SCITT_VERSION_OVERRIDE:-}" ]; then
            SCITT_VERSION_OVERRIDE=$(git -C "${root}" describe --tags --long --always "${SOURCE_COMMIT}")
        fi
    fi

    for name in SOURCE_COMMIT SOURCE_DATE_EPOCH SCITT_VERSION_OVERRIDE; do
        if [ -z "${!name:-}" ]; then
            missing="${missing} ${name}"
        fi
    done
    if [ -n "${missing}" ]; then
        echo "Outside a git checkout these must be set explicitly:${missing}" >&2
        echo "Each one is recorded in build-metadata.json and reproduce.json." >&2
        exit 1
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

    root=$(require_repo_root)
    resolve_inputs
    # Archiving requires the commit itself, not merely a recorded identifier.
    SOURCE_COMMIT=$(git -C "${root}" rev-parse --verify "${SOURCE_COMMIT}^{commit}")
    export SOURCE_COMMIT

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

builder_docker_version() {
    docker version --format '{{.Server.Version}}'
}

# github.com/docker/buildx v0.33.0-desktop.1 <commit> -> 0.33.0
builder_buildx_version() {
    docker buildx version 2>/dev/null |
        head -n1 |
        awk '{print $2}' |
        sed 's/^v//; s/-.*$//'
}

# Compares dotted versions, tolerating the differing component counts that
# builders report.
version_at_least() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# Truncates a version to the component count of a reference, so that a maximum
# expressed as a major version does not reject every patch release of it.
version_prefix() {
    local version="$1" reference="$2" components
    components=$(printf '%s' "${reference}" | awk -F. '{print NF}')
    if [ -z "${components}" ] || [ "${components}" -lt 1 ]; then
        printf '%s' "${version}"
        return 0
    fi
    printf '%s' "${version}" | cut -d. -f"1-${components}"
}

# Fails when the builder is older than a required minimum. An absent
# expectation is not an error, so that contexts archived before a given
# expectation existed can still be rebuilt.
require_min_version() {
    local name="$1" actual="$2" minimum="$3"

    [ -n "${minimum}" ] || return 0
    if ! version_at_least "${actual}" "${minimum}"; then
        echo "${name} ${actual} is older than the minimum ${minimum}." >&2
        exit 1
    fi
}

# Reports, without failing, that the builder is newer than anything this
# expectation has been verified against.
report_if_newer() {
    local name="$1" actual="$2" maximum="$3"

    [ -n "${maximum}" ] || return 0
    if ! version_at_least "${maximum}" "$(version_prefix "${actual}" "${maximum}")"; then
        printf ' %s %s > %s' "${name}" "${actual}" "${maximum}"
    fi
}

# The Dockerfile, not BuildKit, is what normalizes layer timestamps, so the
# builder version is part of the reproducibility contract rather than an
# incidental detail. See docker/toolchain.env.
check_toolchain() {
    local context="${1:-}" env_file docker_actual buildx_actual drift=""

    env_file="${context}/docker/toolchain.env"
    if [ ! -f "${env_file}" ]; then
        echo "No toolchain expectations found at ${env_file}, skipping check." >&2
        return 0
    fi

    # Expectations are read with defaults rather than assumed to be present, so
    # that a context archived by an older or newer revision of this repository
    # cannot fail the build merely by declaring a different set of them.
    # shellcheck source=../docker/toolchain.env
    . "${env_file}"

    docker_actual=$(builder_docker_version)
    buildx_actual=$(builder_buildx_version)
    [ -n "${docker_actual}" ] || docker_actual="0"
    [ -n "${buildx_actual}" ] || buildx_actual="0"

    require_min_version docker "${docker_actual}" "${SCITT_MIN_DOCKER_VERSION:-}"
    require_min_version buildx "${buildx_actual}" "${SCITT_MIN_BUILDX_VERSION:-}"

    drift="${drift}$(report_if_newer docker "${docker_actual}" "${SCITT_MAX_VERIFIED_DOCKER_VERSION:-}")"
    drift="${drift}$(report_if_newer buildx "${buildx_actual}" "${SCITT_MAX_VERIFIED_BUILDX_VERSION:-}")"

    if [ -n "${drift}" ]; then
        echo "Builder is newer than the highest verified version:${drift}" >&2
        echo "The image may still be reproducible, but this combination has not been verified." >&2
        echo "Raise the values in docker/toolchain.env once the reproducibility gate passes on it." >&2
        if [ "${STRICT_TOOLCHAIN:-0}" = "1" ]; then
            exit 1
        fi
        return 0
    fi

    echo "Builder versions are within the verified range: docker ${docker_actual}, buildx ${buildx_actual}"
}

cmd_toolchain() {
    local context="${1:-$(repo_root)}"

    if [ -z "${context}" ]; then
        echo "A context directory is required outside a git checkout." >&2
        exit 1
    fi
    check_toolchain "${context}"
}

cmd_build() {
    local directory="$1"
    local tag="$2"
    shift 2

    resolve_inputs
    check_toolchain "${directory}"

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
    local dockerfile base_image image_id layers docker_version buildx_version

    if [ -z "${context}" ]; then
        echo "A context directory is required outside a git checkout." >&2
        exit 1
    fi
    dockerfile="${context}/docker/Dockerfile"

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
        toolchain) cmd_toolchain "$@" ;;
        all) cmd_all "$@" ;;
        -h | --help | help) usage ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
