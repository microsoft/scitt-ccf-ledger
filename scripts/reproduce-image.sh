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
                                   a build-metadata.env file next to it.
  extract <archive> <directory>    Extract a context archive deterministically.
  build <directory> <tag> [args..] Build the image with canonical arguments.
                                   Extra arguments are passed to docker build.
  manifest <tag> <file> [context]  Write a reproduce.json build manifest.
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
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
        SOURCE_DATE_EPOCH=$(git -C "$(repo_root)" show -s --format=%ct HEAD)
    fi
    if [ -z "${SCITT_VERSION_OVERRIDE:-}" ]; then
        SCITT_VERSION_OVERRIDE=$(git -C "$(repo_root)" describe --tags --long --always)
    fi
    if [ -z "${SOURCE_COMMIT:-}" ]; then
        SOURCE_COMMIT=$(git -C "$(repo_root)" rev-parse HEAD)
    fi

    export SOURCE_DATE_EPOCH SCITT_VERSION_OVERRIDE SOURCE_COMMIT
}

# Build a context archive from tracked content only, with every source of
# filesystem nondeterminism (ordering, ownership, permissions, timestamps)
# normalized away.
cmd_context() {
    local archive="$1"
    local root staging metadata

    root=$(repo_root)
    resolve_inputs

    archive=$(realpath -m "${archive}")
    metadata="$(dirname "${archive}")/build-metadata.env"
    staging=$(mktemp -d)
    REPRO_STAGING_DIR="${staging}"

    mkdir -p "$(dirname "${archive}")"
    (cd "${root}" && git checkout-index --all --prefix="${staging}/")

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

    {
        echo "SOURCE_COMMIT=${SOURCE_COMMIT}"
        echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
        echo "SCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE}"
    } > "${metadata}"

    (cd "$(dirname "${archive}")" && sha256sum "$(basename "${archive}")" > "$(basename "${archive}").sha256")

    echo "Wrote ${archive}"
    cat "${metadata}"
}

# --preserve-permissions keeps extraction independent of the caller's umask,
# so the build context cannot vary with the environment it is unpacked in.
cmd_extract() {
    local archive="$1"
    local directory="$2"

    mkdir -p "${directory}"
    tar \
        --extract \
        --preserve-permissions \
        --file="${archive}" \
        --directory="${directory}"
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

    {
        echo "{"
        echo "  \"schema_version\": 1,"
        echo "  \"source_commit\": \"${SOURCE_COMMIT}\","
        echo "  \"source_date_epoch\": ${SOURCE_DATE_EPOCH},"
        echo "  \"scitt_version\": \"${SCITT_VERSION_OVERRIDE}\","
        echo "  \"base_image\": \"${base_image}\","
        echo "  \"ccf_version\": \"$(dockerfile_arg "${dockerfile}" CCF_VERSION)\","
        echo "  \"ccf_rpm_sha256\": \"$(dockerfile_arg "${dockerfile}" CCF_RPM_SHA256)\","
        echo "  \"ccf_reproduce_sha256\": \"$(dockerfile_arg "${dockerfile}" CCF_REPRODUCE_SHA256)\","
        echo "  \"tdnf_snapshottime\": \"$(dockerfile_arg "${dockerfile}" TDNF_SNAPSHOTTIME)\","
        echo "  \"docker_version\": \"${docker_version}\","
        echo "  \"buildx_version\": \"${buildx_version}\","
        echo "  \"image_id\": \"${image_id}\","
        echo "  \"layers\": ["
        echo "${layers}" | sed '/^$/d' | sed 's/.*/    "&",/' | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "${output}"

    cat "${output}"
}

cmd_all() {
    local tag="${1:-scitt-reproducibility:local}"
    local output="${2:-$(pwd)/reproduction}"
    local context

    mkdir -p "${output}"
    output=$(realpath "${output}")
    context="${output}/context"

    cmd_context "${output}/docker-context.tar"
    cmd_extract "${output}/docker-context.tar" "${context}"

    set -a
    # shellcheck disable=SC1091
    . "${output}/build-metadata.env"
    set +a

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
        all) cmd_all "$@" ;;
        -h | --help | help) usage ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
