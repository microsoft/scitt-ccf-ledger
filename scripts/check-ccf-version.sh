#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Check that every file naming the pinned CCF release agrees on the version.
#
# The version is repeated in the Dockerfile, the devcontainer, the environment
# setup script, the build script and the docs. Letting those drift apart is how
# the devcontainer ends up on a different CCF release than the image, which
# then reproduces differently for no visible reason.
#
# That one value is the whole contract. The Dockerfile derives everything else
# from it, reading the tdnf snapshot time out of the release's own
# reproduce.json rather than repeating it, so there is nothing else to keep in
# step.
#
# This only reads files: no network, no writes. It is safe to run on every CI
# job. scripts/check-build-inputs.sh covers the checks that do reach out.

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dockerfile="${root}/docker/Dockerfile"
devcontainer="${root}/.devcontainer/Dockerfile"
setup_env="${root}/scripts/setup-env.sh"
build_sh="${root}/build.sh"
development_md="${root}/DEVELOPMENT.md"

usage() {
    cat <<'EOF'
Usage: scripts/check-ccf-version.sh

Verify that every file naming the pinned CCF release agrees with the version
in docker/Dockerfile. Reads files only, so it needs no network.
EOF
}

version_in_dockerfile() {
    sed -n 's/^ARG CCF_VERSION="\(.*\)"$/\1/p' "${dockerfile}" | head -n1
}

version_in_devcontainer() {
    sed -n 's/^ARG CCF_VERSION="\(.*\)"$/\1/p' "${devcontainer}" | head -n1
}

version_in_setup_env() {
    # The ${...} here is literal text in the file being matched, not an
    # expansion, so the pattern has to stay single quoted.
    # shellcheck disable=SC2016
    sed -n 's/^CCF_VERSION=${CCF_VERSION:-"\(.*\)"}$/\1/p' "${setup_env}" | head -n1
}

version_in_build_sh() {
    sed -n 's/^[[:space:]]*CCF_SOURCE_VERSION="\(.*\)"$/\1/p' "${build_sh}" | head -n1
}

# A file naming no release at all is something to report, not to die on, and
# grep exits non-zero in exactly that case, so the status has to be dropped
# here rather than tripping errexit.
versions_in_development_md() {
    grep -o 'ccf-[0-9][0-9A-Za-z.-]*' "${development_md}" |
        sed 's/^ccf-//; s/\.tar\.gz$//' | sort -u || true
}

check_consistency() {
    local pinned status=0 found
    pinned=$(version_in_dockerfile)
    if [ -z "${pinned}" ]; then
        echo "FAIL  could not read ARG CCF_VERSION from docker/Dockerfile" >&2
        return 1
    fi
    echo "docker/Dockerfile pins CCF ${pinned}"

    local -a names=(
        ".devcontainer/Dockerfile"
        "scripts/setup-env.sh"
        "build.sh"
    )
    local -a readers=(
        version_in_devcontainer
        version_in_setup_env
        version_in_build_sh
    )
    local i
    for i in "${!names[@]}"; do
        found=$("${readers[$i]}")
        if [ -z "${found}" ]; then
            echo "FAIL  ${names[$i]}: could not read a CCF version"
            status=1
        elif [ "${found}" != "${pinned}" ]; then
            echo "FAIL  ${names[$i]}: pins ${found}, expected ${pinned}"
            status=1
        else
            echo "ok    ${names[$i]}"
        fi
    done

    # The docs walk through installing CCF from source, so every reference has
    # to name the release the image is built against.
    local md
    md=$(versions_in_development_md)
    if [ -z "${md}" ]; then
        echo "FAIL  DEVELOPMENT.md: no ccf-<version> reference found"
        status=1
    elif [ "${md}" != "${pinned}" ]; then
        echo "FAIL  DEVELOPMENT.md: refers to $(echo "${md}" | tr '\n' ' ')expected only ${pinned}"
        status=1
    else
        echo "ok    DEVELOPMENT.md"
    fi

    if [ "${status}" -ne 0 ]; then
        echo "Update the files above so they all name the same CCF release." >&2
    fi
    return "${status}"
}

main() {
    if [ "$#" -gt 0 ]; then
        case "$1" in
            -h | --help)
                usage
                exit 0
                ;;
            *)
                echo "Unexpected argument: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
    fi

    check_consistency
}

main "$@"
