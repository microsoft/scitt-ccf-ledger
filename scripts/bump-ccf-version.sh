#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Move the pinned CCF release in one step.
#
# The version is repeated in the Dockerfile, the devcontainer, the environment
# setup script, the build script and the docs. Updating those by hand is how
# the devcontainer ends up on a different CCF release than the image, which
# then reproduces differently for no visible reason.
#
# The Dockerfile derives everything else from the version: it reads the tdnf
# snapshot time out of the release's reproduce.json rather than repeating it.
# So this only has to keep one value consistent, and confirm the release it
# points at actually carries what a build needs.

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dockerfile="${root}/docker/Dockerfile"
devcontainer="${root}/.devcontainer/Dockerfile"
setup_env="${root}/scripts/setup-env.sh"
build_sh="${root}/build.sh"
development_md="${root}/DEVELOPMENT.md"

# The trap runs once main has returned, so the directory it removes cannot be
# scoped to main.
work=""
cleanup() {
    if [ -n "${work}" ]; then
        rm -rf "${work}"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage:
  scripts/bump-ccf-version.sh <version>
  scripts/bump-ccf-version.sh --check

  <version>   CCF release to move to, without the 'ccf-' prefix (e.g. 7.0.12).
  --check     Verify every file agrees on the pinned CCF version. Needs no
              network, so it is safe to run on every CI job.
EOF
}

# Reading each site through a named function keeps --check and the post-bump
# verification on exactly the same code path, so the check cannot drift away
# from what the bump writes.
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

versions_in_development_md() {
    grep -o 'ccf-[0-9][0-9A-Za-z.-]*' "${development_md}" |
        sed 's/^ccf-//; s/\.tar\.gz$//' | sort -u
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
            echo "FAIL  ${names[$i]}: could not read a CCF version" >&2
            status=1
        elif [ "${found}" != "${pinned}" ]; then
            echo "FAIL  ${names[$i]}: pins ${found}, expected ${pinned}" >&2
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
        echo "FAIL  DEVELOPMENT.md: no ccf-<version> reference found" >&2
        status=1
    elif [ "${md}" != "${pinned}" ]; then
        echo "FAIL  DEVELOPMENT.md: refers to $(echo "${md}" | tr '\n' ' ')expected only ${pinned}" >&2
        status=1
    else
        echo "ok    DEVELOPMENT.md"
    fi

    return "${status}"
}

# Rewrites that silently match nothing are the standard way a bump script rots,
# so every edit states how many lines it expects to change and puts the file
# back if the count is wrong. sed edits in place because reading a file through
# a shell variable discards whether it ended in a newline, and two of these
# files disagree about that.
replace_exactly() {
    local file="$1" expected="$2" expr="$3" backup changed
    backup=$(mktemp)
    cp "${file}" "${backup}"
    sed -i "${expr}" "${file}"
    changed=$(diff "${backup}" "${file}" | grep -c '^<' || true)
    if [ "${changed}" != "${expected}" ]; then
        cp "${backup}" "${file}"
        rm -f "${backup}"
        echo "Expected ${expected} line(s) to change in ${file#"${root}"/}, changed ${changed}." >&2
        echo "The file no longer matches what this script knows how to edit." >&2
        echo "That file was left alone; check 'git diff' for ones already updated." >&2
        exit 1
    fi
    rm -f "${backup}"
}

# Re-running against the version already pinned is a legitimate way to refresh
# checksums after a release is re-published, so a value that is already correct
# has to count as zero lines rather than a missed substitution.
lines_to_change() {
    if [ "$1" = "$2" ]; then
        echo 0
    else
        echo 1
    fi
}

set_arg() {
    local file="$1" arg="$2" new="$3" current
    current=$(sed -n "s/^ARG ${arg}=\"\(.*\)\"\$/\1/p" "${file}" | head -n1)
    if [ -z "${current}" ]; then
        echo "Could not find ARG ${arg} in ${file#"${root}"/}." >&2
        exit 1
    fi
    replace_exactly "${file}" "$(lines_to_change "${current}" "${new}")" \
        "s|^ARG ${arg}=\".*\"\$|ARG ${arg}=\"${new}\"|"
}

# Everything substituted below is interpolated into a sed expression, so a
# value carrying a delimiter or a backreference would rewrite these files in
# ways the line counts above would not catch.
require_format() {
    local name="$1" value="$2" pattern="$3"
    if ! printf '%s' "${value}" | grep -Eq "${pattern}"; then
        echo "${name} is not in the expected form: '${value}'" >&2
        exit 1
    fi
}

escape_for_sed() {
    printf '%s' "$1" | sed 's/[].[^$*\\/]/\\&/g'
}

main() {
    local version=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --check)
                check_consistency
                exit $?
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
            *)
                if [ -n "${version}" ]; then
                    echo "Only one version may be given." >&2
                    exit 1
                fi
                version="$1"
                ;;
        esac
        shift
    done

    if [ -z "${version}" ]; then
        usage >&2
        exit 1
    fi
    version="${version#ccf-}"
    require_format "The version" "${version}" '^[0-9][0-9A-Za-z.-]*$'

    local base="https://github.com/microsoft/CCF/releases/download/ccf-${version}"
    local rpm_name="ccf_devel_${version//-/_}_x86_64.rpm"
    work=$(mktemp -d)

    echo "Checking CCF ${version}"

    # The build reads the package snapshot straight out of this file, so a
    # release that does not publish a usable one cannot be built from at all.
    # Finding that out here beats finding it out inside a Docker stage.
    if ! curl --silent --show-error --fail --location --max-time 60 --retry 3 \
            --output "${work}/reproduce.json" "${base}/reproduce.json"; then
        echo "Could not download reproduce.json for ccf-${version}." >&2
        echo "Check that the release exists and publishes that asset." >&2
        exit 1
    fi

    local snapshottime
    snapshottime=$(python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1])).get("tdnf_snapshottime", ""))' \
        "${work}/reproduce.json" 2>/dev/null || echo "")
    if ! printf '%s' "${snapshottime}" | grep -Eq '^[0-9]+$'; then
        echo "reproduce.json for ccf-${version} has no usable tdnf_snapshottime," >&2
        echo "so the build could not select package versions from it." >&2
        exit 1
    fi

    # The other asset the build fetches. A range request is enough to show it
    # is there without pulling it down.
    local code
    code=$(curl --silent --show-error --location --max-time 60 --retry 3 \
        --range 0-0 --output /dev/null --write-out '%{http_code}' \
        "${base}/${rpm_name}" || echo "000")
    case "${code}" in
        200 | 206) ;;
        *)
            echo "${rpm_name} is not available from ccf-${version} (HTTP ${code})." >&2
            exit 1
            ;;
    esac

    echo "  reproduce.json     sha256 $(sha256sum "${work}/reproduce.json" | cut -d ' ' -f 1)"
    echo "  tdnf_snapshottime  ${snapshottime}"
    echo "  ${rpm_name} is available"
    echo

    local old_version version_lines
    old_version=$(version_in_dockerfile)
    version_lines=$(lines_to_change "${old_version}" "${version}")

    set_arg "${dockerfile}" CCF_VERSION "${version}"
    set_arg "${devcontainer}" CCF_VERSION "${version}"

    replace_exactly "${setup_env}" "${version_lines}" \
        "s|^CCF_VERSION=\${CCF_VERSION:-\".*\"}\$|CCF_VERSION=\${CCF_VERSION:-\"${version}\"}|"
    replace_exactly "${build_sh}" "${version_lines}" \
        "s|^\([[:space:]]*\)CCF_SOURCE_VERSION=\".*\"\$|\1CCF_SOURCE_VERSION=\"${version}\"|"

    # Matching the exact version already pinned, rather than a pattern for what
    # a version looks like, keeps the substitution from reaching into whatever
    # follows it. The docs reference a release tarball, and a looser pattern
    # swallows the .tar.gz on the end of the URL.
    local md_lines=0
    if [ "${old_version}" != "${version}" ]; then
        md_lines=$(grep -c "ccf-$(escape_for_sed "${old_version}")" "${development_md}" || true)
        if [ "${md_lines}" = "0" ]; then
            echo "DEVELOPMENT.md has no ccf-${old_version} reference to update." >&2
            exit 1
        fi
    fi
    replace_exactly "${development_md}" "${md_lines}" \
        "s|ccf-$(escape_for_sed "${old_version}")|ccf-${version}|g"

    echo "Updated:"
    echo "  docker/Dockerfile"
    echo "  .devcontainer/Dockerfile"
    echo "  scripts/setup-env.sh"
    echo "  build.sh"
    echo "  DEVELOPMENT.md"
    echo

    check_consistency
    echo
    echo "Now run scripts/check-build-inputs.sh to confirm the new pins resolve."
}

main "$@"
