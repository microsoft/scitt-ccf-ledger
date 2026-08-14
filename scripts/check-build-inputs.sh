#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Check that every network input a reproducible rebuild depends on is still
# available, and still has the content it was pinned to.
#
# The per-commit and historical reproducibility gates only run when a build
# runs. This probe is deliberately cheap so it can run on a schedule and fail
# in the week an input is withdrawn or silently mutated, while updating the pin
# is still straightforward. Losing any of these inputs makes published images
# impossible to rebuild, which is the failure mode that is hardest to recover
# from years later.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/check-build-inputs.sh [options]

Options:
  --verify-checksums  Download the large pinned artifacts in full and verify
                      their SHA-256, instead of only checking availability.
  --json <file>       Write a machine readable report to <file>.
  -h, --help          Show this help.

Exit status is non-zero when any required input is missing or has changed.

Environment:
  GITHUB_TOKEN  Used for GitHub API requests when set, to avoid the low
                unauthenticated rate limit.
EOF
}

VERIFY_CHECKSUMS=0
JSON_OUTPUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --verify-checksums) VERIFY_CHECKSUMS=1 ;;
        --json)
            shift
            JSON_OUTPUT="${1:-}"
            if [ -z "${JSON_OUTPUT}" ]; then
                echo "--json requires a file path" >&2
                exit 1
            fi
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
    shift
done

root=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "${root}" ]; then
    root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fi
dockerfile="${root}/docker/Dockerfile"
cmakelists="${root}/app/CMakeLists.txt"

RESULTS=()
FAILURES=0

# Records one probe result. Status is ok, failed or skipped; only failed
# affects the exit status, so informational probes cannot break the build.
record() {
    local status="$1" name="$2" detail="$3"
    RESULTS+=("${status}|${name}|${detail}")
    case "${status}" in
        ok) printf '  ok       %s\n' "${name}" ;;
        skipped) printf '  skipped  %s (%s)\n' "${name}" "${detail}" ;;
        *)
            printf '  FAILED   %s (%s)\n' "${name}" "${detail}"
            FAILURES=$((FAILURES + 1))
            ;;
    esac
}

http_status() {
    curl \
        --silent \
        --show-error \
        --location \
        --output /dev/null \
        --max-time 60 \
        --retry 3 \
        --retry-delay 2 \
        --write-out '%{http_code}' \
        "$@" || true
}

dockerfile_arg() {
    sed -n "s/^ARG $1=\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "${dockerfile}" | head -n1
}

# Resolves a tag to the digest the registry currently serves for it, by reading
# the Docker-Content-Digest response header.
registry_tag_digest() {
    local registry="$1" path="$2" tag="$3"
    curl \
        --silent \
        --show-error \
        --location \
        --head \
        --max-time 60 \
        --retry 3 \
        --retry-delay 2 \
        --header 'Accept: application/vnd.oci.image.index.v1+json' \
        --header 'Accept: application/vnd.oci.image.manifest.v1+json' \
        --header 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
        --header 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
        "https://${registry}/v2/${path}/manifests/${tag}" 2>/dev/null |
        tr -d '\r' |
        sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p' |
        tail -n1
}

# A range request avoids downloading multi-hundred-megabyte artifacts just to
# learn whether they still exist. Servers may answer 200 or 206.
probe_url() {
    local name="$1" url="$2" code
    code=$(http_status --range 0-0 "${url}")
    case "${code}" in
        200 | 206) record ok "${name}" "${url}" ;;
        *) record failed "${name}" "HTTP ${code} for ${url}" ;;
    esac
}

echo "Pinned inputs from ${dockerfile#"${root}"/} and ${cmakelists#"${root}"/}"

ccf_version=$(dockerfile_arg CCF_VERSION)
ccf_rpm_sha256=$(dockerfile_arg CCF_RPM_SHA256)
ccf_reproduce_sha256=$(dockerfile_arg CCF_REPRODUCE_SHA256)
tdnf_snapshottime=$(dockerfile_arg TDNF_SNAPSHOTTIME)
base_ref=$(sed -n 's/^FROM \([^ ]*\) AS base[[:space:]]*$/\1/p' "${dockerfile}" | head -n1)

if [ -z "${ccf_version}" ] || [ -z "${base_ref}" ]; then
    echo "Could not read the pinned inputs from ${dockerfile}" >&2
    exit 1
fi

base_repo="${base_ref%%@*}"
base_repo="${base_repo%%:*}"
base_digest="${base_ref##*@}"
base_registry="${base_repo%%/*}"
base_path="${base_repo#*/}"

# The tag is only a label once a digest is present, but a tag that no longer
# resolves to the pinned digest means the two disagree about which image the
# build uses. Dependabot bumps the tag, so a merge that keeps a stale digest
# would otherwise build the old base image under a new tag, undetected.
base_tag=""
base_name_tag="${base_ref%%@*}"
case "${base_name_tag##*/}" in
    *:*) base_tag="${base_name_tag##*:}" ;;
esac

echo
echo "Base image"
if [ "${base_ref}" = "${base_digest}" ]; then
    record failed "base image is pinned by digest" "no digest in ${base_ref}"
elif [ "${base_registry}" != "mcr.microsoft.com" ]; then
    # Other registries need a token exchange this probe does not implement.
    record skipped "base image manifest" "unsupported registry ${base_registry}"
else
    code=$(http_status \
        --header 'Accept: application/vnd.oci.image.index.v1+json' \
        --header 'Accept: application/vnd.oci.image.manifest.v1+json' \
        --header 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
        --header 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
        "https://${base_registry}/v2/${base_path}/manifests/${base_digest}")
    if [ "${code}" = "200" ]; then
        record ok "base image manifest ${base_digest}" "${base_ref}"
    else
        record failed "base image manifest ${base_digest}" "HTTP ${code}"
    fi

    if [ -z "${base_tag}" ]; then
        record skipped "base image tag matches digest" "no tag in ${base_ref}"
    else
        tag_digest=$(registry_tag_digest "${base_registry}" "${base_path}" "${base_tag}")
        if [ -z "${tag_digest}" ]; then
            record failed "base image tag matches digest" "could not resolve tag ${base_tag}"
        elif [ "${tag_digest}" = "${base_digest}" ]; then
            record ok "base image tag ${base_tag} matches digest" "${base_digest}"
        else
            record failed "base image tag ${base_tag} matches digest" \
                "tag resolves to ${tag_digest} but the pin says ${base_digest}"
        fi
    fi
fi

echo
echo "CCF ${ccf_version} release assets"
ccf_base="https://github.com/microsoft/CCF/releases/download/ccf-${ccf_version}"
ccf_rpm="ccf_devel_${ccf_version//-/_}_x86_64.rpm"

# reproduce.json is small, so its checksum is always verified. It is also the
# file the Dockerfile derives the package snapshot from, so a silent change
# here would change every installed package version.
reproduce_json=$(mktemp)
trap 'rm -f "${reproduce_json}"' EXIT
if curl --silent --show-error --location --max-time 60 --retry 3 \
        --output "${reproduce_json}" "${ccf_base}/reproduce.json"; then
    actual=$(sha256sum "${reproduce_json}" | cut -d ' ' -f 1)
    if [ "${actual}" = "${ccf_reproduce_sha256}" ]; then
        record ok "CCF reproduce.json checksum" "${actual}"
    else
        record failed "CCF reproduce.json checksum" \
            "pinned ${ccf_reproduce_sha256}, found ${actual}"
    fi

    published=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tdnf_snapshottime"])' \
        "${reproduce_json}" 2>/dev/null || echo "unreadable")
    if [ "${published}" = "${tdnf_snapshottime}" ]; then
        record ok "CCF tdnf snapshot time" "${published}"
    else
        record failed "CCF tdnf snapshot time" \
            "pinned ${tdnf_snapshottime}, published ${published}"
    fi
else
    record failed "CCF reproduce.json" "download failed from ${ccf_base}"
fi

if [ "${VERIFY_CHECKSUMS}" = "1" ]; then
    rpm_file=$(mktemp)
    if curl --silent --show-error --location --max-time 900 --retry 3 \
            --output "${rpm_file}" "${ccf_base}/${ccf_rpm}"; then
        actual=$(sha256sum "${rpm_file}" | cut -d ' ' -f 1)
        if [ "${actual}" = "${ccf_rpm_sha256}" ]; then
            record ok "CCF devel RPM checksum" "${actual}"
        else
            record failed "CCF devel RPM checksum" \
                "pinned ${ccf_rpm_sha256}, found ${actual}"
        fi
    else
        record failed "CCF devel RPM" "download failed"
    fi
    rm -f "${rpm_file}"
else
    probe_url "CCF devel RPM" "${ccf_base}/${ccf_rpm}"
fi

echo
echo "Azure Linux package snapshot ${tdnf_snapshottime}"
# The snapshot time selects package versions from these repositories. It can
# only be honoured while the repositories still serve the metadata.
for repo in base ms-oss ms-non-oss extended; do
    probe_url "packages.microsoft.com azurelinux 3.0 ${repo}" \
        "https://packages.microsoft.com/azurelinux/3.0/prod/${repo}/x86_64/repodata/repomd.xml"
done

echo
echo "Pinned source dependencies"
gh_auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
    gh_auth=(--header "Authorization: Bearer ${GITHUB_TOKEN}")
fi

# CMake FetchContent pins each dependency to a commit. A commit stays fetchable
# only while the repository exists and has not been rewritten.
while IFS='|' read -r repo_url commit; do
    [ -n "${repo_url}" ] || continue
    slug="${repo_url#https://github.com/}"
    slug="${slug%.git}"
    code=$(http_status "${gh_auth[@]}" "https://api.github.com/repos/${slug}/commits/${commit}")
    case "${code}" in
        200) record ok "${slug}@${commit}" "reachable" ;;
        403 | 429) record skipped "${slug}@${commit}" "GitHub API rate limited (HTTP ${code})" ;;
        *) record failed "${slug}@${commit}" "HTTP ${code}" ;;
    esac
done < <(awk '
    /GIT_REPOSITORY/ { url = $2 }
    /GIT_TAG/ && url != "" { print url "|" $2; url = "" }
' "${cmakelists}")

if [ -n "${JSON_OUTPUT}" ]; then
    mkdir -p "$(dirname "${JSON_OUTPUT}")"
    printf '%s\n' "${RESULTS[@]}" | python3 -c '
import json
import sys

checks = []
for line in sys.stdin.read().splitlines():
    if not line:
        continue
    status, name, detail = line.split("|", 2)
    checks.append({"status": status, "name": name, "detail": detail})

report = {
    "schema_version": 1,
    "failed": sum(1 for c in checks if c["status"] == "failed"),
    "checks": checks,
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
' "${JSON_OUTPUT}"
    echo
    echo "Wrote ${JSON_OUTPUT}"
fi

echo
if [ "${FAILURES}" -gt 0 ]; then
    echo "${FAILURES} pinned build input(s) are unavailable or have changed." >&2
    echo "Published images that depend on them can no longer be rebuilt as published." >&2
    exit 1
fi

echo "All pinned build inputs are still available and unchanged."
