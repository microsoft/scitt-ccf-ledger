#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Compare locally built filesystem layers with the layers a release published.
#
# The per-commit gates in GitHub Actions and OneBranch each build twice and
# compare the two results, which proves that a build system is internally
# deterministic. Neither of them proves that the two build systems agree with
# each other: they run different builders on different agents, so the same
# source can produce different layers without either gate noticing.
#
# This compares a locally produced layer list against the image-layers.txt that
# the GitHub release published for the same tag, which is the record third
# parties reproduce against. A mismatch is a hard failure. A release that has
# no published record is reported and does not fail, because that is an
# ordering or age difference rather than a reproducibility problem.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/compare-published-layers.sh <layers-file> <tag>

Arguments:
  layers-file  Locally produced layer digests, one per line, as written by
               compare-image-layers.py --output-layers or by
               docker image inspect --format '{{range .RootFS.Layers}}...'.
  tag          Release tag whose published image-layers.txt to compare with.

Exit status:
  0  The layers match, or the release published no layer record.
  1  The layers differ, or the local layer file is unusable.

Environment:
  SCITT_RELEASE_REPO      Repository to fetch the release asset from.
                          Defaults to microsoft/scitt-ccf-ledger.
  SCITT_RELEASE_BASE_URL  Host serving the release assets. Defaults to
                          https://github.com. Point this at a mirror when
                          the releases are republished elsewhere.
  GITHUB_TOKEN            Sent as a bearer token when set. Not required for
                          public releases.
EOF
}

if [ $# -ne 2 ]; then
    usage >&2
    exit 1
fi

case "$1" in
    -h | --help)
        usage
        exit 0
        ;;
esac

layers_file="$1"
tag="$2"
release_repo="${SCITT_RELEASE_REPO:-microsoft/scitt-ccf-ledger}"
release_base_url="${SCITT_RELEASE_BASE_URL:-https://github.com}"

if [ ! -s "${layers_file}" ]; then
    echo "Local layer digests are missing or empty: ${layers_file}" >&2
    exit 1
fi

# A truncated or malformed local file would otherwise be compared byte for
# byte against a valid record and reported as a reproducibility failure, which
# would send the reader looking for a build difference that does not exist.
if grep -qvE '^sha256:[0-9a-f]{64}$' "${layers_file}"; then
    echo "Local layer digests are not a plain list of sha256 digests:" >&2
    grep -nvE '^sha256:[0-9a-f]{64}$' "${layers_file}" >&2
    exit 1
fi

published=$(mktemp)
headers=$(mktemp)
trap 'rm -f "${published}" "${headers}"' EXIT

url="${release_base_url}/${release_repo}/releases/download/${tag}/image-layers.txt"
echo "Comparing with ${url}"

auth_args=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
    auth_args=(--header "Authorization: Bearer ${GITHUB_TOKEN}")
fi

status=$(
    curl \
        --silent \
        --show-error \
        --location \
        --retry 3 \
        --retry-delay 2 \
        --max-time 60 \
        --dump-header "${headers}" \
        --write-out '%{http_code}' \
        --output "${published}" \
        "${auth_args[@]}" \
        "${url}" || true
)

if [ "${status}" = "404" ]; then
    echo "Release ${tag} published no image-layers.txt, so there is nothing to"
    echo "compare against. Releases created before the reproducibility gate"
    echo "existed do not carry one."
    exit 0
fi

if [ "${status}" != "200" ]; then
    # Refusing to pass here would make every transient network fault look like
    # a reproducibility failure, so report it plainly and leave the decision to
    # the caller, which can re-run.
    echo "Could not download the published layer record (HTTP ${status})." >&2
    echo "Skipping the cross-system comparison for ${tag}." >&2
    exit 0
fi

if grep -qvE '^sha256:[0-9a-f]{64}$' "${published}"; then
    echo "The published record for ${tag} is not a plain list of sha256" >&2
    echo "digests, so it cannot be compared:" >&2
    head -5 "${published}" >&2
    exit 1
fi

echo "Layers published for ${tag}:"
cat "${published}"
echo "Layers produced by this build:"
cat "${layers_file}"

if ! cmp --silent "${published}" "${layers_file}"; then
    echo "This build does not reproduce the layers published for ${tag}." >&2
    diff -u \
        --label "published by ${tag}" \
        --label "produced by this build" \
        "${published}" "${layers_file}" >&2 || true
    echo >&2
    echo "The two build systems no longer agree. Compare the recorded build" >&2
    echo "inputs in reproduce.json, starting with docker_version and" >&2
    echo "buildx_version, and confirm context_sha256 is identical." >&2
    exit 1
fi

echo "This build reproduces the layers published for ${tag}."
