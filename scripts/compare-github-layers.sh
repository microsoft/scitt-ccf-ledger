#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Compare locally built filesystem layers with the layers GitHub Actions built
# for the same commit.
#
# The comparison is keyed on the commit that was built rather than on the pull
# request head. GitHub builds refs/pull/N/merge, a commit it regenerates
# whenever the head or the target branch moves, and the build inputs derive
# from it. Looking up the status for the commit this build used means the two
# systems are only ever compared when they built the same source, so a moving
# target branch reports "no record" instead of a spurious difference.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/compare-github-layers.sh <layers-file> <commit> [context-sha256]

Arguments:
  layers-file     Locally produced layer digests, one per line, as written by
                  compare-image-layers.py --output-layers.
  commit          The commit that was built, as recorded in build-metadata.json
                  or reproduce.json. Not the pull request head.
  context-sha256  Optional. The build context digest this build used. When
                  given it is compared too, which distinguishes "the two
                  systems built different sources" from "the two systems built
                  the same source differently".

Exit status:
  0  The records match, or GitHub published no record to compare with.
  1  The records differ, or the local layer file is unusable.

Environment:
  SCITT_STATUS_REPO      Repository to read the commit status from. Defaults
                         to microsoft/scitt-ccf-ledger.
  SCITT_STATUS_API       API root. Defaults to https://api.github.com.
  SCITT_STATUS_CONTEXT   Status context to look for. Defaults to
                         reproducibility/layers.
  SCITT_STATUS_TIMEOUT   Seconds to wait for GitHub to publish its record.
                         Defaults to 1200. Set to 0 to check once.
  SCITT_STATUS_INTERVAL  Seconds between polls. Defaults to 30.
EOF
}

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
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
commit="$2"
context_sha256="${3:-}"
status_repo="${SCITT_STATUS_REPO:-microsoft/scitt-ccf-ledger}"
status_api="${SCITT_STATUS_API:-https://api.github.com}"
status_context="${SCITT_STATUS_CONTEXT:-reproducibility/layers}"
status_timeout="${SCITT_STATUS_TIMEOUT:-1200}"
status_interval="${SCITT_STATUS_INTERVAL:-30}"

# Without curl this check cannot run at all. Reporting that as a skip would
# leave a pipeline that looks like it verifies something and never does, so
# fail on it: a missing tool is a deterministic environment defect, unlike the
# genuinely transient conditions handled further down.
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to read the record GitHub published." >&2
    exit 1
fi

if [ ! -s "${layers_file}" ]; then
    echo "Local layer digests are missing or empty: ${layers_file}" >&2
    exit 1
fi

if grep -qvE '^sha256:[0-9a-f]{64}$' "${layers_file}"; then
    echo "Local layer digests are not a plain list of sha256 digests:" >&2
    grep -nvE '^sha256:[0-9a-f]{64}$' "${layers_file}" >&2
    exit 1
fi

if ! printf '%s' "${commit}" | grep -qE '^[0-9a-f]{40}$'; then
    echo "Not a full commit hash: ${commit}" >&2
    exit 1
fi

# Hash the digests rather than the file so that trailing whitespace or a
# missing final newline cannot make two identical layer lists disagree. Both
# systems must derive this the same way; the workflow that publishes the
# status uses this same pipeline.
layers_digest=$(grep -E '^sha256:[0-9a-f]{64}$' "${layers_file}" |
    sha256sum |
    cut -d ' ' -f 1)

response=$(mktemp)
trap 'rm -f "${response}"' EXIT

url="${status_api}/repos/${status_repo}/commits/${commit}/status"
echo "Looking for the ${status_context} record GitHub published for ${commit}."

deadline=$(( $(date +%s) + status_timeout ))
reached_api=0
published=""

while true; do
    status=$(
        curl \
            --silent \
            --show-error \
            --location \
            --max-time 60 \
            --write-out '%{http_code}' \
            --output "${response}" \
            --header "Accept: application/vnd.github+json" \
            "${url}" 2>/dev/null || true
    )

    if [ "${status}" = "200" ]; then
        reached_api=1
        published=$(
            SCITT_STATUS_CONTEXT="${status_context}" python3 - "${response}" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

wanted = os.environ["SCITT_STATUS_CONTEXT"]
for entry in payload.get("statuses", []):
    if entry.get("context") == wanted:
        print(entry.get("state", ""), entry.get("description", ""), sep="\t")
        break
PY
        )
        if [ -n "${published}" ]; then
            break
        fi
    fi

    if [ "$(date +%s)" -ge "${deadline}" ]; then
        break
    fi

    sleep "${status_interval}"
done

if [ -z "${published}" ]; then
    if [ "${reached_api}" -eq 0 ]; then
        # Distinguished from "not published yet" because the two need opposite
        # responses: waiting longer fixes one and never fixes the other. A
        # build agent on an isolated network reaches this branch, and saying so
        # is what stops the check from looking like it passed.
        echo "Could not reach ${status_api} (last HTTP status '${status}')." >&2
        echo "The comparison against GitHub Actions was NOT performed. If this" >&2
        echo "persists, the agent cannot reach the API and this check is not" >&2
        echo "verifying anything." >&2
    else
        echo "GitHub published no ${status_context} record for ${commit} within" >&2
        echo "${status_timeout}s. Its build may still be running, may have been" >&2
        echo "superseded, or may never have built this commit." >&2
        echo "The comparison against GitHub Actions was NOT performed." >&2
    fi
    exit 0
fi

published_state=${published%%$'\t'*}
published_description=${published#*$'\t'}

if [ "${published_state}" != "success" ]; then
    # GitHub reporting its own failure is not this pipeline's to report again,
    # and its layer list would describe a build that did not pass its own gate.
    echo "GitHub recorded state '${published_state}' for ${commit}, so there is"
    echo "no verified layer list to compare with. The comparison against"
    echo "GitHub Actions was NOT performed."
    exit 0
fi

published_layers=$(printf '%s' "${published_description}" |
    sed -n 's/.*\bL:\([0-9a-f]\{64\}\).*/\1/p')
published_context=$(printf '%s' "${published_description}" |
    sed -n 's/.*\bC:\([0-9a-f]\{64\}\).*/\1/p')

if [ -z "${published_layers}" ]; then
    echo "The ${status_context} record for ${commit} is not in the expected" >&2
    echo "form, so it cannot be compared: ${published_description}" >&2
    exit 1
fi

echo "Layer digest GitHub recorded: ${published_layers}"
echo "Layer digest this build produced: ${layers_digest}"

if [ -n "${context_sha256}" ] && [ -n "${published_context}" ]; then
    echo "Build context GitHub recorded: ${published_context}"
    echo "Build context this build used: ${context_sha256}"
    if [ "${published_context}" != "${context_sha256}" ]; then
        echo "The two build systems did not build the same context for" >&2
        echo "${commit}, so their layers are not comparable. Compare the" >&2
        echo "recorded context_sha256 values: an identical commit must produce" >&2
        echo "an identical context." >&2
        exit 1
    fi
fi

if [ "${published_layers}" != "${layers_digest}" ]; then
    echo "This build does not reproduce the layers GitHub Actions built for" >&2
    echo "${commit}." >&2
    echo "Layers produced here:" >&2
    cat "${layers_file}" >&2
    echo >&2
    echo "The two build systems no longer agree. Compare the recorded build" >&2
    echo "inputs in reproduce.json, starting with docker_version and" >&2
    echo "buildx_version." >&2
    exit 1
fi

echo "This build reproduces the layers GitHub Actions built for ${commit}."
