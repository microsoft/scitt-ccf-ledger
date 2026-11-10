#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Maintain a rolling history of benchmark results (bencher.json files) in a
# GitHub Actions artifact. Requires gh, GH_TOKEN and GITHUB_REPOSITORY.
#
#   perf-history.sh restore <artifact> <dir>
#       Copy the results from the latest unexpired <artifact> into <dir>.
#   perf-history.sh add <results.json> <dir>
#       Add results, if present, to <dir> as
#       <run_id>-<run_number>-<run_attempt>.json.
#   perf-history.sh trim <dir> <count>
#       Keep only the newest <count> results in <dir>.

set -euo pipefail

restore() {
    local artifact=$1 dir=$2
    mkdir -p "$dir"
    local run_ids
    run_ids=$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${artifact}&per_page=100" \
        --jq '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | reverse | .[0:20] | .[].workflow_run.id')
    local tmp
    tmp=$(mktemp -d)
    for run_id in $run_ids; do
        if gh run download "$run_id" -R "$GITHUB_REPOSITORY" --name "$artifact" --dir "$tmp"; then
            find "$tmp" -name '*.json' -exec cp {} "$dir/" \;
            break
        fi
    done
    rm -rf "$tmp"
}

add() {
    local results=$1 dir=$2
    mkdir -p "$dir"
    if [[ -f "$results" ]]; then
        cp "$results" "$dir/${GITHUB_RUN_ID}-${GITHUB_RUN_NUMBER}-${GITHUB_RUN_ATTEMPT}.json"
    else
        echo "No results found at $results"
    fi
}

trim() {
    local dir=$1 count=$2
    (cd "$dir" && ls -1 | sort -t- -k1,1n -k2,2n -k3,3n | head -n -"$count" | xargs -r rm -f)
}

command=${1:-}
shift || true
case "$command" in
    restore) restore "$@" ;;
    add) add "$@" ;;
    trim) trim "$@" ;;
    *)
        echo "Usage: $0 {restore <artifact> <dir>|add <results.json> <dir>|trim <dir> <count>}" >&2
        exit 1
        ;;
esac
