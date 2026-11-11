#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Maintain a rolling history of benchmark results (bencher.json files) in a
# GitHub Actions artifact. Requires gh, GH_TOKEN and GITHUB_REPOSITORY.
#
#   perf-history.sh restore <artifact> <dir> <workflow> <head-repo> <head-branch>
#       Copy the results from the latest unexpired <artifact> into <dir>,
#       only accepting artifacts produced by .github/workflows/<workflow> for
#       <head-branch> of <head-repo>. Artifact names are not unique across
#       runs, so any run, including one for a fork pull request, can upload an
#       artifact with the same name. Fails if a matching artifact exists but
#       cannot be downloaded, rather than silently starting a new history.
#   perf-history.sh add <results.json> <dir>
#       Add results, if present, to <dir> as
#       <run_id>-<run_number>-<run_attempt>.json.
#   perf-history.sh trim <dir> <count>
#       Keep only the newest <count> results in <dir>.

set -euo pipefail

restore() {
    local artifact=$1 dir=$2 workflow=$3 head_repo=$4 head_branch=$5
    mkdir -p "$dir"
    local run_ids
    run_ids=$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${artifact}&per_page=100" \
        --jq '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | reverse | .[0:20] | .[].workflow_run.id')
    local matches=0 run_id run path repo branch tmp
    for run_id in $run_ids; do
        run=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}" \
            --jq '[.path, .head_repository.full_name, .head_branch] | @tsv')
        IFS=$'\t' read -r path repo branch <<< "$run"
        if [[ "$path" != ".github/workflows/${workflow}" || "$repo" != "$head_repo" || "$branch" != "$head_branch" ]]; then
            echo "Ignoring $artifact from run $run_id ($path, $repo:$branch)"
            continue
        fi
        matches=$((matches + 1))
        tmp=$(mktemp -d)
        if gh run download "$run_id" -R "$GITHUB_REPOSITORY" --name "$artifact" --dir "$tmp"; then
            find "$tmp" -name '*.json' -exec cp {} "$dir/" \;
            rm -rf "$tmp"
            return 0
        fi
        rm -rf "$tmp"
    done
    if ((matches > 0)); then
        echo "Found $matches matching $artifact artifact(s), but could not download any" >&2
        return 1
    fi
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
        echo "Usage: $0 {restore <artifact> <dir> <workflow> <head-repo> <head-branch>|add <results.json> <dir>|trim <dir> <count>}" >&2
        exit 1
        ;;
esac
