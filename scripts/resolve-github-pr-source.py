# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Resolve a PR merge to the immutable source GitHub verified for its parents."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, stdout=subprocess.PIPE, text=True
    ).stdout.strip()


def resolve_source(
    merge: str, api: str, repository: str, timeout: int, interval: int
) -> str:
    parents = git("show", "-s", "--format=%P", merge).split()
    if len(parents) != 2:
        raise ValueError(f"Expected a two-parent PR merge commit, got {merge}")
    base, head = parents
    context = f"reproducibility/merge/{base}"
    url = f"{api}/repos/{repository}/commits/{head}/status?per_page=100"
    deadline = time.monotonic() + timeout
    print(
        f"Waiting for GitHub's verified merge of {head} into {base}.", file=sys.stderr
    )

    while True:
        request = Request(url, headers={"Accept": "application/vnd.github+json"})
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
        if not isinstance(payload, dict) or not isinstance(
            payload.get("statuses"), list
        ):
            raise ValueError("GitHub returned an invalid commit status response")
        for entry in payload["statuses"]:
            if not isinstance(entry, dict):
                raise ValueError("GitHub returned an invalid commit status entry")
            if entry.get("context") != context:
                continue
            if entry.get("state") != "success":
                raise ValueError(f"GitHub has not verified this merge: {entry}")
            description = entry.get("description")
            match = (
                re.fullmatch(r"M:([0-9a-f]{40})", description)
                if isinstance(description, str)
                else None
            )
            if match is None:
                raise ValueError(f"Invalid verified merge record: {entry}")
            selected = match.group(1)
            exists = subprocess.run(
                ["git", "cat-file", "-e", f"{selected}^{{commit}}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if exists.returncode != 0:
                git("fetch", "--no-tags", "origin", selected)
            if git("show", "-s", "--format=%P", selected).split() != parents:
                raise ValueError("GitHub's verified merge has different PR parents")
            if git("rev-parse", f"{selected}^{{tree}}") != git(
                "rev-parse", f"{merge}^{{tree}}"
            ):
                raise ValueError("GitHub's verified merge has a different source tree")
            print(f"Using GitHub's verified merge {selected}.", file=sys.stderr)
            return selected

        if time.monotonic() >= deadline:
            raise ValueError(
                f"No verified merge record for head {head} and base {base} within "
                f"{timeout}s. Check the Docker reproducibility workflow; no source "
                "was selected."
            )
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("merge", help="The checked-out PR merge commit")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.merge) is None:
        parser.error("merge must be a full commit hash")
    try:
        timeout = int(os.environ.get("SCITT_STATUS_TIMEOUT", "1200"))
        interval = int(os.environ.get("SCITT_STATUS_INTERVAL", "30"))
        if timeout < 0 or interval < 0:
            raise ValueError("Status timeout and interval must be non-negative")
        print(
            resolve_source(
                args.merge,
                os.environ.get("SCITT_STATUS_API", "https://api.github.com"),
                os.environ.get("SCITT_STATUS_REPO", "microsoft/scitt-ccf-ledger"),
                timeout,
                interval,
            )
        )
    except (ValueError, URLError, TimeoutError, subprocess.CalledProcessError) as error:
        sys.exit(f"Could not select GitHub's verified PR source: {error}")


if __name__ == "__main__":
    main()
