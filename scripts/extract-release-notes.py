# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import os
import re
import subprocess
import sys

version_header = re.compile(r"## \[(.+)\]")
link_definition = re.compile(r"\[(.+)\]:")


def list_git_tags():
    git_tags = list()
    try:
        # versionsort.suffix makes sure to put prerelease versions before the actual version
        # --sort=-version:refname sorts tags by semver
        git_tags_output = subprocess.run(
            [
                "git",
                "-c",
                "versionsort.suffix=-dev",
                "-c",
                "versionsort.suffix=-pre",
                "tag",
                "--sort=-version:refname",
            ],
            capture_output=True,
            universal_newlines=True,
            check=True,
        ).stdout.strip()
        if git_tags_output:
            git_tags = git_tags_output.split("\n")
    except subprocess.CalledProcessError:
        print("Warning: Could not retrieve git tags")
    return git_tags


def doc_versions_and_links(filename):
    documented_versions = set()
    links_found = set()
    with open(filename) as f:
        while line := f.readline():
            if match := version_header.match(line):
                log_version = match.group(1)
                documented_versions.add(log_version)
            elif match := link_definition.match(line):
                link_version = match.group(1)
                links_found.add(link_version)
    return documented_versions, links_found


def add_missing_tags(filename, git_tags):
    print("Adding missing git tags for undocumented versions")
    next_unchecked_tag_idx = 0
    with open(f"{filename}.tmp", "w") as newer:
        with open(filename) as f:
            while line := f.readline():
                if match := version_header.match(line):
                    log_version = match.group(1)
                    all_prev_exists = False
                    if next_unchecked_tag_idx < len(git_tags):
                        for idx, tag in enumerate(git_tags):
                            if idx < next_unchecked_tag_idx:
                                continue
                            if tag != log_version and not (all_prev_exists):
                                next_unchecked_tag_idx = idx + 1
                                newer.write(f"## [{tag}]\n")
                                older_tag = git_tags[idx + 1]
                                try:
                                    log_output = subprocess.run(
                                        [
                                            "git",
                                            "log",
                                            "--oneline",
                                            f"{older_tag}..{tag}",
                                        ],
                                        capture_output=True,
                                        universal_newlines=True,
                                        check=True,
                                    ).stdout.strip()
                                    if log_output:
                                        newer.write(f"### Changes\n")
                                        for change in log_output.split("\n"):
                                            newer.write(f"- {change}\n")
                                        newer.write("\n")
                                except subprocess.CalledProcessError:
                                    print(
                                        f"Warning: Could not get git log between versions {older_tag} and {tag}"
                                    )

                            elif tag == log_version:
                                next_unchecked_tag_idx = idx + 1
                                all_prev_exists = True
                            else:
                                break

                newer.write(line)

    os.replace(f"{filename}.tmp", filename)


def main():
    parser = argparse.ArgumentParser(
        description="Parses a CHANGELOG file and checks it meets some formatting expectations. "
        "Will also extract release notes for targeted versions."
    )
    parser.add_argument(
        "--changelog", help="Path to CHANGELOG file to parse", default="CHANGELOG.md"
    )
    parser.add_argument(
        "--fix",
        help="Fix any automatically correctable errors",
        action="store_true",
    )
    parser.add_argument(
        "--describe-path-changes",
        help="If true, add a note whenever the given path has changes between releases.",
        action="append",
        default=[],
    )
    args = parser.parse_args()

    git_tags = list_git_tags()
    documented_versions, links_found = doc_versions_and_links(args.changelog)

    # Check for missing git tags in changelog, respect the order
    undocumented_versions = list()
    for tag in git_tags:
        if tag not in documented_versions:
            undocumented_versions.append(tag)

    if len(undocumented_versions) > 0:
        print("Undocumented versions (missing git tags) in changelog:")
        for tag in undocumented_versions:
            print(f"  {tag}")

        if args.fix:
            add_missing_tags(args.changelog, git_tags)
            # reevaluate updated changelog
            documented_versions, links_found = doc_versions_and_links(args.changelog)
        else:
            print(
                "Run with --fix to automatically add missing git tags to the changelog."
            )
            sys.exit(1)

    # Check that each documented version has a link
    versions_without_links = documented_versions - links_found
    if len(versions_without_links) > 0:
        print("Missing links for following versions:")
        for version in versions_without_links:
            print(f"  {version}")

    # If there were any problems, try to fix them and exit
    if len(versions_without_links) > 0:
        if args.fix:
            print("Adding missing links for versioned releases")
            with open(args.changelog, "a") as f:
                for version in versions_without_links:
                    # Append presumed link
                    f.write(
                        f"[{version}]: https://github.com/microsoft/scitt-ccf-ledger/releases/tag/{version}\n"
                    )
        else:
            print("Run with --fix to automatically add missing links to the changelog.")
            sys.exit(1)

    print("CHANGELOG is valid!")


if __name__ == "__main__":
    main()
