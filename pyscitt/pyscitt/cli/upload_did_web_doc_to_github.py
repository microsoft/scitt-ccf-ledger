# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

DID_WEB_PREFIX = "did:web:"
GITHUB_IO_SUFFIX = ".github.io"
DID_FILENAME = "did.json"
WELLKNOWN_DIR = ".well-known"


def run(*args):
    print(" ".join(args))
    subprocess.run(args)


def upload_did_web_doc_to_github(did_path: Path):
    did_path = did_path.resolve()
    with open(did_path) as f:
        doc = json.load(f)
    did = doc["id"]
    assert did.startswith(DID_WEB_PREFIX), f"DID must start with {DID_WEB_PREFIX}"
    domain = did.replace(DID_WEB_PREFIX, "")
    assert domain.endswith(
        GITHUB_IO_SUFFIX
    ), f"did:web domain must end with {GITHUB_IO_SUFFIX}"
    gh_user = domain.replace(GITHUB_IO_SUFFIX, "")
    repo_url = f"https://github.com/{gh_user}/{domain}"

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = os.path.join(tmpdir, domain)
        run("git", "clone", repo_url, repo_path)
        os.chdir(repo_path)
        os.makedirs(WELLKNOWN_DIR, exist_ok=True)
        did_repo_path = os.path.join(WELLKNOWN_DIR, DID_FILENAME)
        shutil.copyfile(did_path, did_repo_path)
        # Adding .nojekyll allows a fresh GitHub pages site to serve files.
        Path(".nojekyll").touch()
        run("git", "add", ".nojekyll", did_repo_path)
        run("git", "commit", "-m", f"update {did_repo_path}")
        run("git", "push")


def cli(fn):
    parser = fn(
        description="Upload a DID document for did:web:user.github.io to "
        "an existing user/user.github.io GitHub repository"
    )
    parser.add_argument("path", type=Path, help="Path to did.json file")

    def cmd(args):
        upload_did_web_doc_to_github(args.path)

    parser.set_defaults(func=cmd)

    return parser


if __name__ == "__main__":
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args()
    args.func(args)
