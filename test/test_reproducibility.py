# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

RESOLVER = (
    Path(__file__).resolve().parents[1] / "scripts" / "resolve-github-pr-source.py"
)


def git(repo, *args, env=None):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo, tree, parents=(), timestamp=1700000000):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_AUTHOR_DATE": f"{timestamp} +0000",
        "GIT_COMMITTER_DATE": f"{timestamp} +0000",
    }
    parent_args = [arg for parent in parents for arg in ("-p", parent)]
    return git(repo, "commit-tree", tree, *parent_args, "-m", "Test commit", env=env)


@pytest.fixture
def source_repo(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "source.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", ".")
    base_tree = git(repo, "write-tree")
    base = commit(repo, base_tree)
    (repo / "source.txt").write_text("head\n", encoding="utf-8")
    git(repo, "add", ".")
    head_tree = git(repo, "write-tree")
    head = commit(repo, head_tree, [base])
    verified = commit(repo, head_tree, [base, head], timestamp=1700000030)
    checkout = commit(repo, head_tree, [base, head], timestamp=1700000032)
    git(repo, "update-ref", "refs/heads/main", checkout)
    return repo, base, head, verified, checkout


@pytest.fixture
def status_api():
    payload = {"statuses": []}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(payload.get("http_status", 200))
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", payload, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def mapping(base, verified, **overrides):
    return {
        "context": f"reproducibility/merge/{base}",
        "state": "success",
        "description": f"M:{verified}",
        **overrides,
    }


def resolve(repo, checkout, api):
    return subprocess.run(
        [sys.executable, str(RESOLVER), checkout],
        cwd=repo,
        env={
            **os.environ,
            "SCITT_STATUS_API": api,
            "SCITT_STATUS_TIMEOUT": "0",
            "SCITT_STATUS_INTERVAL": "0",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("regenerated", [False, True])
def test_resolve_verified_merge(source_repo, status_api, regenerated):
    repo, base, head, verified, checkout = source_repo
    api, payload, requests = status_api
    payload["statuses"] = [mapping(base, verified)]
    result = resolve(repo, checkout if regenerated else verified, api)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == verified
    assert requests == [
        f"/repos/microsoft/scitt-ccf-ledger/commits/{head}/status?per_page=100"
    ]
    assert checkout != verified
    assert git(repo, "rev-parse", f"{checkout}^{{tree}}") == git(
        repo, "rev-parse", f"{verified}^{{tree}}"
    )


def test_fetch_verified_merge(source_repo, status_api, tmp_path):
    repo, base, _head, verified, checkout = source_repo
    api, payload, _requests = status_api
    payload["statuses"] = [mapping(base, verified)]
    git(repo, "update-ref", "refs/heads/verified", verified)
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    git(consumer, "init", "-q")
    git(consumer, "remote", "add", "origin", str(repo))
    git(consumer, "fetch", "--no-tags", "origin", checkout)
    result = resolve(consumer, checkout, api)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == verified
    assert git(consumer, "rev-parse", f"{verified}^{{commit}}") == verified


@pytest.mark.parametrize(
    "overrides,expected_error",
    [
        ({"context": "reproducibility/merge/" + "0" * 40}, "No verified merge record"),
        ({"state": "failure"}, "has not verified"),
        ({"state": "pending"}, "has not verified"),
        ({"description": "M:main"}, "Invalid verified merge record"),
        ({"description": None}, "Invalid verified merge record"),
    ],
)
def test_reject_unverified_record(source_repo, status_api, overrides, expected_error):
    repo, base, _head, verified, checkout = source_repo
    api, payload, _requests = status_api
    payload["statuses"] = [mapping(base, verified, **overrides)]
    result = resolve(repo, checkout, api)
    assert result.returncode != 0
    assert expected_error in result.stderr
    assert result.stdout == ""


def test_reject_different_parents(source_repo, status_api):
    repo, base, head, _verified, checkout = source_repo
    api, payload, _requests = status_api
    wrong = commit(repo, git(repo, "rev-parse", f"{head}^{{tree}}"), [head, base])
    payload["statuses"] = [mapping(base, wrong)]
    result = resolve(repo, checkout, api)
    assert result.returncode != 0
    assert "different PR parents" in result.stderr


def test_reject_different_tree(source_repo, status_api):
    repo, base, head, _verified, checkout = source_repo
    api, payload, _requests = status_api
    wrong = commit(repo, git(repo, "rev-parse", f"{base}^{{tree}}"), [base, head])
    payload["statuses"] = [mapping(base, wrong)]
    result = resolve(repo, checkout, api)
    assert result.returncode != 0
    assert "different source tree" in result.stderr


@pytest.mark.parametrize("http_status", [200, 403, 500])
def test_missing_or_unreadable_record_fails(source_repo, status_api, http_status):
    repo, _base, _head, _verified, checkout = source_repo
    api, payload, _requests = status_api
    payload["http_status"] = http_status
    result = resolve(repo, checkout, api)
    assert result.returncode != 0
    assert "Could not select" in result.stderr
    assert result.stdout == ""


def test_reject_non_merge(source_repo, status_api):
    repo, _base, head, _verified, _checkout = source_repo
    api, _payload, requests = status_api
    result = resolve(repo, head, api)
    assert result.returncode != 0
    assert "two-parent PR merge" in result.stderr
    assert requests == []


def test_reject_invalid_api_response(source_repo, status_api):
    repo, _base, _head, _verified, checkout = source_repo
    api, payload, _requests = status_api
    payload["statuses"] = [None]
    result = resolve(repo, checkout, api)
    assert result.returncode != 0
    assert "invalid commit status entry" in result.stderr
    assert result.stdout == ""
