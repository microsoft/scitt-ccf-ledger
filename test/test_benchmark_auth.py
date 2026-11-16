# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import io
import json
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import jwt
import pytest
from cryptography import x509

from . import test_perf
from .infra import locust_benchmark
from .test_perf import benchmark_tokens


@pytest.fixture(scope="module")
def shared_benchmark_tokens(benchmark_tokens):
    return benchmark_tokens


@pytest.mark.parametrize("case", range(2))
def test_benchmark_token_pool(benchmark_tokens, shared_benchmark_tokens, case):
    assert benchmark_tokens is shared_benchmark_tokens
    proposal, tokens, expires_at = benchmark_tokens
    args = proposal["actions"][0]["args"]
    assert args["issuer"] == "https://benchmark.example.com"
    assert args["auto_refresh"] is False
    keys = {key["kid"]: key for key in args["jwks"]["keys"]}
    assert len(keys) == 4
    assert len(set(tokens)) == test_perf.JWT_TOKEN_COUNT

    subjects = set()
    key_ids = []
    for token in tokens:
        kid = jwt.get_unverified_header(token)["kid"]
        key = keys[kid]
        public_key = x509.load_der_x509_certificate(
            base64.b64decode(key["x5c"][0])
        ).public_key()
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=test_perf.JWT_AUDIENCE,
            issuer=args["issuer"],
        )
        subjects.add(claims["sub"])
        assert claims["exp"] == expires_at
        assert claims["exp"] - claims["nbf"] == 3610
        assert claims["jti"] == claims["sub"].removeprefix("user-")
        key_ids.append(kid)
    assert len(subjects) == test_perf.JWT_TOKEN_COUNT
    assert key_ids == key_ids[:4] * (test_perf.JWT_TOKEN_COUNT // 4)
    assert len(set(key_ids[:4])) == 4


def test_cached_benchmark_pool_rejects_near_expiry(benchmark_tokens):
    proposal, tokens, _ = benchmark_tokens
    client = Mock()
    fixture = test_perf.authenticated_benchmark.__wrapped__(
        client, Mock(), (proposal, tokens, time.time() + 60)
    )
    with pytest.raises(RuntimeError, match="too close to expiry"):
        next(fixture)
    client.governance.propose.assert_not_called()


def test_locust_rotates_tokens_and_authenticates_follow_up_reads(monkeypatch):
    monkeypatch.setenv("LOCUST_SKIP_MONKEY_PATCH", "1")
    from .load_test.locustfile import Submitter, on_init

    tokens = ["first", "second", "third", "fourth"]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(tokens)))
    environment = SimpleNamespace(
        parsed_options=SimpleNamespace(scitt_jwt_tokens_stdin=True, measure_time_s=0),
        runner=None,
        events=SimpleNamespace(request=Mock()),
    )
    on_init(environment)
    response = MagicMock()
    response.__enter__.return_value = SimpleNamespace(
        status_code=201, content=b"receipt"
    )
    user = SimpleNamespace(
        environment=environment,
        _signed_statements=[b"statement"],
        skip_confirmation=False,
        client=SimpleNamespace(post=Mock(return_value=response)),
        _extract_tx_id=Mock(return_value="1.2"),
        _wait_for_statement=Mock(),
    )
    for _ in range(8):
        Submitter.submit_signed_statement(user)
    for index, call in enumerate(user.client.post.call_args_list):
        assert call.kwargs["headers"] == {
            "Content-Type": "application/cose",
            "Authorization": f"Bearer {tokens[index % 4]}",
        }
        assert user._wait_for_statement.call_args_list[index].kwargs["headers"] == {
            "Authorization": f"Bearer {tokens[index % 4]}"
        }
    for call in environment.events.request.fire.call_args_list:
        assert call.kwargs["exception"] is None


# Stands in for Locust: runs the given statement, then publishes a master port.
CHILD_SCRIPT = """
import json, os, sys, time
{}
ready = os.environ.get("SCITT_LOCUST_MASTER_READY")
if ready:
    with open(ready + ".pending", "w") as f:
        f.write("12345")
    os.replace(ready + ".pending", ready)
    time.sleep(1)  # Outlive the poll which reads the port, as a master does.
"""


@pytest.mark.parametrize(
    "child, error",
    [
        ("assert len(json.load(sys.stdin)) == 200", None),
        ("time.sleep(600)", subprocess.TimeoutExpired),
        ("sys.exit(3)", "exited with 3"),
    ],
)
def test_token_delivery_cannot_block_startup(monkeypatch, tmp_path, child, error):
    # Larger than a pipe buffer, so a child which does not read it blocks the write.
    tokens = ["x" * 1000] * 200
    processes = []
    popen = subprocess.Popen

    def start(command, **kwargs):
        processes.append(
            popen([sys.executable, "-c", CHILD_SCRIPT.format(child)], **kwargs)
        )
        return processes[-1]

    def run():
        return locust_benchmark.run_locust(
            "https://scitt.example.com",
            tmp_path,
            [],
            "POST /entries",
            auth_tokens=tokens,
        )

    monkeypatch.setattr(locust_benchmark.subprocess, "Popen", start)
    (tmp_path / "locust_stats.csv").write_text("Name,Request Count\nPOST /entries,1\n")
    if error is None:
        assert run()["Request Count"] == "1"
        assert len(processes) == 1 + locust_benchmark.LOCUST_WORKERS
    elif isinstance(error, str):
        with pytest.raises(RuntimeError, match=error):
            run()
    else:
        monkeypatch.setattr(locust_benchmark, "STARTUP_TIMEOUT_S", 1)
        with pytest.raises(error):
            run()
    assert all(process.poll() is not None for process in processes)
