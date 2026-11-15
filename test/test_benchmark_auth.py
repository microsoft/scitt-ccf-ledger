# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import io
import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import jwt
from cryptography import x509

from . import test_perf
from .infra import locust_benchmark


def test_benchmark_token_pool(monkeypatch):
    monkeypatch.setattr(test_perf, "JWT_TOKEN_COUNT", 8)
    proposals = []
    client = SimpleNamespace(
        governance=SimpleNamespace(
            propose=lambda proposal, **kwargs: proposals.append(proposal)
        )
    )
    tokens, expires_at = test_perf.benchmark_tokens.__wrapped__(client)
    args = proposals[0]["actions"][0]["args"]
    assert args["issuer"] == "https://benchmark.example.com"
    assert args["auto_refresh"] is False
    keys = {key["kid"]: key for key in args["jwks"]["keys"]}
    assert len(keys) == 4
    assert len(set(tokens)) == 8
    assert 3590 < expires_at - time.time() <= 3600

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
        assert claims["jti"] == claims["sub"].removeprefix("user-")
        key_ids.append(kid)
    assert len(subjects) == 8
    assert key_ids[:4] == key_ids[4:]
    assert len(set(key_ids[:4])) == 4


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


def test_launches_all_workers_before_delivering_tokens(monkeypatch, tmp_path):
    processes = []
    pools = []
    tokens = ["first", "second"]

    class TokenInput(io.StringIO):
        def write(self, text):
            if processes and "--worker" in processes[-1].args:
                assert len(processes) == 1 + locust_benchmark.LOCUST_WORKERS
            return super().write(text)

        def close(self):
            if not self.closed:
                pools.append(json.loads(self.getvalue()))
            super().close()

    def start(command, **kwargs):
        process = Mock(args=command, stdin=TokenInput())
        process.poll.return_value = 0
        process.wait.return_value = 0
        processes.append(process)
        return process

    monkeypatch.setattr(locust_benchmark.subprocess, "Popen", start)
    monkeypatch.setattr(locust_benchmark, "wait_for_master", lambda *_: 12345)
    (tmp_path / "locust_stats.csv").write_text("Name,Request Count\nPOST /entries,1\n")
    stats = locust_benchmark.run_locust(
        "https://scitt.example.com", tmp_path, [], "POST /entries", auth_tokens=tokens
    )
    assert stats["Request Count"] == "1"
    assert pools == [tokens] * (1 + locust_benchmark.LOCUST_WORKERS)
