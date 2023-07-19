# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import subprocess
from pathlib import Path

import pytest

from pyscitt import crypto
from pyscitt.client import Client

NUM_CLAIMS = 100
LOCUST_PEAK_USERS = 500
LOCUST_USERS_SPAWN_RATE = 10
LOCUST_RUNTIME_SEC = 60

@pytest.mark.perf
@pytest.mark.disable_proxy
class TestLoad:
    def test_load(self, client: Client, did_web, tmp_path: Path):
        for i in range(NUM_CLAIMS):
            identity = did_web.create_identity()
            claim = crypto.sign_json_claimset(identity, {"foo": "bar"})
            (tmp_path / f"claim{i}.cose").write_bytes(claim)

        try:
            result = subprocess.run(
                [
                    "locust",
                    "-f",
                    "test/load_test/locustfile.py",
                    "--headless",
                    "--skip-log",
                    "--json",
                    "--host",
                    client.url,
                    "--users",
                    str(LOCUST_PEAK_USERS),
                    "--spawn-rate",
                    str(LOCUST_USERS_SPAWN_RATE),
                    "--run-time",
                    str(LOCUST_RUNTIME) + "s",
                    "--scitt-claims",
                    str(tmp_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print(e.stdout)
            print(e.stderr)
            raise

        stats = json.loads(result.stdout)
        print(stats)

        assert all([s["num_failures"] == 0 for s in stats])
