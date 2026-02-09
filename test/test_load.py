# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pyscitt import crypto
from pyscitt.client import Client
from test.load_test.docker_monitor import DockerMonitor

NUM_STATEMENTS = 100
LOCUST_PEAK_USERS = 800
LOCUST_USERS_SPAWN_RATE = 20
LOCUST_RUNTIME_SEC = 120

LOAD_TEST_DIR = Path(__file__).parent / "load_test"
STATS_FILE = LOAD_TEST_DIR / "locust_stats.json"
DOCKER_STATS_FILE = LOAD_TEST_DIR / "docker_stats.json"
CHARTS_DIR = LOAD_TEST_DIR / "charts"


@pytest.mark.perf
class TestLoad:
    def test_load(
        self, client: Client, cert_authority, configure_service, tmp_path: Path
    ):
        configure_service(
            {"policy": {"policyScript": "export function apply() { return true; }"}}
        )
        for i in range(NUM_STATEMENTS):
            identity = cert_authority.create_identity(
                alg="ES256", kty="ec", add_eku="2.999"
            )
            signed_statement = crypto.sign_json_statement(
                identity, {"foo": "bar", "idx": i}, cwt=True
            )
            (tmp_path / f"signed_statement{i}.cose").write_bytes(signed_statement)

        # Start Docker resource monitoring if running in Docker mode
        use_docker_monitor = os.environ.get("DOCKER", "0") == "1"
        monitor = None
        if use_docker_monitor:
            monitor = DockerMonitor(interval=1.0)
            monitor.start()

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
                    str(LOCUST_RUNTIME_SEC) + "s",
                    "--scitt-statements",
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
        finally:
            if monitor is not None:
                monitor.stop()
                monitor.save(DOCKER_STATS_FILE)

        stats = json.loads(result.stdout)
        print(stats)

        # Save raw stats to file for later analysis
        STATS_FILE.write_text(json.dumps(stats, indent=2))
        print(f"Stats saved to {STATS_FILE}")

        # Generate charts, overwriting any previous results
        chart_cmd = [
            sys.executable,
            "-m",
            "test.load_test.generate_charts",
            str(STATS_FILE),
            str(CHARTS_DIR),
            "--peak-users",
            str(LOCUST_PEAK_USERS),
            "--spawn-rate",
            str(LOCUST_USERS_SPAWN_RATE),
        ]
        if use_docker_monitor and DOCKER_STATS_FILE.exists():
            chart_cmd += ["--docker-stats", str(DOCKER_STATS_FILE)]
        subprocess.run(chart_cmd, check=True)

        assert all([s["num_failures"] == 0 for s in stats])
