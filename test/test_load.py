# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import subprocess
import sys
from pathlib import Path
from test.load_test.docker_monitor import DockerMonitor

import pytest

from pyscitt import crypto
from pyscitt.client import Client

NUM_STATEMENTS = 100
LOCUST_PEAK_USERS = 800
LOCUST_USERS_SPAWN_RATE = 20
LOCUST_RUNTIME_SEC = 120

# The .NET SDK load test submits all statements from a single long-lived process
# using one shared client with waitForCommit. CCF batches many concurrent
# in-flight submissions into a single commit/signature, so throughput scales with
# concurrency rather than the ~1s per-request commit latency; a high concurrency
# is therefore used to approach the service's registration throughput. Batch size
# and concurrency are tuned to the peak sustained rate of a single-node dev
# service (which shares the host with the client); larger runs degrade as the
# ledger and indexes grow, and higher concurrency saturates the shared CPU.
DOTNET_LOAD_NUM_STATEMENTS = 8000
DOTNET_LOAD_CONCURRENCY = 800

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
                check=False,
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

    @pytest.mark.dotnet
    def test_dotnet_load(
        self,
        service_url: str,
        cert_authority,
        configure_service,
        client: Client,
        tmp_path: Path,
    ):
        """
        Load test the service through the .NET SDK.

        Similar to test_load, but instead of driving the HTTP API directly with
        locust, statements are submitted using the .NET SDK. A single long-lived
        process submits all statements concurrently through one shared
        CodeTransparencyClient (the SDK CLI's `load` operation), so the TLS
        connection, HTTP pipeline and JIT-compiled code stay warm and the
        measured throughput reflects the service rather than per-process startup.
        """
        configure_service(
            {"policy": {"policyScript": "export function apply() { return true; }"}}
        )

        # Generate the signed statements into a dedicated directory so the .NET
        # load operation only picks up the .cose statements. A single identity is
        # reused across all statements to keep generation fast for large batches;
        # each statement is still individually signed and verified by the service.
        statements_dir = tmp_path / "statements"
        statements_dir.mkdir()
        identity = cert_authority.create_identity(
            alg="ES256", kty="ec", add_eku="2.999"
        )
        for i in range(DOTNET_LOAD_NUM_STATEMENTS):
            signed_statement = crypto.sign_json_statement(
                identity, {"foo": "bar", "idx": i}, cwt=True
            )
            (statements_dir / f"signed_statement{i}.cose").write_bytes(signed_statement)

        # Write the service CA certificate so the SDK can trust the endpoint.
        # get_service_certificate() already returns PEM, so write it as-is to
        # preserve the full content (including any chain).
        repo_root = Path(__file__).resolve().parent.parent
        project_path = repo_root / "test/e2e_dotnet_sdk/pipeline-dotnet-cts-cli.csproj"
        ca_certificate_path = tmp_path / "service-cert.pem"
        ca_certificate_path.write_text(client.get_service_certificate())

        # Build the project once up front so the load run can use --no-build.
        # Allow restore here so the test is self-contained when run directly with
        # pytest (the wrapper script restores separately for warmed CI builds).
        build = subprocess.run(
            ["dotnet", "build", str(project_path)],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert (
            build.returncode == 0
        ), f"dotnet build failed\nstdout:\n{build.stdout}\nstderr:\n{build.stderr}"

        # Submit every statement from a single process using one shared client.
        # Collect a stats JSON (and, in Docker mode, container resource samples)
        # and turn them into charts, mirroring the locust load test's outputs.
        stats_file = LOAD_TEST_DIR / "dotnet_load_stats.json"
        docker_stats_file = LOAD_TEST_DIR / "dotnet_docker_stats.json"

        use_docker_monitor = os.environ.get("DOCKER", "0") == "1"
        monitor = None
        if use_docker_monitor:
            monitor = DockerMonitor(interval=1.0)
            monitor.start()

        try:
            result = subprocess.run(
                [
                    "dotnet",
                    "run",
                    "--no-build",
                    "--no-restore",
                    "--project",
                    str(project_path),
                    "--",
                    "--endpoint",
                    service_url,
                    "--ca-certificate",
                    str(ca_certificate_path),
                    "--concurrency",
                    str(DOTNET_LOAD_CONCURRENCY),
                    "--async",
                    "--stats-file",
                    str(stats_file),
                    "load",
                    str(statements_dir),
                ],
                cwd=repo_root,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            if monitor is not None:
                monitor.stop()
                monitor.save(docker_stats_file)

        print(result.stdout)
        assert (
            result.returncode == 0
        ), f"dotnet load failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"

        # Generate charts from the stats produced by the .NET load run.
        chart_cmd = [
            sys.executable,
            "-m",
            "test.load_test.generate_dotnet_charts",
            str(stats_file),
            str(CHARTS_DIR),
        ]
        if use_docker_monitor and docker_stats_file.exists():
            chart_cmd += ["--docker-stats", str(docker_stats_file)]
        subprocess.run(chart_cmd, check=True)
