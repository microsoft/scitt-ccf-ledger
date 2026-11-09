# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Run distributed Locust benchmarks to completion, after the setup of CCF's
tests/infra/locust_benchmark.py: one master and LOCUST_WORKERS workers, with
statistics reset once all users have spawned and a fixed measurement window.
"""

import csv
import math
import os
import subprocess
import tempfile
import time
from pathlib import Path

from .bencher import Latency, Throughput

LOCUST_FILE = "test/load_test/locustfile.py"
LOCUST_USERS = 100
LOCUST_SPAWN_RATE = 100
LOCUST_WORKERS = 4
LOCUST_MEASURE_TIME_S = 30
RUN_TIME_MARGIN_S = 60
STARTUP_TIMEOUT_S = 60
SHUTDOWN_TIMEOUT_S = 10
MASTER_HOST = "127.0.0.1"
MASTER_READY_ENVIRONMENT_VARIABLE = "SCITT_LOCUST_MASTER_READY"
MIN_MEASURED_FRACTION = 0.9


def wait_for_master(process: subprocess.Popen, ready_path: Path) -> int:
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            raise RuntimeError(
                f"Locust master exited with {exit_code} before publishing its port"
            )
        if ready_path.exists():
            port = int(ready_path.read_text(encoding="ascii"))
            if not 0 < port < 65536:
                raise RuntimeError(f"Invalid Locust master port: {port}")
            return port
        time.sleep(0.05)
    raise subprocess.TimeoutExpired(process.args, STARTUP_TIMEOUT_S)


def stop_processes(processes: list[subprocess.Popen]) -> None:
    # Signal every child before waiting, so cleanup is bounded for the whole run
    # rather than paying a full grace period for each unresponsive worker.
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT_S
    for process in processes:
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
    for process in processes:
        process.wait()


def run_locust(
    host: str, output_dir: Path, workload_arguments: list[str], statistics_name: str
) -> dict[str, str]:
    """Run Locust to completion and return the selected row of its statistics."""
    csv_prefix = output_dir / "locust"
    common_cmd = [
        "locust",
        "--headless",
        "--skip-log",
        "--locustfile",
        LOCUST_FILE,
        "--host",
        host,
        "--users",
        str(LOCUST_USERS),
        "--spawn-rate",
        str(LOCUST_SPAWN_RATE),
        "--measure-time-s",
        str(LOCUST_MEASURE_TIME_S),
        # Reset worker statistics too, not just the master's aggregate.
        "--reset-stats",
        *workload_arguments,
    ]

    # The locustfile ends the run after a full measurement window following the
    # ramp. Locust's own deadline is only a generous backstop for a stuck ramp.
    spawn_time_s = math.ceil(LOCUST_USERS / LOCUST_SPAWN_RATE)
    run_time_ceiling_s = spawn_time_s + LOCUST_MEASURE_TIME_S + RUN_TIME_MARGIN_S

    environment = os.environ.copy()
    environment.pop(MASTER_READY_ENVIRONMENT_VARIABLE, None)
    processes: list[subprocess.Popen] = []
    with tempfile.TemporaryDirectory(prefix="locust-", dir=output_dir) as ready_dir:
        try:
            ready_path = Path(ready_dir) / "master.port"
            master = subprocess.Popen(
                [
                    *common_cmd,
                    "--run-time",
                    f"{run_time_ceiling_s}s",
                    "--csv",
                    str(csv_prefix),
                    "--master",
                    "--master-bind-host",
                    MASTER_HOST,
                    "--master-bind-port",
                    "0",
                    "--expect-workers",
                    str(LOCUST_WORKERS),
                    "--expect-workers-max-wait",
                    str(STARTUP_TIMEOUT_S),
                ],
                env={**environment, MASTER_READY_ENVIRONMENT_VARIABLE: str(ready_path)},
            )
            processes.append(master)
            # The master owns its bound socket before any worker can connect. A
            # probe-and-close port reservation could race.
            master_port = wait_for_master(master, ready_path)
            worker_cmd = [
                *common_cmd,
                "--worker",
                "--master-host",
                MASTER_HOST,
                "--master-port",
                str(master_port),
            ]
            for _ in range(LOCUST_WORKERS):
                processes.append(subprocess.Popen(worker_cmd, env=environment))

            exit_code = master.wait(
                timeout=STARTUP_TIMEOUT_S + run_time_ceiling_s + SHUTDOWN_TIMEOUT_S
            )
            # Locust exits non-zero if any request failed.
            if exit_code != 0:
                raise subprocess.CalledProcessError(exit_code, master.args)
            deadline = time.monotonic() + SHUTDOWN_TIMEOUT_S
            for worker in processes[1:]:
                exit_code = worker.wait(timeout=max(0, deadline - time.monotonic()))
                if exit_code != 0:
                    raise subprocess.CalledProcessError(exit_code, worker.args)
        finally:
            stop_processes(processes)

    stats_path = f"{csv_prefix}_stats.csv"
    with open(stats_path, newline="", encoding="utf-8") as stats_file:
        for row in csv.DictReader(stats_file):
            if row.get("Name") == statistics_name:
                return row
    raise RuntimeError(f"No {statistics_name!r} row found in {stats_path}")


def parse_result(stats: dict[str, str]) -> tuple[Throughput, Latency]:
    """
    Turn a row of Locust statistics into requests per second and latency in
    milliseconds (median, with p99 as high and minimum as low).
    """
    request_count = int(stats["Request Count"])
    failure_count = int(stats["Failure Count"])
    request_rate = float(stats["Requests/s"])

    if request_count == 0:
        raise RuntimeError("Locust recorded no requests")
    if failure_count != 0:
        raise RuntimeError(
            f"Locust recorded {failure_count} failures out of {request_count} requests"
        )

    measured_duration_s = request_count / request_rate
    if measured_duration_s < LOCUST_MEASURE_TIME_S * MIN_MEASURED_FRACTION:
        raise RuntimeError(
            f"Measured over {measured_duration_s:.1f}s, but expected "
            f"{LOCUST_MEASURE_TIME_S}s. The run was cut short, so this result does "
            "not describe steady state."
        )

    return (
        Throughput(value=round(request_rate, 1)),
        Latency(
            value=float(stats["Median Response Time"]),
            high_value=float(stats["99%"]),
            low_value=float(stats["Min Response Time"]),
        ),
    )
