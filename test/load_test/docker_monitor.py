# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Monitor Docker container CPU and memory usage over time.

Polls `docker stats` at a configurable interval and writes
time-series metrics to a JSON file. Every container of a SCITT deployment is
measured, so a multi-node cluster reports the usage of all of its nodes and its
load balancer rather than of a single container.

Can be used as a context manager from test code or run standalone:
    python -m test.load_test.docker_monitor -o docker_stats.json
    python -m test.load_test.docker_monitor --container <name> [--container <name>]
"""

import argparse
import json
import re
import signal
import subprocess
import threading
import time
from pathlib import Path


def _parse_pct(value: str) -> float:
    """Parse a percentage string like '12.34%' into a float."""
    return float(value.strip().rstrip("%"))


def _parse_mem(value: str) -> float:
    """Parse a memory string like '123.4MiB' into megabytes."""
    value = value.strip()
    # Order matters: check longer suffixes first to avoid 'B' matching 'MiB'/'GiB'/'KiB'.
    units = [("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("B", 1 / (1024 * 1024))]
    for suffix, factor in units:
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * factor
    # Fallback: try plain number (assume bytes)
    return float(re.sub(r"[^\d.]", "", value)) / (1024 * 1024)


def _poll_docker_stats(containers: list[str]) -> dict | None:
    """
    Run `docker stats --no-stream` for the given containers and parse output.

    Returns a sample holding the per-container metrics plus the totals across
    the whole cluster. A single `docker stats` call covers every container so
    that all of them are measured at the same instant.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}",
                *containers,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return None

        per_container = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            name = parts[0].strip()
            mem_parts = parts[2].split("/")
            per_container[name] = {
                "cpu_percent": _parse_pct(parts[1]),
                "mem_used_mb": round(_parse_mem(mem_parts[0]), 2),
                "mem_limit_mb": (
                    round(_parse_mem(mem_parts[1]), 2) if len(mem_parts) > 1 else 0.0
                ),
                "mem_percent": _parse_pct(parts[3]),
            }

        if not per_container:
            return None

        # The top-level metrics are the totals across the cluster, so that a
        # single-node and a multi-node run can be compared directly.
        return {
            "cpu_percent": round(
                sum(c["cpu_percent"] for c in per_container.values()), 2
            ),
            "mem_used_mb": round(
                sum(c["mem_used_mb"] for c in per_container.values()), 2
            ),
            "mem_limit_mb": round(
                sum(c["mem_limit_mb"] for c in per_container.values()), 2
            ),
            "mem_percent": round(
                sum(c["mem_percent"] for c in per_container.values()), 2
            ),
            "per_container": per_container,
        }
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def _find_scitt_containers() -> list[str]:
    """
    Find every running container belonging to a SCITT dev deployment.

    A cluster is made up of one container per node plus a load balancer, so all
    of them have to be measured; monitoring only the first one found would
    report the resource usage of a single container as if it were the service.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return sorted(
            name
            for name in result.stdout.strip().splitlines()
            if name.startswith("scitt-dev-")
        )
    except (subprocess.TimeoutExpired, OSError):
        return []


class DockerMonitor:
    """Collect Docker container resource metrics in a background thread."""

    def __init__(
        self, containers: str | list[str] | None = None, interval: float = 1.0
    ):
        """
        Args:
            containers: Docker container name(s) or ID(s).
                        If None, auto-detects all running scitt-dev-* containers,
                        which covers every node of a cluster and its load balancer.
            interval:   Polling interval in seconds.
        """
        if isinstance(containers, str):
            containers = [containers]
        self.containers: list[str] | None = containers
        self.interval = interval
        self.samples: list[dict] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_time: float = 0

    @property
    def container(self) -> str:
        """Human readable description of what is being monitored."""
        return ", ".join(self.containers or [])

    def _resolve_containers(self):
        if not self.containers:
            self.containers = _find_scitt_containers()
            if not self.containers:
                raise RuntimeError(
                    "No scitt-dev-* container found. "
                    "Specify a container name explicitly."
                )
        print(
            f"DockerMonitor: monitoring {len(self.containers)} container(s): "
            f"{', '.join(self.containers)}"
        )

    def _poll_loop(self):
        while not self._stop_event.is_set():
            assert self.containers is not None
            sample = _poll_docker_stats(self.containers)
            if sample is not None:
                sample["elapsed_seconds"] = round(
                    time.monotonic() - self._start_time, 1
                )
                sample["unix_ts"] = int(time.time())
                self.samples.append(sample)
            self._stop_event.wait(self.interval)

    def start(self):
        """Start collecting samples in a background thread."""
        self._resolve_containers()
        self._start_time = time.monotonic()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> list[dict]:
        """Stop collecting and return all samples."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        return self.samples

    def save(self, path: Path | str):
        """Save collected samples to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "container": self.container,
            "containers": self.containers,
            "interval_seconds": self.interval,
            "num_samples": len(self.samples),
            "samples": self.samples,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"DockerMonitor: {len(self.samples)} samples saved to {path}")

    # Context-manager interface
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Monitor Docker container CPU/memory and write to JSON."
    )
    parser.add_argument(
        "--container",
        type=str,
        action="append",
        dest="containers",
        default=None,
        help=(
            "Container name/ID, repeatable "
            "(auto-detects all scitt-dev-* containers if omitted)"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("docker_stats.json"),
        help="Output JSON file path",
    )
    parser.add_argument(
        "--interval", type=float, default=1.0, help="Polling interval in seconds"
    )
    args = parser.parse_args()

    monitor = DockerMonitor(containers=args.containers, interval=args.interval)
    monitor.start()

    print("Monitoring... Press Ctrl+C to stop.")

    def handle_signal(_sig, _frame):
        monitor.stop()
        monitor.save(args.output)
        raise SystemExit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while True:
            time.sleep(1)
    except SystemExit:
        pass


if __name__ == "__main__":
    main()
