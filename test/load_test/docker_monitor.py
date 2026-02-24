# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Monitor Docker container CPU and memory usage over time.

Polls `docker stats` at a configurable interval and writes
time-series metrics to a JSON file.

Can be used as a context manager from test code or run standalone:
    python -m test.load_test.docker_monitor --container <name> -o docker_stats.json
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


def _poll_docker_stats(container: str) -> dict | None:
    """Run `docker stats --no-stream` for a single container and parse output."""
    try:
        result = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}",
                container,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return None
        line = result.stdout.strip()
        if not line:
            return None
        parts = line.split("\t")
        if len(parts) < 3:
            return None
        cpu_pct = _parse_pct(parts[0])
        mem_parts = parts[1].split("/")
        mem_used_mb = _parse_mem(mem_parts[0])
        mem_limit_mb = _parse_mem(mem_parts[1]) if len(mem_parts) > 1 else 0.0
        mem_pct = _parse_pct(parts[2])
        return {
            "cpu_percent": cpu_pct,
            "mem_used_mb": round(mem_used_mb, 2),
            "mem_limit_mb": round(mem_limit_mb, 2),
            "mem_percent": mem_pct,
        }
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def _find_scitt_container() -> str | None:
    """Find a running container whose name starts with 'scitt-dev-'."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for name in result.stdout.strip().splitlines():
            if name.startswith("scitt-dev-"):
                return name
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


class DockerMonitor:
    """Collect Docker container resource metrics in a background thread."""

    def __init__(self, container: str | None = None, interval: float = 1.0):
        """
        Args:
            container: Docker container name or ID.
                       If None, auto-detects a running scitt-dev-* container.
            interval:  Polling interval in seconds.
        """
        self.container: str | None = container
        self.interval = interval
        self.samples: list[dict] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_time: float = 0

    def _resolve_container(self):
        if self.container is None:
            self.container = _find_scitt_container()
            if self.container is None:
                raise RuntimeError(
                    "No scitt-dev-* container found. "
                    "Specify a container name explicitly."
                )
        print(f"DockerMonitor: monitoring container '{self.container}'")

    def _poll_loop(self):
        while not self._stop_event.is_set():
            assert self.container is not None
            sample = _poll_docker_stats(self.container)
            if sample is not None:
                sample["elapsed_seconds"] = round(
                    time.monotonic() - self._start_time, 1
                )
                sample["unix_ts"] = int(time.time())
                self.samples.append(sample)
            self._stop_event.wait(self.interval)

    def start(self):
        """Start collecting samples in a background thread."""
        self._resolve_container()
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
        default=None,
        help="Container name/ID (auto-detects scitt-dev-* if omitted)",
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

    monitor = DockerMonitor(container=args.container, interval=args.interval)
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
