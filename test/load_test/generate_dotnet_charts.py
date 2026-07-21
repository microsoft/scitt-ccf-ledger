# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Generate charts for the .NET SDK load test from its JSON stats output.

The stats file is produced by the .NET CLI `load` operation (via --stats-file)
and contains aggregate metrics, latency percentiles and per-second completion
counts. Optionally, Docker resource samples (from docker_monitor) can be
overlaid.

Usage:
    python -m test.load_test.generate_dotnet_charts <stats_json> <output_dir> \
        [--docker-stats <docker_stats_json>]
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _plot_throughput(stats: dict, out_dir: Path) -> None:
    rps = stats.get("requests_per_sec", {})
    if not rps:
        return
    seconds = sorted(int(k) for k in rps)
    values = [rps[str(s)] for s in seconds]

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(seconds, values, marker="o", markersize=3)
    ax.axhline(
        stats.get("throughput_rps", 0),
        color="tab:orange",
        linestyle="--",
        label=f"avg {stats.get('throughput_rps', 0):.1f} req/s",
    )
    ax.set_title(
        f"Completions per second "
        f"(concurrency {stats.get('concurrency', '?')}, {stats.get('mode', '')})"
    )
    ax.set_xlabel("elapsed seconds")
    ax.set_ylabel("completions/s")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "dotnet_throughput.png", dpi=120)
    plt.close(fig)


def _plot_latency(stats: dict, out_dir: Path) -> None:
    latency = stats.get("latency_ms", {})
    if not latency:
        return
    labels = ["min", "mean", "p50", "p90", "p99", "max"]
    values = [latency.get(name, 0) for name in labels]

    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(labels, values, color="tab:blue")
    ax.bar_label(bars, fmt="%.0f", padding=2, fontsize=8)
    ax.set_title("Per-request latency (ms)")
    ax.set_ylabel("milliseconds")
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "dotnet_latency.png", dpi=120)
    plt.close(fig)


def _plot_docker(docker_stats_path: Path, out_dir: Path) -> None:
    data = json.loads(docker_stats_path.read_text())
    samples = data.get("samples", [])
    if not samples:
        return
    elapsed = [s.get("elapsed_seconds", 0) for s in samples]
    cpu = [s.get("cpu_percent", 0) for s in samples]
    mem = [s.get("mem_used_mb", 0) for s in samples]

    fig, ax_cpu = plt.subplots(figsize=(10, 4))
    ax_cpu.plot(elapsed, cpu, color="tab:red", label="CPU %")
    ax_cpu.set_xlabel("elapsed seconds")
    ax_cpu.set_ylabel("CPU %", color="tab:red")
    ax_cpu.tick_params(axis="y", labelcolor="tab:red")
    ax_cpu.grid(True, alpha=0.3)

    ax_mem = ax_cpu.twinx()
    ax_mem.plot(elapsed, mem, color="tab:green", label="Memory (MiB)")
    ax_mem.set_ylabel("Memory (MiB)", color="tab:green")
    ax_mem.tick_params(axis="y", labelcolor="tab:green")

    ax_cpu.set_title(f"Container resource usage ({data.get('container', '')})")
    fig.tight_layout()
    fig.savefig(out_dir / "dotnet_docker_resources.png", dpi=120)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate charts for the .NET SDK load test stats."
    )
    parser.add_argument(
        "stats_json", type=Path, help="Path to the .NET load stats JSON"
    )
    parser.add_argument("output_dir", type=Path, help="Directory to write charts to")
    parser.add_argument(
        "--docker-stats",
        type=Path,
        default=None,
        help="Optional docker_monitor JSON to overlay resource usage",
    )
    args = parser.parse_args()

    stats = json.loads(args.stats_json.read_text())
    args.output_dir.mkdir(parents=True, exist_ok=True)

    _plot_throughput(stats, args.output_dir)
    _plot_latency(stats, args.output_dir)
    if args.docker_stats is not None and args.docker_stats.exists():
        _plot_docker(args.docker_stats, args.output_dir)

    print(f"Charts written to {args.output_dir}")


if __name__ == "__main__":
    main()
