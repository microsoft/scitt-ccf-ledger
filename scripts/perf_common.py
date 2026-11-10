# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Shared helpers for the perf scripts, which read directories of perf data files:
one bencher.json per run, named <run_id>-<run_number>-<run_attempt>.json.

Adapted from CCF's scripts/perf_summary.py and scripts/perf_compare_radar.py.
"""

import json
import math
import os
from collections.abc import Sequence
from typing import Any, NamedTuple

PerfData = dict[str, Any]


class MetricGroup(NamedTuple):
    metric: str
    title: str
    unit: str
    # Factor from the recorded unit to the display unit
    scale: float


# Latencies are recorded in nanoseconds, as in the Bencher metric format.
METRIC_GROUPS = [
    MetricGroup("throughput", "Throughput", "req/s", 1.0),
    MetricGroup("latency", "Latency", "ms", 1e-6),
]
# Metrics for which a higher value is an improvement.
HIGHER_IS_BETTER = {"throughput"}
METADATA_KEY = "__metadata"
DEFAULT_REPOSITORY = "microsoft/scitt-ccf-ledger"

EWMA_HALF_LIFE = 7
EWMA_ALPHA = 1 - 0.5 ** (1 / EWMA_HALF_LIFE)


def ewma(values: Sequence[float], alpha: float = EWMA_ALPHA) -> float:
    """Return the exponentially weighted moving average of the values."""
    if not values:
        raise ValueError("Cannot calculate an EWMA without values")

    average = values[0]
    for value in values[1:]:
        average = alpha * value + (1 - alpha) * average
    return average


def jobid_sort_key(name: str) -> tuple[int, object]:
    """Order perf files chronologically by their numeric job id.

    File names have the form ``<run_id>-<run_number>-<run_attempt>.json`` where
    each component increases over time, so ordering by the integer components
    gives chronological order. Falls back to the name for unexpected formats.
    """
    stem = name[:-5] if name.endswith(".json") else name
    try:
        return (0, tuple(int(part) for part in stem.split("-")))
    except ValueError:
        return (1, name)


def list_perf_files(directory: str) -> list[str]:
    """Return perf files in the directory, ordered chronologically (oldest first)."""
    if not os.path.isdir(directory):
        return []
    files = [
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    ]
    return sorted(files, key=jobid_sort_key)


def load_json(path: str) -> PerfData | None:
    """Load a JSON object from a file, or None if it cannot be read."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def metric_value(
    data: PerfData, benchmark: str, metric: str, scale: float = 1.0
) -> float | None:
    """Return the scaled numeric value of a benchmark metric, or None if absent."""
    metrics = data.get(benchmark)
    if not isinstance(metrics, dict):
        return None
    entry = metrics.get(metric)
    if not isinstance(entry, dict):
        return None
    value = entry.get("value")
    return value * scale if isinstance(value, (int, float)) else None


def compact_number(value: float) -> str:
    """Format a number compactly for tables and chart labels."""
    if not math.isfinite(value):
        return str(value)

    abs_value = abs(value)
    if abs_value == 0:
        return "0"
    if abs_value >= 1000:
        return f"{value:,.0f}"
    if abs_value >= 100:
        return f"{value:.0f}"
    if abs_value >= 10:
        return f"{value:.1f}".rstrip("0").rstrip(".")
    if abs_value >= 1:
        return f"{value:.2f}".rstrip("0").rstrip(".")
    return f"{value:.3g}"


def metric_label_value(value: float, unit: str) -> str:
    """Format a metric value with its display unit."""
    return f"{compact_number(value)} {unit}"
