# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Summarise a directory of perf data files as markdown for a GitHub job summary,
comparing the latest run with an EWMA baseline and charting the history.

Adapted from CCF's scripts/perf_summary.py.
"""

import argparse
import html
import json
import os
import statistics
from typing import NamedTuple

from perf_common import (
    DEFAULT_REPOSITORY,
    EWMA_HALF_LIFE,
    METADATA_KEY,
    METRIC_GROUPS,
    MetricGroup,
    PerfData,
    ewma,
    list_perf_files,
    load_json,
    metric_label_value,
    metric_value,
)

CHART_MAX_POINTS = 30


class PerfRun(NamedTuple):
    label: str
    run_url: str | None
    commit_url: str | None
    data: PerfData


class MetricSummary(NamedTuple):
    benchmark: str
    latest: float
    baseline: float
    delta_percent: float
    sigma_percent: float


def run_label(name: str) -> str:
    """Short x-axis label for a perf file: the run number when available."""
    stem = name[:-5] if name.endswith(".json") else name
    parts = stem.split("-")
    return parts[1] if len(parts) >= 2 else stem


def run_url(name: str) -> str | None:
    """GitHub Actions URL for a perf file, when the run id can be parsed."""
    stem = name[:-5] if name.endswith(".json") else name
    parts = stem.split("-")
    if not parts or not parts[0].isdigit():
        return None

    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY)
    return f"{server_url}/{repository}/actions/runs/{parts[0]}"


def commit_url(metadata: dict) -> str | None:
    """GitHub commit URL from perf metadata, when available."""
    commit = metadata.get("commit")
    if not isinstance(commit, str) or not commit:
        return None

    server_url = metadata.get("server_url") or os.environ.get(
        "GITHUB_SERVER_URL", "https://github.com"
    )
    repository = metadata.get("repository") or os.environ.get(
        "GITHUB_REPOSITORY", DEFAULT_REPOSITORY
    )
    if not isinstance(server_url, str) or not isinstance(repository, str):
        return None
    return f"{server_url.rstrip('/')}/{repository}/commit/{commit}"


def load_perf_data(directory: str, files: list[str]) -> list[PerfRun]:
    """Load each readable perf file, with its label and links."""
    loaded: list[PerfRun] = []
    for name in files:
        data = load_json(os.path.join(directory, name))
        if data is None:
            continue
        metadata = data.get(METADATA_KEY, {})
        if not isinstance(metadata, dict):
            metadata = {}
        loaded.append(
            PerfRun(run_label(name), run_url(name), commit_url(metadata), data)
        )
    return loaded


def metric_summaries(loaded: list[PerfRun], group: MetricGroup) -> list[MetricSummary]:
    """Summarise one metric in the latest run against its historical baselines."""
    if not loaded:
        return []

    latest_data = loaded[-1].data
    summaries: list[MetricSummary] = []
    for benchmark in sorted(latest_data):
        if benchmark == METADATA_KEY:
            continue
        latest = metric_value(latest_data, benchmark, group.metric, group.scale)
        if latest is None:
            continue

        values = [
            value
            for run in loaded
            if (value := metric_value(run.data, benchmark, group.metric, group.scale))
            is not None
        ]
        baseline = ewma(values)
        if baseline <= 0:
            continue

        sigma = statistics.pstdev(values) if len(values) > 1 else 0.0
        summaries.append(
            MetricSummary(
                benchmark,
                latest,
                baseline,
                ((latest / baseline) - 1) * 100,
                (sigma / baseline) * 100,
            )
        )

    return summaries


def repeated_values(value: float, count: int) -> str:
    """Render a constant series for every chart category."""
    return ", ".join(f"{value:.2f}" for _ in range(count))


def render_mermaid_xychart(
    series: list[tuple[str, float]], metric: str, unit: str
) -> str:
    """Render a Mermaid xychart line chart for a single benchmark metric."""
    labels = ", ".join(json.dumps(label) for label, _ in series)
    raw_values = [value for _, value in series]
    values = ", ".join(f"{value:.2f}" for value in raw_values)
    baseline = ewma(raw_values)
    sigma = statistics.pstdev(raw_values) if len(raw_values) > 1 else 0
    lines = [
        "```mermaid",
        "---",
        "config:",
        "    xyChart:",
        "        width: 700",
        "        height: 400",
        "        showTitle: false",
        "        xAxis:",
        "            labelFontSize: 10",
        "            labelRotation: -45",
        "            titleFontSize: 12",
        "        yAxis:",
        "            labelFontSize: 8",
        "            titleFontSize: 12",
        "            showTitle: false",
        "    themeVariables:",
        "        xyChart:",
        '            plotColorPalette: "#003E7E, #62B5E5, #C7E9FB, #C7E9FB"',
        "---",
        "xychart",
        f"    x-axis [{labels}]",
        f'    y-axis "{metric} ({unit})"',
        f"    line [{values}]",
        f"    line [{repeated_values(baseline, len(raw_values))}]",
        f"    line [{repeated_values(baseline - sigma, len(raw_values))}]",
        f"    line [{repeated_values(baseline + sigma, len(raw_values))}]",
        "```",
        "",
    ]
    return "\n".join(lines)


def render_metric_table(
    loaded: list[PerfRun], summaries: list[MetricSummary], group: MetricGroup
) -> str:
    """Render metric values with each historical chart in a spanning row."""
    lines = [
        '<table width="100%">',
        "<thead>",
        "<tr>",
        "<th>Benchmark</th>",
        "<th>Metric</th>",
        '<th align="right">Latest</th>',
        '<th align="right">EWMA</th>',
        '<th align="right">Change</th>',
        '<th align="right">1 sigma</th>',
        "</tr>",
        "</thead>",
        "<tbody>",
    ]
    for summary in summaries:
        series = [
            (run.label, value)
            for run in loaded
            if (
                value := metric_value(
                    run.data, summary.benchmark, group.metric, group.scale
                )
            )
            is not None
        ]
        lines.extend(
            [
                "<tr>",
                f"<td>{html.escape(summary.benchmark)}</td>",
                f"<td>{group.title}</td>",
                f'<td align="right">{metric_label_value(summary.latest, group.unit)}</td>',
                f'<td align="right">{metric_label_value(summary.baseline, group.unit)}</td>',
                f'<td align="right">{summary.delta_percent:+.1f}%</td>',
                f'<td align="right">{summary.sigma_percent:.1f}%</td>',
                "</tr>",
                "<tr>",
                '<td colspan="6">',
                "<details>",
                "<summary>History</summary>",
                "",
                render_mermaid_xychart(series, group.metric, group.unit),
                "</details>",
                "</td>",
                "</tr>",
                "",
            ]
        )
    lines.extend(["</tbody>", "</table>", ""])
    return "\n".join(lines)


def render_runs_table(loaded: list[PerfRun]) -> str:
    """Render a compact table of run labels, Actions runs, and commits."""
    lines = [
        "### Runs",
        "",
        '<table width="100%">',
        "<thead>",
        "<tr>",
        "<th>Run</th>",
        "<th>Actions</th>",
        "<th>Commit</th>",
        "</tr>",
        "</thead>",
        "<tbody>",
    ]
    for run in reversed(loaded):
        metadata = run.data.get(METADATA_KEY, {})
        commit_sha = metadata.get("commit") if isinstance(metadata, dict) else None
        short_commit = commit_sha[:8] if isinstance(commit_sha, str) else ""
        run_link = (
            f'<a href="{html.escape(run.run_url, quote=True)}">run</a>'
            if run.run_url
            else ""
        )
        commit_link = (
            f'<a href="{html.escape(run.commit_url, quote=True)}">{short_commit}</a>'
            if run.commit_url and short_commit
            else ""
        )
        lines.extend(
            [
                "<tr>",
                f"<td>{html.escape(run.label)}</td>",
                f"<td>{run_link}</td>",
                f"<td>{commit_link}</td>",
                "</tr>",
            ]
        )
    lines.extend(["</tbody>", "</table>", ""])
    return "\n".join(lines)


def render_metric_group(loaded: list[PerfRun], group: MetricGroup) -> str:
    """Render the summary and charts for benchmarks that report one metric."""
    summaries = metric_summaries(loaded, group)
    lines = [f"## {group.title} ({group.unit})", ""]
    if not summaries:
        lines.append(f"_No benchmarks with a `{group.metric}` metric found._")
        lines.append("")
        return "\n".join(lines)

    lines.append(render_metric_table(loaded, summaries, group))
    return "\n".join(lines)


def render_perf_summary(loaded: list[PerfRun]) -> str:
    """Render all perf metric groups as markdown."""
    lines = [
        "# Performance summary",
        "",
        (
            "_Each section compares its latest values with an EWMA baseline using a "
            f"{EWMA_HALF_LIFE}-run half-life, followed by historical charts with "
            "+/-1 sigma reference lines. One sigma is the population standard "
            "deviation across the displayed runs._"
        ),
        "",
    ]
    for group in METRIC_GROUPS:
        lines.append(render_metric_group(loaded, group))
    lines.append(render_runs_table(loaded))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarise perf data files as markdown for a job summary."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="perf",
        help="Directory containing the perf data files (default: perf)",
    )
    args = parser.parse_args()

    recent = list_perf_files(args.directory)[-CHART_MAX_POINTS:]
    print(render_perf_summary(load_perf_data(args.directory, recent)))


if __name__ == "__main__":
    main()
