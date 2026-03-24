# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Generate load test charts from Locust JSON output.

Usage:
    python -m test.load_test.generate_charts <stats_json_file> <output_dir>
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def build_rps_df(endpoint_stats, label, global_start_time=None):
    """Build a time-series DataFrame from an endpoint's num_reqs_per_sec."""
    start_time = (
        global_start_time
        if global_start_time is not None
        else endpoint_stats["start_time"]
    )
    rows = []
    for ts_str, count in endpoint_stats["num_reqs_per_sec"].items():
        ts = int(ts_str)
        rows.append(
            {
                "unix_ts": ts,
                "elapsed_seconds": ts - int(start_time),
                "requests_per_sec": count,
            }
        )
    df = pd.DataFrame(rows).sort_values("unix_ts").reset_index(drop=True)
    df["cumulative_requests"] = df["requests_per_sec"].cumsum()
    df["endpoint"] = label
    return df


def build_fail_df(endpoint_stats, global_start_time, label):
    """Build a time-series DataFrame from an endpoint's num_fail_per_sec."""
    rows = []
    for ts_str, count in endpoint_stats.get("num_fail_per_sec", {}).items():
        ts = int(ts_str)
        rows.append(
            {
                "unix_ts": ts,
                "elapsed_seconds": ts - int(global_start_time),
                "failures_per_sec": count,
            }
        )
    if rows:
        df = pd.DataFrame(rows).sort_values("unix_ts").reset_index(drop=True)
    else:
        df = pd.DataFrame(
            columns=["unix_ts", "elapsed_seconds", "failures_per_sec"]
        ).astype({"unix_ts": int, "elapsed_seconds": int, "failures_per_sec": float})
    df["endpoint"] = label
    return df


def align_series(dfs, value_col, elapsed_col="elapsed_seconds"):
    """Align multiple DataFrames to a shared elapsed-time index, filling gaps with 0."""
    all_elapsed = sorted(set().union(*[set(df[elapsed_col].tolist()) for df in dfs]))
    aligned = []
    for df in dfs:
        s = df.set_index(elapsed_col)[value_col].reindex(all_elapsed, fill_value=0)
        aligned.append(s.values)
    return all_elapsed, aligned


def build_e2e_latency_df(samples, global_start_time, bin_size=10):
    """Build per-bin P50/P95/P99 DataFrame from E2E latency samples.

    Samples are binned into ``bin_size``-second intervals; percentiles are
    computed over all samples that fall in each bin.
    """
    rows = []
    for s in samples:
        elapsed = s["unix_ts"] - global_start_time
        bin_start = int(elapsed // bin_size) * bin_size
        rows.append({"bin": bin_start, "latency_ms": s["latency_ms"]})
    if not rows:
        return pd.DataFrame(columns=["elapsed_seconds", "p50", "p95", "p99"])
    df = pd.DataFrame(rows)
    grouped = (
        df.groupby("bin")["latency_ms"]
        .agg(
            p50=lambda x: np.percentile(x, 50),
            p95=lambda x: np.percentile(x, 95),
            p99=lambda x: np.percentile(x, 99),
        )
        .reset_index()
        .rename(columns={"bin": "elapsed_seconds"})
    )
    return grouped


def expand_response_times(response_times_dict):
    """Expand locust's {bucket: count} into a list of response times."""
    times = []
    for bucket_str, count in response_times_dict.items():
        bucket_ms = float(bucket_str)
        times.extend([bucket_ms] * count)
    return np.array(times)


def generate_charts(
    stats, output_dir, peak_users, spawn_rate, docker_stats=None, e2e_samples=None
):
    """Generate and save all load test charts to output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    post_stats = next(s for s in stats if s["name"] == "POST /entries")
    get_stats = next(s for s in stats if s["name"] == "GET /operations/[id]")
    get_entries_stats = next(
        s for s in stats if s["name"] == "GET /entries/[id]/statement"
    )
    submit_task_stats = next(
        (
            s
            for s in stats
            if s["name"] == "submit_signed_statement" and s.get("method") == "TASK"
        ),
        None,
    )

    ramp_up_seconds = peak_users / spawn_rate

    global_start_time = min(
        post_stats["start_time"],
        get_stats["start_time"],
        get_entries_stats["start_time"],
    )

    df_post = build_rps_df(post_stats, "POST /entries", global_start_time)
    df_get = build_rps_df(get_stats, "GET /operations/[id]", global_start_time)
    df_get_entries = build_rps_df(
        get_entries_stats, "GET /entries/[id]/statement", global_start_time
    )

    df_post_fail = build_fail_df(post_stats, global_start_time, "POST /entries")
    df_get_fail = build_fail_df(get_stats, global_start_time, "GET /operations/[id]")
    df_get_entries_fail = build_fail_df(
        get_entries_stats, global_start_time, "GET /entries/[id]/statement"
    )

    post_rt = expand_response_times(post_stats["response_times"])
    get_rt = expand_response_times(get_stats["response_times"])
    get_entries_rt = expand_response_times(get_entries_stats["response_times"])
    submit_task_rt = (
        expand_response_times(submit_task_stats["response_times"])
        if submit_task_stats is not None
        else np.array([])
    )

    # Steady-state metrics (after ramp-up)
    post_steady = df_post[df_post["elapsed_seconds"] >= ramp_up_seconds]
    post_mean = post_steady["requests_per_sec"].mean()
    get_steady = df_get[df_get["elapsed_seconds"] >= ramp_up_seconds]
    get_mean = get_steady["requests_per_sec"].mean()
    get_entries_steady = df_get_entries[
        df_get_entries["elapsed_seconds"] >= ramp_up_seconds
    ]
    get_entries_mean = get_entries_steady["requests_per_sec"].mean()

    # --- Chart 1: Requests Per Second Over Time ---
    fig, (ax_top, ax_mid, ax_bot) = plt.subplots(3, 1, figsize=(14, 13), sharex=True)

    ax_top.plot(
        df_post["elapsed_seconds"],
        df_post["requests_per_sec"],
        color="#2196F3",
        linewidth=1,
        alpha=0.7,
        label="POST /entries RPS",
    )
    ax_top.axhline(
        y=post_mean,
        color="#4CAF50",
        linestyle="--",
        linewidth=1.5,
        label=f"Steady-state Mean ({post_mean:.0f} req/s)",
    )
    ax_top.axvspan(
        0,
        ramp_up_seconds,
        alpha=0.08,
        color="orange",
        label=f"Ramp-up ({ramp_up_seconds:.0f}s)",
    )
    ax_top.set_ylabel("Requests Per Second")
    ax_top.set_title("POST /entries — Submission Throughput")
    ax_top.legend(loc="upper left")
    ax_top.grid(True, alpha=0.3)

    ax_mid.plot(
        df_get["elapsed_seconds"],
        df_get["requests_per_sec"],
        color="#FF9800",
        linewidth=1,
        alpha=0.7,
        label="GET /operations RPS",
    )
    ax_mid.axhline(
        y=get_mean,
        color="#4CAF50",
        linestyle="--",
        linewidth=1.5,
        label=f"Steady-state Mean ({get_mean:.0f} req/s)",
    )
    ax_mid.axvspan(0, ramp_up_seconds, alpha=0.08, color="orange")
    ax_mid.set_ylabel("Requests Per Second")
    ax_mid.set_title("GET /operations/[id] — Operation Polling Throughput")
    ax_mid.legend(loc="upper left")
    ax_mid.grid(True, alpha=0.3)

    ax_bot.plot(
        df_get_entries["elapsed_seconds"],
        df_get_entries["requests_per_sec"],
        color="#9C27B0",
        linewidth=1,
        alpha=0.7,
        label="GET /entries/[id]/statement RPS",
    )
    ax_bot.axhline(
        y=get_entries_mean,
        color="#4CAF50",
        linestyle="--",
        linewidth=1.5,
        label=f"Steady-state Mean ({get_entries_mean:.0f} req/s)",
    )
    ax_bot.axvspan(0, ramp_up_seconds, alpha=0.08, color="orange")
    ax_bot.set_xlabel("Elapsed Time (seconds)")
    ax_bot.set_ylabel("Requests Per Second")
    ax_bot.set_title("GET /entries/[id]/statement — Entry Retrieval Throughput")
    ax_bot.legend(loc="upper left")
    ax_bot.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "rps_over_time.png", dpi=150)
    plt.close(fig)

    # --- Chart 2: Response Time Distribution ---
    rt_plots = [
        (
            "POST /entries — Response Time Distribution",
            post_rt,
            "#2196F3",
            "#FF9800",
            "#9C27B0",
        ),
        (
            "GET /operations/[id] — Response Time Distribution",
            get_rt,
            "#FF9800",
            "#2196F3",
            "#9C27B0",
        ),
        (
            "GET /entries/[id]/statement — Response Time Distribution",
            get_entries_rt,
            "#9C27B0",
            "#2196F3",
            "#FF9800",
        ),
    ]
    if submit_task_rt.size:
        rt_plots.append(
            (
                "submit_signed_statement — End-to-End Response Time Distribution",
                submit_task_rt,
                "#009688",
                "#F44336",
                "#3F51B5",
            )
        )

    fig, axes = plt.subplots(1, len(rt_plots), figsize=(6.5 * len(rt_plots), 5))
    if len(rt_plots) == 1:
        axes = [axes]

    for ax, (title, rt_values, hist_color, p95_color, p99_color) in zip(axes, rt_plots):
        median = np.median(rt_values)
        p95 = np.percentile(rt_values, 95)
        p99 = np.percentile(rt_values, 99)
        ax.hist(
            rt_values,
            bins=60,
            color=hist_color,
            alpha=0.7,
            edgecolor="white",
            linewidth=0.5,
        )
        ax.axvline(
            median,
            color="#F44336",
            linestyle="--",
            linewidth=1.5,
            label=f"Median: {median:.0f}ms",
        )
        ax.axvline(
            p95,
            color=p95_color,
            linestyle=":",
            linewidth=1.5,
            label=f"P95: {p95:.0f}ms",
        )
        ax.axvline(
            p99,
            color=p99_color,
            linestyle=":",
            linewidth=1.5,
            label=f"P99: {p99:.0f}ms",
        )
        ax.set_xlabel("Response Time (ms)")
        ax.set_ylabel("Count")
        ax.set_title(title)
        ax.legend()
        ax.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "response_time_distribution.png", dpi=150)
    plt.close(fig)

    # --- Chart 3: User Ramp-Up vs Throughput ---
    fig, (ax_rps, ax_fail) = plt.subplots(
        2, 1, figsize=(14, 10), sharex=True, gridspec_kw={"height_ratios": [3, 1]}
    )

    df_post["estimated_users"] = df_post["elapsed_seconds"].apply(
        lambda t: min(t * spawn_rate, peak_users)
    )

    # Stacked RPS areas
    rps_elapsed, rps_arrays = align_series(
        [df_post, df_get, df_get_entries], "requests_per_sec"
    )
    ax_rps.stackplot(
        rps_elapsed,
        rps_arrays,
        labels=["POST /entries", "GET /operations/[id]", "GET /entries/[id]/statement"],
        colors=["#2196F3", "#FF9800", "#9C27B0"],
        alpha=0.6,
    )
    ax_rps.set_ylabel("Requests Per Second")
    ax_rps.set_title(
        "SCITT Load Test — User Ramp-Up vs Throughput (All Endpoints, Stacked)"
    )
    ax_rps.grid(True, alpha=0.3)

    ax_users = ax_rps.twinx()
    ax_users.plot(
        df_post["elapsed_seconds"],
        df_post["estimated_users"],
        color="#F44336",
        linewidth=2.5,
        linestyle="--",
        label="Concurrent Users",
    )
    ax_users.set_ylabel("Concurrent Users", color="#F44336")
    ax_users.tick_params(axis="y", labelcolor="#F44336")
    ax_users.set_ylim(0, peak_users * 1.2)

    lines_rps, labels_rps = ax_rps.get_legend_handles_labels()
    lines_users, labels_users = ax_users.get_legend_handles_labels()
    ax_rps.legend(lines_rps + lines_users, labels_rps + labels_users, loc="upper left")

    # Stacked failures area + individual lines
    fail_elapsed, fail_arrays = align_series(
        [df_post_fail, df_get_fail, df_get_entries_fail], "failures_per_sec"
    )
    ax_fail.stackplot(
        fail_elapsed,
        fail_arrays,
        labels=["POST /entries", "GET /operations/[id]", "GET /entries/[id]/statement"],
        colors=["#2196F3", "#FF9800", "#9C27B0"],
        alpha=0.5,
    )
    for df_fail, color, label in [
        (df_post_fail, "#1565C0", "POST /entries failures"),
        (df_get_fail, "#E65100", "GET /operations failures"),
        (df_get_entries_fail, "#6A1B9A", "GET /entries failures"),
    ]:
        if not df_fail.empty:
            ax_fail.plot(
                df_fail["elapsed_seconds"],
                df_fail["failures_per_sec"],
                color=color,
                linewidth=1.5,
                label=label,
            )
    ax_fail.set_ylabel("Failures Per Second")
    ax_fail.set_title("Failures Per Second (Stacked)")
    ax_fail.legend(loc="upper left")
    ax_fail.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "rampup_vs_throughput.png", dpi=150)
    plt.close(fig)

    # --- Summary text file ---
    test_duration = post_stats["last_request_timestamp"] - post_stats["start_time"]
    post_avg_rt = post_stats["total_response_time"] / post_stats["num_requests"]
    get_avg_rt = get_stats["total_response_time"] / get_stats["num_requests"]
    get_entries_avg_rt = (
        get_entries_stats["total_response_time"] / get_entries_stats["num_requests"]
    )

    summary_lines = [
        "SCITT Load Test Summary",
        "=" * 40,
        "",
        "Test Configuration",
        "-" * 40,
        f"  Test Duration:    {test_duration:.1f}s",
        f"  Peak Users:       {peak_users:,}",
        f"  Spawn Rate:       {spawn_rate} users/sec",
        f"  Ramp-up Duration: {ramp_up_seconds:.0f}s",
        "",
        "POST /entries (Submissions)",
        "-" * 40,
        f"  Total Submissions:      {post_stats['num_requests']:,}",
        f"  Failures:               {post_stats['num_failures']:,}",
        f"  Steady-state Mean RPS:  {post_mean:.0f}",
        f"  Avg Response Time:      {post_avg_rt:.1f}ms",
        f"  Median Response Time:   {np.median(post_rt):.0f}ms",
        f"  P95 Response Time:      {np.percentile(post_rt, 95):.0f}ms",
        f"  P99 Response Time:      {np.percentile(post_rt, 99):.0f}ms",
        f"  Max Response Time:      {post_stats['max_response_time']:.1f}ms",
        "",
        "GET /operations/[id] (Polling)",
        "-" * 40,
        f"  Total Polls:            {get_stats['num_requests']:,}",
        f"  Failures:               {get_stats['num_failures']:,}",
        f"  Steady-state Mean RPS:  {get_mean:.0f}",
        f"  Avg Response Time:      {get_avg_rt:.1f}ms",
        f"  Median Response Time:   {np.median(get_rt):.0f}ms",
        f"  P95 Response Time:      {np.percentile(get_rt, 95):.0f}ms",
        f"  P99 Response Time:      {np.percentile(get_rt, 99):.0f}ms",
        f"  Max Response Time:      {get_stats['max_response_time']:.1f}ms",
        f"  Polls per Submission:   {get_stats['num_requests']/post_stats['num_requests']:.1f}x",
        "",
        "GET /entries/[id]/statement (Entry Retrieval)",
        "-" * 40,
        f"  Total Requests:         {get_entries_stats['num_requests']:,}",
        f"  Failures:               {get_entries_stats['num_failures']:,}",
        f"  Steady-state Mean RPS:  {get_entries_mean:.0f}",
        f"  Avg Response Time:      {get_entries_avg_rt:.1f}ms",
        f"  Median Response Time:   {np.median(get_entries_rt):.0f}ms",
        f"  P95 Response Time:      {np.percentile(get_entries_rt, 95):.0f}ms",
        f"  P99 Response Time:      {np.percentile(get_entries_rt, 99):.0f}ms",
        f"  Max Response Time:      {get_entries_stats['max_response_time']:.1f}ms",
        f"  Retrievals per Submission: {get_entries_stats['num_requests']/post_stats['num_requests']:.1f}x",
    ]

    # --- Chart 4: Docker Resource Usage (if available) ---
    if docker_stats is not None and docker_stats.get("samples"):
        samples = docker_stats["samples"]
        df_docker = pd.DataFrame(samples)

        fig, (ax_cpu, ax_mem) = plt.subplots(2, 1, figsize=(14, 9), sharex=True)

        ax_cpu.plot(
            df_docker["elapsed_seconds"],
            df_docker["cpu_percent"],
            color="#E91E63",
            linewidth=1.2,
            alpha=0.8,
            label="CPU %",
        )
        cpu_mean = df_docker["cpu_percent"].mean()
        cpu_max = df_docker["cpu_percent"].max()
        ax_cpu.axhline(
            y=cpu_mean,
            color="#4CAF50",
            linestyle="--",
            linewidth=1.5,
            label=f"Mean: {cpu_mean:.1f}%",
        )
        ax_cpu.axhline(
            y=cpu_max,
            color="#F44336",
            linestyle=":",
            linewidth=1,
            alpha=0.6,
            label=f"Max: {cpu_max:.1f}%",
        )
        ax_cpu.axvspan(
            0,
            ramp_up_seconds,
            alpha=0.08,
            color="orange",
            label=f"Ramp-up ({ramp_up_seconds:.0f}s)",
        )
        ax_cpu.fill_between(
            df_docker["elapsed_seconds"],
            df_docker["cpu_percent"],
            alpha=0.15,
            color="#E91E63",
        )
        ax_cpu.set_ylabel("CPU Usage (%)")
        ax_cpu.set_title(
            f"Docker Container CPU Usage — {docker_stats.get('container', 'unknown')}"
        )
        ax_cpu.legend(loc="upper left")
        ax_cpu.grid(True, alpha=0.3)

        ax_mem.plot(
            df_docker["elapsed_seconds"],
            df_docker["mem_used_mb"],
            color="#673AB7",
            linewidth=1.2,
            alpha=0.8,
            label="Memory Used (MB)",
        )
        mem_mean = df_docker["mem_used_mb"].mean()
        mem_max = df_docker["mem_used_mb"].max()
        ax_mem.axhline(
            y=mem_mean,
            color="#4CAF50",
            linestyle="--",
            linewidth=1.5,
            label=f"Mean: {mem_mean:.0f} MB",
        )
        ax_mem.axhline(
            y=mem_max,
            color="#F44336",
            linestyle=":",
            linewidth=1,
            alpha=0.6,
            label=f"Max: {mem_max:.0f} MB",
        )
        ax_mem.axvspan(0, ramp_up_seconds, alpha=0.08, color="orange")
        ax_mem.fill_between(
            df_docker["elapsed_seconds"],
            df_docker["mem_used_mb"],
            alpha=0.15,
            color="#673AB7",
        )
        if df_docker["mem_limit_mb"].max() > 0:
            mem_limit = df_docker["mem_limit_mb"].iloc[0]
            ax_mem.axhline(
                y=mem_limit,
                color="#FF5722",
                linestyle="-",
                linewidth=1,
                alpha=0.4,
                label=f"Limit: {mem_limit:.0f} MB",
            )
        ax_mem.set_xlabel("Elapsed Time (seconds)")
        ax_mem.set_ylabel("Memory Usage (MB)")
        ax_mem.set_title(
            f"Docker Container Memory Usage — {docker_stats.get('container', 'unknown')}"
        )
        ax_mem.legend(loc="upper left")
        ax_mem.grid(True, alpha=0.3)

        plt.tight_layout()
        fig.savefig(output_dir / "docker_resource_usage.png", dpi=150)
        plt.close(fig)

        # Append resource stats to summary
        summary_lines += [
            "",
            f"Docker Resource Usage ({docker_stats.get('container', 'N/A')})",
            "-" * 40,
            f"  Samples Collected:  {len(samples)}",
            f"  CPU Mean:           {cpu_mean:.1f}%",
            f"  CPU Max:            {cpu_max:.1f}%",
            f"  Memory Mean:        {mem_mean:.0f} MB",
            f"  Memory Max:         {mem_max:.0f} MB",
            f"  Memory Limit:       {df_docker['mem_limit_mb'].iloc[0]:.0f} MB",
        ]

    summary_text = "\n".join(summary_lines)
    (output_dir / "summary.txt").write_text(summary_text)
    print(summary_text)

    print(f"\nCharts saved to {output_dir}/")
    print("  - rps_over_time.png")
    print("  - response_time_distribution.png")
    print("  - rampup_vs_throughput.png")
    if docker_stats is not None and docker_stats.get("samples"):
        print("  - docker_resource_usage.png")
    print("  - summary.txt")


def main():
    parser = argparse.ArgumentParser(
        description="Generate load test charts from Locust JSON output."
    )
    parser.add_argument(
        "stats_file", type=Path, help="Path to the Locust JSON stats file"
    )
    parser.add_argument(
        "output_dir", type=Path, help="Directory to save charts into (will be created)"
    )
    parser.add_argument(
        "--peak-users",
        type=int,
        default=800,
        help="Peak concurrent users (default: 800)",
    )
    parser.add_argument(
        "--spawn-rate",
        type=int,
        default=20,
        help="User spawn rate per second (default: 20)",
    )
    parser.add_argument(
        "--docker-stats",
        type=Path,
        default=None,
        help="Path to Docker resource stats JSON file (optional)",
    )
    args = parser.parse_args()

    stats = json.loads(args.stats_file.read_text())
    docker_stats = None
    if args.docker_stats and args.docker_stats.exists():
        docker_stats = json.loads(args.docker_stats.read_text())
    generate_charts(
        stats, args.output_dir, args.peak_users, args.spawn_rate, docker_stats
    )


if __name__ == "__main__":
    main()
