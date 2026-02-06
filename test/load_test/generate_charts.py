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


def build_rps_df(endpoint_stats, label):
    """Build a time-series DataFrame from an endpoint's num_reqs_per_sec."""
    start_time = endpoint_stats["start_time"]
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


def expand_response_times(response_times_dict):
    """Expand locust's {bucket: count} into a list of response times."""
    times = []
    for bucket_str, count in response_times_dict.items():
        bucket_ms = float(bucket_str)
        times.extend([bucket_ms] * count)
    return np.array(times)


def generate_charts(stats, output_dir, peak_users, spawn_rate):
    """Generate and save all load test charts to output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    post_stats = next(s for s in stats if s["name"] == "POST /entries")
    get_stats = next(s for s in stats if s["name"] == "GET /operations/[id]")

    ramp_up_seconds = peak_users / spawn_rate

    df_post = build_rps_df(post_stats, "POST /entries")
    df_get = build_rps_df(get_stats, "GET /operations/[id]")

    post_rt = expand_response_times(post_stats["response_times"])
    get_rt = expand_response_times(get_stats["response_times"])

    # Steady-state metrics (after ramp-up)
    post_steady = df_post[df_post["elapsed_seconds"] >= ramp_up_seconds]
    post_mean = post_steady["requests_per_sec"].mean()
    get_steady = df_get[df_get["elapsed_seconds"] >= ramp_up_seconds]
    get_mean = get_steady["requests_per_sec"].mean()

    # --- Chart 1: Requests Per Second Over Time ---
    fig, (ax_top, ax_bot) = plt.subplots(2, 1, figsize=(14, 9), sharex=True)

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

    ax_bot.plot(
        df_get["elapsed_seconds"],
        df_get["requests_per_sec"],
        color="#FF9800",
        linewidth=1,
        alpha=0.7,
        label="GET /operations RPS",
    )
    ax_bot.axhline(
        y=get_mean,
        color="#4CAF50",
        linestyle="--",
        linewidth=1.5,
        label=f"Steady-state Mean ({get_mean:.0f} req/s)",
    )
    ax_bot.axvspan(0, ramp_up_seconds, alpha=0.08, color="orange")
    ax_bot.set_xlabel("Elapsed Time (seconds)")
    ax_bot.set_ylabel("Requests Per Second")
    ax_bot.set_title("GET /operations/[id] — Operation Polling Throughput")
    ax_bot.legend(loc="upper left")
    ax_bot.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "rps_over_time.png", dpi=150)
    plt.close(fig)

    # --- Chart 2: Response Time Distribution ---
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    ax1.hist(
        post_rt, bins=60, color="#2196F3", alpha=0.7, edgecolor="white", linewidth=0.5
    )
    ax1.axvline(
        np.median(post_rt),
        color="#F44336",
        linestyle="--",
        linewidth=1.5,
        label=f"Median: {np.median(post_rt):.0f}ms",
    )
    ax1.axvline(
        np.percentile(post_rt, 95),
        color="#FF9800",
        linestyle=":",
        linewidth=1.5,
        label=f"P95: {np.percentile(post_rt, 95):.0f}ms",
    )
    ax1.axvline(
        np.percentile(post_rt, 99),
        color="#9C27B0",
        linestyle=":",
        linewidth=1.5,
        label=f"P99: {np.percentile(post_rt, 99):.0f}ms",
    )
    ax1.set_xlabel("Response Time (ms)")
    ax1.set_ylabel("Count")
    ax1.set_title("POST /entries — Response Time Distribution")
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    ax2.hist(
        get_rt, bins=60, color="#FF9800", alpha=0.7, edgecolor="white", linewidth=0.5
    )
    ax2.axvline(
        np.median(get_rt),
        color="#F44336",
        linestyle="--",
        linewidth=1.5,
        label=f"Median: {np.median(get_rt):.0f}ms",
    )
    ax2.axvline(
        np.percentile(get_rt, 95),
        color="#2196F3",
        linestyle=":",
        linewidth=1.5,
        label=f"P95: {np.percentile(get_rt, 95):.0f}ms",
    )
    ax2.axvline(
        np.percentile(get_rt, 99),
        color="#9C27B0",
        linestyle=":",
        linewidth=1.5,
        label=f"P99: {np.percentile(get_rt, 99):.0f}ms",
    )
    ax2.set_xlabel("Response Time (ms)")
    ax2.set_ylabel("Count")
    ax2.set_title("GET /operations/[id] — Response Time Distribution")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_dir / "response_time_distribution.png", dpi=150)
    plt.close(fig)

    # --- Chart 3: User Ramp-Up vs Throughput ---
    fig, ax1 = plt.subplots(figsize=(14, 5))

    df_post["estimated_users"] = df_post["elapsed_seconds"].apply(
        lambda t: min(t * spawn_rate, peak_users)
    )

    ax1.fill_between(
        df_post["elapsed_seconds"],
        df_post["requests_per_sec"],
        alpha=0.3,
        color="#2196F3",
        label="POST /entries",
    )
    ax1.fill_between(
        df_get["elapsed_seconds"],
        df_get["requests_per_sec"],
        alpha=0.3,
        color="#FF9800",
        label="GET /operations",
    )
    ax1.set_xlabel("Elapsed Time (seconds)")
    ax1.set_ylabel("Requests Per Second")

    ax2 = ax1.twinx()
    ax2.plot(
        df_post["elapsed_seconds"],
        df_post["estimated_users"],
        color="#F44336",
        linewidth=2.5,
        linestyle="--",
        label="Concurrent Users",
    )
    ax2.set_ylabel("Concurrent Users", color="#F44336")
    ax2.tick_params(axis="y", labelcolor="#F44336")
    ax2.set_ylim(0, peak_users * 1.2)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="center right")

    ax1.set_title("SCITT Load Test — User Ramp-Up vs Throughput (Both Endpoints)")
    ax1.grid(True, alpha=0.3)
    plt.tight_layout()
    fig.savefig(output_dir / "rampup_vs_throughput.png", dpi=150)
    plt.close(fig)

    # --- Summary text file ---
    test_duration = post_stats["last_request_timestamp"] - post_stats["start_time"]
    post_avg_rt = post_stats["total_response_time"] / post_stats["num_requests"]
    get_avg_rt = get_stats["total_response_time"] / get_stats["num_requests"]

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
    ]

    summary_text = "\n".join(summary_lines)
    (output_dir / "summary.txt").write_text(summary_text)
    print(summary_text)

    print(f"\nCharts saved to {output_dir}/")
    print("  - rps_over_time.png")
    print("  - response_time_distribution.png")
    print("  - rampup_vs_throughput.png")
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
    args = parser.parse_args()

    stats = json.loads(args.stats_file.read_text())
    generate_charts(stats, args.output_dir, args.peak_users, args.spawn_rate)


if __name__ == "__main__":
    main()
