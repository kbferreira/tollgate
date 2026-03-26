#!/usr/bin/env python3
"""
plot.py — TOLLGATE — Visualization Suite
========================================================
Generates publication-quality figures for all benchmark metrics.

Outputs (saved to figures/):
  01_latency_cdf.png          — CDF of latency per transport
  02_latency_vs_payload.png   — P50/P99 latency vs payload size
  03_throughput_vs_payload.png— Throughput vs payload size
  04_drop_rate.png            — Drop rate vs payload size
  05_latency_boxplot.png      — Box plots per transport × payload
  06_latency_heatmap.png      — P99 heatmap (transport × payload)
  07_speedup_bar.png          — Speedup vs perf baseline
  08_latency_histogram.png    — Log2 histogram per transport
  09_numa_comparison.png      — NUMA vs non-NUMA (if data present)
  10_cpu_scaling.png          — Throughput vs CPU count (if data present)

Usage:
  python3 plot.py results_summary.csv
  python3 plot.py results/ --format pdf --dpi 300
"""

import os
import sys
import json
import glob
import argparse
import math
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.gridspec import GridSpec
from pathlib import Path

matplotlib.rcParams.update({
    "font.family":       "DejaVu Sans",
    "font.size":         11,
    "axes.titlesize":    13,
    "axes.labelsize":    11,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9,
    "figure.dpi":        150,
    "savefig.dpi":       150,
    "savefig.bbox":      "tight",
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.grid":         True,
    "grid.alpha":        0.3,
    "lines.linewidth":   2.0,
})

TRANSPORT_COLORS = {
    "ringbuf": "#2196F3",   # Blue
    "perf":    "#FF5722",   # Deep Orange
    "hashmap": "#4CAF50",   # Green
    "percpu":  "#9C27B0",   # Purple
}
TRANSPORT_MARKERS = {
    "ringbuf": "o",
    "perf":    "s",
    "hashmap": "^",
    "percpu":  "D",
}
TRANSPORT_LABELS = {
    "ringbuf": "Ring Buffer",
    "perf":    "Perf Event Array",
    "hashmap": "Hash Map",
    "percpu":  "Per-CPU Array",
}
TRANSPORT_ORDER = ["ringbuf", "perf", "hashmap", "percpu"]


def load_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Ensure transport ordering
    df["transport"] = pd.Categorical(df["transport"],
                                      categories=TRANSPORT_ORDER, ordered=True)
    df = df.sort_values(["transport", "payload_size_B"])
    return df


def load_json_dir(directory: str) -> pd.DataFrame:
    """Load raw JSON results and flatten into DataFrame."""
    rows = []
    for f in sorted(glob.glob(os.path.join(directory, "*.json"))):
        try:
            with open(f) as fh:
                data = json.load(fh)
            for r in (data if isinstance(data, list) else [data]):
                if "error" not in r:
                    rows.append(r)
        except Exception:
            pass
    df = pd.DataFrame(rows)
    if df.empty:
        print("No data loaded from JSON files."); sys.exit(1)
    return df


def fmt_bytes(x):
    if x >= 1024: return f"{x//1024}KB"
    return f"{x}B"


def savefig(fig, name: str, out_dir: str, fmt: str):
    path = os.path.join(out_dir, f"{name}.{fmt}")
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved: {path}")


# ─── Fig 1: Latency CDF ───────────────────────────────────────────────────────
def plot_latency_cdf(json_results: list, out_dir: str, fmt: str,
                     payload_filter: int = 256):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle(f"Latency CDF — Payload {payload_filter}B", fontweight="bold")

    for ax, log_scale in zip(axes, [False, True]):
        for transport in TRANSPORT_ORDER:
            lats = []
            for r in json_results:
                if (r.get("transport") == transport and
                        r.get("payload_size") == payload_filter):
                    lats.extend(r.get("raw_latencies_ns", []))
            if not lats:
                continue
            lats_us = np.array(sorted(lats)) / 1000.0  # ns → µs
            cdf = np.arange(1, len(lats_us) + 1) / len(lats_us)

            ax.plot(lats_us, cdf,
                    color=TRANSPORT_COLORS[transport],
                    label=TRANSPORT_LABELS[transport],
                    marker=TRANSPORT_MARKERS[transport],
                    markevery=max(1, len(lats_us)//20),
                    markersize=4)

        ax.set_xlabel("Latency (µs)")
        ax.set_ylabel("CDF")
        ax.set_ylim(0, 1.05)
        ax.legend()
        if log_scale:
            ax.set_xscale("log")
            ax.set_title("Log Scale (tail focus)")
        else:
            ax.set_title("Linear Scale")
        # Mark key percentiles
        for pct, ls in [(0.50, "--"), (0.90, ":"), (0.99, "-.")]:
            ax.axhline(pct, color="gray", linewidth=0.8, linestyle=ls,
                       label=f"P{int(pct*100)}" if not log_scale else "")

    plt.tight_layout()
    savefig(fig, "01_latency_cdf", out_dir, fmt)


# ─── Fig 2: Latency vs Payload ────────────────────────────────────────────────
def plot_latency_vs_payload(df: pd.DataFrame, out_dir: str, fmt: str):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Latency vs. Payload Size", fontweight="bold")

    for ax, (col, title) in zip(axes, [
            ("lat_p50_us", "Median Latency (P50)"),
            ("lat_p99_us", "Tail Latency (P99)"),
    ]):
        for transport in TRANSPORT_ORDER:
            sub = df[df["transport"] == transport]
            if sub.empty or col not in df.columns: continue
            ax.plot(sub["payload_size_B"], sub[col],
                    color=TRANSPORT_COLORS[transport],
                    label=TRANSPORT_LABELS[transport],
                    marker=TRANSPORT_MARKERS[transport],
                    markersize=6)
            # Error bars if stdev available
            if "lat_stdev_us" in df.columns:
                ax.fill_between(sub["payload_size_B"],
                                sub[col] - sub["lat_stdev_us"],
                                sub[col] + sub["lat_stdev_us"],
                                alpha=0.15,
                                color=TRANSPORT_COLORS[transport])

        ax.set_xlabel("Payload Size (bytes)")
        ax.set_ylabel("Latency (µs)")
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_title(title)
        ax.xaxis.set_major_formatter(
            mticker.FuncFormatter(lambda x, _: fmt_bytes(int(x))))
        ax.legend()

    plt.tight_layout()
    savefig(fig, "02_latency_vs_payload", out_dir, fmt)


# ─── Fig 3: Throughput vs Payload ─────────────────────────────────────────────
def plot_throughput(df: pd.DataFrame, out_dir: str, fmt: str):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Throughput vs. Payload Size", fontweight="bold")

    cols = [("throughput_Keps", "Event Throughput (Kev/s)"),
            ("throughput_MBps", "Bandwidth (MB/s)")]

    for ax, (col, ylabel) in zip(axes, cols):
        for transport in TRANSPORT_ORDER:
            sub = df[df["transport"] == transport]
            if sub.empty or col not in df.columns: continue
            ax.plot(sub["payload_size_B"], sub[col],
                    color=TRANSPORT_COLORS[transport],
                    label=TRANSPORT_LABELS[transport],
                    marker=TRANSPORT_MARKERS[transport],
                    markersize=6)

        ax.set_xlabel("Payload Size (bytes)")
        ax.set_ylabel(ylabel)
        ax.set_xscale("log", base=2)
        ax.set_title(ylabel)
        ax.xaxis.set_major_formatter(
            mticker.FuncFormatter(lambda x, _: fmt_bytes(int(x))))
        ax.legend()

    plt.tight_layout()
    savefig(fig, "03_throughput_vs_payload", out_dir, fmt)


# ─── Fig 4: Drop Rate ─────────────────────────────────────────────────────────
def plot_drop_rate(df: pd.DataFrame, out_dir: str, fmt: str):
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.set_title("Drop Rate vs. Payload Size", fontweight="bold")

    for transport in TRANSPORT_ORDER:
        sub = df[df["transport"] == transport]
        if sub.empty: continue
        ax.plot(sub["payload_size_B"], sub["drop_rate_pct"],
                color=TRANSPORT_COLORS[transport],
                label=TRANSPORT_LABELS[transport],
                marker=TRANSPORT_MARKERS[transport],
                markersize=6)

    ax.set_xlabel("Payload Size (bytes)")
    ax.set_ylabel("Drop Rate (%)")
    ax.set_xscale("log", base=2)
    ax.xaxis.set_major_formatter(
        mticker.FuncFormatter(lambda x, _: fmt_bytes(int(x))))
    ax.axhline(0.1, color="red", linestyle="--", linewidth=1, label="0.1% threshold")
    ax.legend()
    plt.tight_layout()
    savefig(fig, "04_drop_rate", out_dir, fmt)


# ─── Fig 5: Box Plots ─────────────────────────────────────────────────────────
def plot_boxplots(json_results: list, out_dir: str, fmt: str,
                  payloads=(64, 256, 1024, 4096)):
    n_payloads   = len(payloads)
    n_transports = len(TRANSPORT_ORDER)
    fig, axes = plt.subplots(1, n_payloads, figsize=(4 * n_payloads, 5),
                              sharey=False)
    fig.suptitle("Latency Distribution by Transport × Payload", fontweight="bold")

    if n_payloads == 1:
        axes = [axes]

    for ax, payload in zip(axes, payloads):
        data = []
        labels = []
        colors = []
        for transport in TRANSPORT_ORDER:
            lats = []
            for r in json_results:
                if (r.get("transport") == transport and
                        r.get("payload_size") == payload):
                    lats.extend(r.get("raw_latencies_ns", []))
            if lats:
                data.append(np.array(lats) / 1000.0)
                labels.append(TRANSPORT_LABELS[transport].replace(" ", "\n"))
                colors.append(TRANSPORT_COLORS[transport])

        if not data:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    transform=ax.transAxes)
            continue

        bp = ax.boxplot(data, patch_artist=True, showfliers=False,
                        medianprops=dict(color="black", linewidth=2))
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)

        ax.set_yscale("log")
        ax.set_xticklabels(labels, fontsize=8)
        ax.set_ylabel("Latency (µs)" if payload == payloads[0] else "")
        ax.set_title(fmt_bytes(payload))

    plt.tight_layout()
    savefig(fig, "05_latency_boxplot", out_dir, fmt)


# ─── Fig 6: P99 Heatmap ──────────────────────────────────────────────────────
def plot_heatmap(df: pd.DataFrame, out_dir: str, fmt: str):
    if "lat_p99_us" not in df.columns:
        return
    pivot = df.pivot_table(index="transport", columns="payload_size_B",
                           values="lat_p99_us", aggfunc="mean")
    pivot = pivot.reindex([t for t in TRANSPORT_ORDER if t in pivot.index])

    fig, ax = plt.subplots(figsize=(max(8, len(pivot.columns) * 1.2), 4))
    im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd")

    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels([fmt_bytes(c) for c in pivot.columns])
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels([TRANSPORT_LABELS.get(t, t) for t in pivot.index])

    for i in range(len(pivot.index)):
        for j in range(len(pivot.columns)):
            val = pivot.values[i, j]
            if not math.isnan(val):
                ax.text(j, i, f"{val:.1f}", ha="center", va="center",
                        fontsize=8,
                        color="white" if val > pivot.values.max() * 0.6 else "black")

    plt.colorbar(im, ax=ax, label="P99 Latency (µs)")
    ax.set_title("P99 Latency Heatmap (Transport × Payload)", fontweight="bold")
    plt.tight_layout()
    savefig(fig, "06_latency_heatmap", out_dir, fmt)


# ─── Fig 7: Speedup Bar Chart ─────────────────────────────────────────────────
def plot_speedup(df: pd.DataFrame, out_dir: str, fmt: str,
                 baseline: str = "perf", metric: str = "lat_p99_us"):
    base_df = df[df["transport"] == baseline][["payload_size_B", metric]].copy()
    base_df.columns = ["payload_size_B", "baseline"]

    transports = [t for t in TRANSPORT_ORDER if t != baseline]
    payloads   = sorted(df["payload_size_B"].unique())

    x = np.arange(len(payloads))
    width = 0.8 / len(transports)

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.set_title(f"Latency Speedup vs. {TRANSPORT_LABELS[baseline]} (P99)",
                 fontweight="bold")

    for i, transport in enumerate(transports):
        sub = df[df["transport"] == transport].merge(base_df, on="payload_size_B")
        if sub.empty: continue
        sub["speedup"] = sub["baseline"] / sub[metric]
        offset = (i - len(transports)/2 + 0.5) * width
        bars = ax.bar(x + offset, sub["speedup"],
                      width=width,
                      color=TRANSPORT_COLORS[transport],
                      label=TRANSPORT_LABELS[transport],
                      alpha=0.85,
                      edgecolor="white",
                      linewidth=0.5)
        for bar, val in zip(bars, sub["speedup"]):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + 0.02,
                    f"{val:.1f}x", ha="center", va="bottom", fontsize=7)

    ax.axhline(1.0, color="black", linewidth=1.5, linestyle="--",
               label=f"Baseline ({TRANSPORT_LABELS[baseline]})")
    ax.set_xticks(x)
    ax.set_xticklabels([fmt_bytes(p) for p in payloads])
    ax.set_xlabel("Payload Size")
    ax.set_ylabel("Speedup (higher = better)")
    ax.legend()
    plt.tight_layout()
    savefig(fig, "07_speedup_bar", out_dir, fmt)


# ─── Fig 8: Latency Histogram (log2 bins) ────────────────────────────────────
def plot_histogram(json_results: list, out_dir: str, fmt: str,
                   payload_filter: int = 256):
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle(f"Latency Histogram (payload={payload_filter}B)",
                 fontweight="bold")
    axes = axes.flatten()

    for ax, transport in zip(axes, TRANSPORT_ORDER):
        lats = []
        for r in json_results:
            if (r.get("transport") == transport and
                    r.get("payload_size") == payload_filter):
                lats.extend(r.get("raw_latencies_ns", []))
        if not lats:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    transform=ax.transAxes)
            ax.set_title(TRANSPORT_LABELS.get(transport, transport))
            continue

        lats_us = np.array(lats) / 1000.0
        log_bins = np.logspace(
            math.log10(max(0.01, lats_us.min())),
            math.log10(lats_us.max()),
            50
        )
        ax.hist(lats_us, bins=log_bins,
                color=TRANSPORT_COLORS[transport], alpha=0.8, edgecolor="white")
        ax.set_xscale("log")
        ax.set_xlabel("Latency (µs)")
        ax.set_ylabel("Count")
        ax.set_title(TRANSPORT_LABELS.get(transport, transport))

        # Annotate percentiles
        for pct, label in [(50, "P50"), (99, "P99"), (99.9, "P99.9")]:
            val = np.percentile(lats_us, pct)
            ax.axvline(val, color="red", linestyle="--", linewidth=1)
            ax.text(val, ax.get_ylim()[1] * 0.9, label,
                    rotation=90, fontsize=7, color="red", va="top")

    plt.tight_layout()
    savefig(fig, "08_latency_histogram", out_dir, fmt)


# ─── Fig 9: Wakeup latency breakdown ─────────────────────────────────────────
def plot_overhead_breakdown(df: pd.DataFrame, out_dir: str, fmt: str):
    """Stacked bar showing latency components if available."""
    # This figure is produced when detailed timing data is available
    # For now, compare min (approx. kernel overhead) vs median vs P99
    payloads = sorted(df["payload_size_B"].unique())[:6]  # cap at 6 payloads

    fig, axes = plt.subplots(1, len(TRANSPORT_ORDER),
                              figsize=(4*len(TRANSPORT_ORDER), 5), sharey=True)
    fig.suptitle("Latency Percentile Breakdown by Transport", fontweight="bold")

    percentile_cols = ["lat_min_us", "lat_p50_us", "lat_p90_us", "lat_p99_us"]
    percentile_labels = ["Min", "P50", "P90", "P99"]
    colors = ["#81D4FA", "#29B6F6", "#0288D1", "#01579B"]

    for ax, transport in zip(axes, TRANSPORT_ORDER):
        sub = df[df["transport"] == transport]
        if sub.empty: continue

        x = np.arange(len(sub))
        bottoms = np.zeros(len(sub))
        prev = np.zeros(len(sub))

        for col, label, color in zip(percentile_cols, percentile_labels, colors):
            if col not in df.columns: continue
            vals = sub[col].values
            increments = np.maximum(0, vals - prev)
            ax.bar(x, increments, bottom=prev, color=color,
                   label=label if ax == axes[0] else "", alpha=0.9,
                   edgecolor="white", linewidth=0.3)
            prev = vals

        ax.set_xticks(x)
        ax.set_xticklabels([fmt_bytes(p) for p in sub["payload_size_B"]],
                           rotation=45, fontsize=7)
        ax.set_title(TRANSPORT_LABELS.get(transport, transport), fontsize=10)
        ax.set_ylabel("Latency (µs)" if transport == TRANSPORT_ORDER[0] else "")

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=4, fontsize=9,
               bbox_to_anchor=(0.5, -0.05))
    plt.tight_layout()
    savefig(fig, "09_latency_breakdown", out_dir, fmt)


# ─── Main ─────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Plot eBPF benchmark results")
    p.add_argument("input",         help="CSV summary file or results/ directory")
    p.add_argument("--format",      default="png", choices=["png", "pdf", "svg"])
    p.add_argument("--dpi",         type=int, default=150)
    p.add_argument("--output",      default="figures/")
    p.add_argument("--payload",     type=int, default=256,
                   help="Payload size filter for single-payload figures")
    return p.parse_args()


def main():
    args = parse_args()
    matplotlib.rcParams["savefig.dpi"] = args.dpi
    matplotlib.rcParams["figure.dpi"]  = args.dpi

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Generating figures → {out_dir}/")

    # Load CSV summary
    if os.path.isfile(args.input) and args.input.endswith(".csv"):
        df = load_csv(args.input)
        json_results = []
    elif os.path.isdir(args.input):
        df_raw = load_json_dir(args.input)
        json_results = df_raw.to_dict("records")
        # Build summary CSV on the fly
        df = df_raw.rename(columns={
            "payload_size":   "payload_size_B",
            "latency_p50_ns": "lat_p50_us",
            "latency_p99_ns": "lat_p99_us",
            "latency_min_ns": "lat_min_us",
            "latency_p90_ns": "lat_p90_us",
            "latency_stdev_ns": "lat_stdev_us",
            "throughput_eps": "throughput_Keps",
            "throughput_mbps": "throughput_MBps",
        })
        # Convert ns → us where needed
        for col in ["lat_p50_us", "lat_p99_us", "lat_min_us",
                    "lat_p90_us", "lat_stdev_us"]:
            if col in df.columns and df[col].mean() > 1000:
                df[col] = df[col] / 1000.0
        if "throughput_Keps" in df.columns:
            df["throughput_Keps"] = df["throughput_Keps"] / 1000.0
    else:
        print(f"Input must be a CSV file or directory. Got: {args.input}")
        sys.exit(1)

    print(f"Loaded {len(df)} rows across "
          f"{df['transport'].nunique() if 'transport' in df.columns else '?'} transports")

    # Generate all figures
    print("\nGenerating plots...")

    if json_results:
        plot_latency_cdf(json_results, str(out_dir), args.format, args.payload)
        plot_boxplots(json_results, str(out_dir), args.format)
        plot_histogram(json_results, str(out_dir), args.format, args.payload)

    plot_latency_vs_payload(df, str(out_dir), args.format)
    plot_throughput(df, str(out_dir), args.format)
    plot_drop_rate(df, str(out_dir), args.format)
    plot_heatmap(df, str(out_dir), args.format)
    plot_speedup(df, str(out_dir), args.format)
    plot_overhead_breakdown(df, str(out_dir), args.format)

    print(f"\nAll figures saved to {out_dir}/")


if __name__ == "__main__":
    main()
