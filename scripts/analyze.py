#!/usr/bin/env python3
"""
analyze.py — TOLLGATE — Data Analysis Pipeline
=============================================================
Aggregates JSON result files, computes statistics, generates CSV
summary tables, and prints formatted comparison reports.

Usage:
  python3 analyze.py results/            # analyze all JSON files in dir
  python3 analyze.py results/r_*.json    # specific files
  python3 analyze.py --compare ringbuf perf --metric latency_p99_ns
"""

import os
import sys
import json
import glob
import argparse
import statistics
import csv
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any, Optional
import math

# ─── Metric definitions ────────────────────────────────────────────────────────
METRICS = {
    "latency_min_ns":    {"label": "Latency Min (µs)",    "scale": 1e-3},
    "latency_p50_ns":    {"label": "Latency P50 (µs)",    "scale": 1e-3},
    "latency_p90_ns":    {"label": "Latency P90 (µs)",    "scale": 1e-3},
    "latency_p95_ns":    {"label": "Latency P95 (µs)",    "scale": 1e-3},
    "latency_p99_ns":    {"label": "Latency P99 (µs)",    "scale": 1e-3},
    "latency_p999_ns":   {"label": "Latency P99.9 (µs)",  "scale": 1e-3},
    "latency_mean_ns":   {"label": "Latency Mean (µs)",   "scale": 1e-3},
    "latency_max_ns":    {"label": "Latency Max (µs)",    "scale": 1e-3},
    "latency_stdev_ns":  {"label": "Latency StdDev (µs)", "scale": 1e-3},
    "throughput_eps":    {"label": "Throughput (Kev/s)",   "scale": 1e-3},
    "throughput_mbps":   {"label": "Throughput (MB/s)",   "scale": 1.0},
    "drop_rate_pct":     {"label": "Drop Rate (%)",       "scale": 1.0},
    "events_total":      {"label": "Events",              "scale": 1.0},
}

TRANSPORT_ORDER = ["ringbuf", "perf", "hashmap", "percpu"]
TRANSPORT_DISPLAY = {
    "ringbuf": "Ring Buffer",
    "perf":    "Perf Event Array",
    "hashmap": "Hash Map",
    "percpu":  "Per-CPU Array",
}

# ─── Data loading ──────────────────────────────────────────────────────────────
def load_results(paths: List[str]) -> List[Dict[str, Any]]:
    results = []
    for path in paths:
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                results.extend(data)
            elif isinstance(data, dict):
                results.append(data)
        except Exception as e:
            print(f"WARN: Could not load {path}: {e}")
    # Filter out error runs
    valid = [r for r in results if "error" not in r]
    print(f"Loaded {len(valid)} valid runs ({len(results) - len(valid)} errors filtered)")
    return valid


def load_directory(directory: str) -> List[Dict[str, Any]]:
    files = sorted(glob.glob(os.path.join(directory, "*.json")))
    if not files:
        print(f"No JSON files found in {directory}")
        sys.exit(1)
    return load_results(files)


# ─── Aggregation ──────────────────────────────────────────────────────────────
def group_runs(results: List[Dict], group_keys=("transport", "payload_size")) -> Dict:
    """Group results by key tuple and aggregate repeated runs."""
    groups = defaultdict(list)
    for r in results:
        key = tuple(r.get(k) for k in group_keys)
        groups[key].append(r)
    return dict(groups)


def aggregate_group(runs: List[Dict]) -> Dict:
    """Compute mean ± stdev across repeated runs for all numeric metrics."""
    agg = {}
    if not runs:
        return agg

    # Copy non-numeric fields from first run
    for k in ("transport", "payload_size", "suite", "hostname", "kernel", "ncpus"):
        if k in runs[0]:
            agg[k] = runs[0][k]
    agg["n_repeats"] = len(runs)

    # Aggregate all numeric metrics
    numeric_keys = [k for k, v in runs[0].items()
                    if isinstance(v, (int, float)) and k not in ("repeat",)]
    for k in numeric_keys:
        vals = [r[k] for r in runs if k in r and r[k] is not None]
        if vals:
            agg[f"{k}_mean"]  = statistics.mean(vals)
            agg[f"{k}_stdev"] = statistics.stdev(vals) if len(vals) > 1 else 0.0
            agg[f"{k}_min"]   = min(vals)
            agg[f"{k}_max"]   = max(vals)
            agg[k]            = statistics.mean(vals)  # convenience alias

    # Pool raw latency samples across repeats for accurate percentile recalculation
    all_lats = []
    for r in runs:
        all_lats.extend(r.get("raw_latencies_ns", []))
    if all_lats:
        all_lats.sort()
        n = len(all_lats)
        def p(pct): return all_lats[int((pct/100.0) * (n-1))]
        agg["pooled_p50_ns"]  = p(50)
        agg["pooled_p90_ns"]  = p(90)
        agg["pooled_p95_ns"]  = p(95)
        agg["pooled_p99_ns"]  = p(99)
        agg["pooled_p999_ns"] = p(99.9)
        agg["pooled_n"]       = n

    return agg


# ─── Comparison tables ─────────────────────────────────────────────────────────
def print_comparison_table(aggregated: Dict, metric: str = "latency_p99_ns",
                            payload_filter: Optional[int] = None):
    """Print ASCII table: transports as columns, payload sizes as rows."""
    meta = METRICS.get(metric, {"label": metric, "scale": 1.0})
    label, scale = meta["label"], meta["scale"]

    # Collect all payload sizes and transports present
    payloads = sorted(set(k[1] for k in aggregated))
    transports = [t for t in TRANSPORT_ORDER
                  if any(k[0] == t for k in aggregated)]

    if payload_filter:
        payloads = [p for p in payloads if p == payload_filter]

    col_w = 18
    header = f"{'Payload':>8}  " + "".join(
        f"{TRANSPORT_DISPLAY.get(t, t):>{col_w}}" for t in transports
    )
    print(f"\n{'─'*len(header)}")
    print(f"  {label} — grouped by payload size vs. transport")
    print(f"{'─'*len(header)}")
    print(header)
    print(f"{'─'*len(header)}")

    for payload in payloads:
        row = f"{payload:>6}B  "
        for t in transports:
            key = (t, payload)
            agg = aggregated.get(key)
            if agg and metric in agg:
                val = agg[metric] * scale
                std = agg.get(f"{metric}_stdev", 0) * scale
                row += f"{val:>{col_w-6}.2f}±{std:<5.1f}"
            else:
                row += f"{'N/A':>{col_w}}"
        print(row)

    print(f"{'─'*len(header)}\n")


def print_speedup_table(aggregated: Dict, baseline: str = "perf",
                        metric: str = "latency_p50_ns"):
    """Print speedup of each transport vs. baseline."""
    payloads = sorted(set(k[1] for k in aggregated))
    transports = [t for t in TRANSPORT_ORDER
                  if t != baseline and any(k[0] == t for k in aggregated)]

    print(f"\n  Speedup vs. {TRANSPORT_DISPLAY.get(baseline, baseline)} ({metric})")
    print(f"  (>1.0 = faster than baseline)\n")
    header = f"{'Payload':>8}  " + "".join(f"{t:>16}" for t in transports)
    print(header)
    print("─" * len(header))

    for payload in payloads:
        base_key = (baseline, payload)
        base_agg = aggregated.get(base_key)
        if not base_agg or metric not in base_agg or base_agg[metric] == 0:
            continue
        base_val = base_agg[metric]

        row = f"{payload:>6}B  "
        for t in transports:
            key = (t, payload)
            agg = aggregated.get(key)
            if agg and metric in agg and agg[metric] > 0:
                speedup = base_val / agg[metric]
                marker = "✓" if speedup > 1.0 else "✗"
                row += f"{speedup:>13.2f}x{marker} "
            else:
                row += f"{'N/A':>16}"
        print(row)
    print()


# ─── CSV export ───────────────────────────────────────────────────────────────
def export_csv(aggregated: Dict, out_path: str):
    rows = []
    for (transport, payload), agg in sorted(aggregated.items()):
        row = {
            "transport":        transport,
            "payload_size_B":   payload,
            "n_repeats":        agg.get("n_repeats", 0),
            "throughput_Keps":  agg.get("throughput_eps", 0) / 1e3,
            "throughput_MBps":  agg.get("throughput_mbps", 0),
            "drop_rate_pct":    agg.get("drop_rate_pct", 0),
            "lat_min_us":       agg.get("latency_min_ns", 0) / 1e3,
            "lat_p50_us":       agg.get("pooled_p50_ns", agg.get("latency_p50_ns", 0)) / 1e3,
            "lat_p90_us":       agg.get("pooled_p90_ns", agg.get("latency_p90_ns", 0)) / 1e3,
            "lat_p99_us":       agg.get("pooled_p99_ns", agg.get("latency_p99_ns", 0)) / 1e3,
            "lat_p999_us":      agg.get("pooled_p999_ns", agg.get("latency_p999_ns", 0)) / 1e3,
            "lat_mean_us":      agg.get("latency_mean_ns", 0) / 1e3,
            "lat_stdev_us":     agg.get("latency_stdev_ns_stdev", 0) / 1e3,
        }
        rows.append(row)

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV saved → {out_path}")


# ─── Summary statistics ────────────────────────────────────────────────────────
def print_summary(aggregated: Dict):
    print("\n" + "═"*72)
    print("  TOLLGATE — SUMMARY REPORT")
    print("═"*72)

    # Find system info from first result
    first = next(iter(aggregated.values()), {})
    if "hostname" in first:
        print(f"  Host:    {first.get('hostname', 'unknown')}")
        print(f"  Kernel:  {first.get('kernel', 'unknown')}")
        print(f"  CPUs:    {first.get('ncpus', 'unknown')}")
    print()

    # Best transport per metric
    best = {}
    for metric in ("latency_p50_ns", "latency_p99_ns", "throughput_eps", "drop_rate_pct"):
        best_key = None
        best_val = float("inf") if "lat" in metric or "drop" in metric else 0
        for key, agg in aggregated.items():
            if metric not in agg:
                continue
            val = agg[metric]
            if "lat" in metric or "drop" in metric:
                if val < best_val:
                    best_val, best_key = val, key
            else:
                if val > best_val:
                    best_val, best_key = val, key
        if best_key:
            scale = METRICS[metric]["scale"]
            unit  = METRICS[metric]["label"].split("(")[-1].rstrip(")")
            print(f"  Best {metric:30s}: {TRANSPORT_DISPLAY.get(best_key[0], best_key[0]):20s} "
                  f"@ {best_val*scale:.2f} {unit}  (payload={best_key[1]}B)")

    print()
    print_comparison_table(aggregated, "latency_p50_ns")
    print_comparison_table(aggregated, "latency_p99_ns")
    print_comparison_table(aggregated, "throughput_eps")
    print_speedup_table(aggregated, baseline="perf", metric="latency_p50_ns")


# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Analyze eBPF transport benchmark results")
    p.add_argument("input", nargs="+",
                   help="Result JSON files or directory")
    p.add_argument("--metric", default="latency_p99_ns",
                   choices=list(METRICS.keys()),
                   help="Primary metric for comparison tables")
    p.add_argument("--baseline", default="perf",
                   choices=TRANSPORT_ORDER,
                   help="Baseline transport for speedup table")
    p.add_argument("--csv", default=None,
                   help="Output CSV path")
    p.add_argument("--payload", type=int, default=None,
                   help="Filter to a single payload size")
    return p.parse_args()


def main():
    args = parse_args()

    # Load data
    if len(args.input) == 1 and os.path.isdir(args.input[0]):
        results = load_directory(args.input[0])
    else:
        results = load_results(args.input)

    if not results:
        print("No results to analyze.")
        sys.exit(1)

    # Group and aggregate
    groups     = group_runs(results, group_keys=("transport", "payload_size"))
    aggregated = {key: aggregate_group(runs) for key, runs in groups.items()}

    # Print report
    print_summary(aggregated)

    # Export CSV
    if args.csv:
        export_csv(aggregated, args.csv)
    else:
        export_csv(aggregated, "results_summary.csv")


if __name__ == "__main__":
    main()
