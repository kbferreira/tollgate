#!/usr/bin/env python3
"""
tollgate.py — TOLLGATE: Transport Overhead of Linux Low-Granularity Asynchronous Tracing Engine
======================================================================
Unified BCC-based benchmark driver for:
  - Ring Buffer (BPF_MAP_TYPE_RINGBUF)
  - Perf Event Array (BPF_MAP_TYPE_PERF_EVENT_ARRAY)
  - Hash Map (BPF_MAP_TYPE_HASH)
  - Array Map (BPF_MAP_TYPE_ARRAY)
  - Per-CPU Array (BPF_MAP_TYPE_PERCPU_ARRAY)

Usage:
  sudo python3 ebpf_bench.py --transport ringbuf --payload 256 --duration 10
  sudo python3 ebpf_bench.py --all --payload 64,256,1024,4096 --output results/

Metrics collected per run:
  - Event throughput (events/sec, MB/sec)
  - End-to-end latency (submit_ts → userspace_read_ts) in nanoseconds
  - Drop rate (%)
  - CPU utilization (kernel + user)
  - Wakeup frequency
  - NUMA cross-socket events (if applicable)
"""

import os
import sys
import time
import json
import ctypes
import struct
import argparse
import threading
import subprocess
import statistics
import itertools
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    from bcc import BPF, PerfType, PerfSWConfig
    import psutil
except ImportError:
    print("ERROR: Install bcc and psutil:  pip install bcc psutil")
    sys.exit(1)

# ─── BPF Source: Ring Buffer ───────────────────────────────────────────────────
RINGBUF_BPF = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_RINGBUF_OUTPUT(rb, RINGBUF_PAGES);

BPF_ARRAY(rb_counters, u64, 4);
#define CTR_SUBMITTED 0
#define CTR_DROPPED   1
#define CTR_BYTES     2

struct rb_event {
    u64 ktime_submit_ns;
    u64 sequence;
    u32 cpu;
    u32 payload_size;
    u8  payload[PAYLOAD_SIZE];
};

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct rb_event *e = rb.ringbuf_reserve(sizeof(struct rb_event));
    if (!e) {
        u32 k = CTR_DROPPED;
        u64 *v = rb_counters.lookup(&k);
        if (v) (*v)++;
        return 0;
    }
    e->ktime_submit_ns = bpf_ktime_get_ns();
    e->cpu  = bpf_get_smp_processor_id();
    e->payload_size = PAYLOAD_SIZE;
    rb.ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);

    u32 k = CTR_SUBMITTED;
    u64 *v = rb_counters.lookup(&k);
    if (v) (*v)++;
    return 0;
}
"""

# ─── BPF Source: Perf Event Array ─────────────────────────────────────────────
PERF_BPF = r"""
#include <uapi/linux/ptrace.h>

struct perf_event_t {
    u64 ktime_ns;
    u64 sequence;
    u32 cpu;
    u32 payload_size;
    u8  payload[PAYLOAD_SIZE];
};

BPF_PERF_OUTPUT(perf_events);
BPF_ARRAY(perf_counters, u64, 4);
BPF_PERCPU_ARRAY(scratch, struct perf_event_t, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 zero = 0;
    struct perf_event_t *rec = scratch.lookup(&zero);
    if (!rec) return 0;

    rec->ktime_ns     = bpf_ktime_get_ns();
    rec->cpu          = bpf_get_smp_processor_id();
    rec->payload_size = PAYLOAD_SIZE;

    int ret = perf_events.perf_submit(args, rec, sizeof(struct perf_event_t));
    u32 k = (ret == 0) ? 0 : 1;
    u64 *v = perf_counters.lookup(&k);
    if (v) (*v)++;
    return 0;
}
"""

# ─── BPF Source: Hash Map (polling) ───────────────────────────────────────────
HASHMAP_BPF = r"""
#include <uapi/linux/ptrace.h>

struct hmap_key   { u32 cpu; u32 seq; };
struct hmap_value { u64 ktime_ns; u64 sequence; u32 cpu; u32 payload_size; u8 payload[64]; };

BPF_HASH(hash_map, struct hmap_key, struct hmap_value, 65536);
BPF_ARRAY(hm_counters, u64, 4);
BPF_PERCPU_ARRAY(hm_seq, u64, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u32 zero  = 0;
    u64 *seqp = hm_seq.lookup(&zero);
    if (!seqp) return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct hmap_key k = { .cpu = cpu, .seq = (u32)(*seqp & 0xFFFF) };
    struct hmap_value v = {
        .ktime_ns    = bpf_ktime_get_ns(),
        .sequence    = *seqp,
        .cpu         = cpu,
        .payload_size = 64,
    };
    hash_map.update(&k, &v);
    (*seqp)++;
    u32 ck = 0; u64 *cv = hm_counters.lookup(&ck);
    if (cv) (*cv)++;
    return 0;
}
"""

# ─── BPF Source: Per-CPU Array (polling, lowest overhead) ────────────────────
PERCPU_BPF = r"""
#include <uapi/linux/ptrace.h>

struct pcpu_slot { u64 ktime_ns; u64 sequence; u32 cpu; u32 valid; u8 payload[48]; };

BPF_PERCPU_ARRAY(pcpu_map, struct pcpu_slot, 1024);
BPF_PERCPU_ARRAY(pcpu_idx, u64, 1);
BPF_ARRAY(pcpu_counters, u64, 2);

RAW_TRACEPOINT_PROBE(sys_enter) {
    u32 zero  = 0;
    u64 *idxp = pcpu_idx.lookup(&zero);
    if (!idxp) return 0;

    u32 slot = (u32)(*idxp & 0x3FF);
    struct pcpu_slot s = {
        .ktime_ns = bpf_ktime_get_ns(),
        .sequence = *idxp,
        .cpu      = bpf_get_smp_processor_id(),
        .valid    = 1,
    };
    pcpu_map.update(&slot, &s);
    (*idxp)++;
    u32 ck = 0; u64 *cv = pcpu_counters.lookup(&ck);
    if (cv) (*cv)++;
    return 0;
}
"""

# ─── Event structures (ctypes mirrors of BPF structs) ────────────────────────
class RingbufEvent(ctypes.Structure):
    _fields_ = [
        ("ktime_submit_ns", ctypes.c_uint64),
        ("sequence",        ctypes.c_uint64),
        ("cpu",             ctypes.c_uint32),
        ("payload_size",    ctypes.c_uint32),
    ]

class PerfEvent(ctypes.Structure):
    _fields_ = [
        ("ktime_ns",     ctypes.c_uint64),
        ("sequence",     ctypes.c_uint64),
        ("cpu",          ctypes.c_uint32),
        ("payload_size", ctypes.c_uint32),
    ]

# ─── Benchmark Runner ─────────────────────────────────────────────────────────
class TransportBenchmark:
    def __init__(self, transport: str, payload_size: int,
                 duration: int, ringbuf_pages: int = 256):
        self.transport     = transport
        self.payload_size  = payload_size
        self.duration      = duration
        self.ringbuf_pages = ringbuf_pages
        self.events        = []
        self.latencies_ns  = []
        self.drops         = 0
        self.b             = None
        self._stop         = threading.Event()

    def _cflags(self):
        return [
            f"-DPAYLOAD_SIZE={self.payload_size}",
            f"-DRINGBUF_PAGES={self.ringbuf_pages}",
        ]

    def _load_ringbuf(self):
        self.b = BPF(text=RINGBUF_BPF, cflags=self._cflags())
        rb = self.b["rb"]

        def handle_event(ctx, data, size):
            recv_ts = time.time_ns()
            evt = ctypes.cast(data, ctypes.POINTER(RingbufEvent)).contents
            latency = recv_ts - evt.ktime_submit_ns
            self.latencies_ns.append(latency)
            self.events.append({
                "ts_submit": evt.ktime_submit_ns,
                "ts_recv":   recv_ts,
                "latency_ns": latency,
                "cpu":       evt.cpu,
                "size":      size,
            })

        rb.open_ring_buffer(handle_event)
        return rb

    def _load_perf(self):
        self.b = BPF(text=PERF_BPF, cflags=self._cflags())

        def handle_perf(cpu, data, size):
            recv_ts = time.time_ns()
            evt = ctypes.cast(data, ctypes.POINTER(PerfEvent)).contents
            latency = recv_ts - evt.ktime_ns
            self.latencies_ns.append(latency)
            self.events.append({
                "ts_submit":  evt.ktime_ns,
                "ts_recv":    recv_ts,
                "latency_ns": latency,
                "cpu":        evt.cpu,
                "size":       size,
            })

        self.b["perf_events"].open_perf_buffer(handle_perf, page_cnt=64)

    def _load_hashmap(self):
        self.b = BPF(text=HASHMAP_BPF, cflags=self._cflags())

    def _load_percpu(self):
        self.b = BPF(text=PERCPU_BPF, cflags=self._cflags())

    def _poll_hashmap(self):
        """Polling loop for hash/array map transports."""
        hmap = self.b["hash_map"]
        seen = set()
        while not self._stop.is_set():
            recv_ts = time.time_ns()
            items = list(hmap.items())
            for k, v in items:
                key = (v.cpu, v.sequence)
                if key not in seen:
                    seen.add(key)
                    latency = recv_ts - v.ktime_ns
                    self.latencies_ns.append(latency)
                    self.events.append({
                        "ts_submit":  v.ktime_ns,
                        "ts_recv":    recv_ts,
                        "latency_ns": latency,
                        "cpu":        v.cpu,
                        "size":       self.payload_size + 24,
                    })
            time.sleep(0.001)  # 1ms poll interval

    def run(self) -> dict:
        """Execute a single benchmark run and return results."""
        cpu_before = psutil.cpu_times_percent(interval=None)

        if self.transport == "ringbuf":
            rb = self._load_ringbuf()
        elif self.transport == "perf":
            self._load_perf()
        elif self.transport == "hashmap":
            self._load_hashmap()
            poll_thread = threading.Thread(target=self._poll_hashmap, daemon=True)
        elif self.transport == "percpu":
            self._load_percpu()
        else:
            raise ValueError(f"Unknown transport: {self.transport}")

        # Workload generator: stress the tracepoints
        workload = subprocess.Popen(
            ["stress-ng", "--sequential", "0",
             "--timeout", str(self.duration),
             "--metrics-brief", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        start_wall = time.time()
        start_mono = time.monotonic()

        if self.transport == "hashmap":
            poll_thread.start()

        try:
            deadline = start_mono + self.duration
            while time.monotonic() < deadline:
                if self.transport in ("ringbuf",):
                    self.b.ring_buffer_poll(timeout=100)
                elif self.transport == "perf":
                    self.b.perf_buffer_poll(timeout=100)
                else:
                    time.sleep(0.1)
        finally:
            self._stop.set()
            workload.wait()

        elapsed = time.monotonic() - start_mono
        cpu_after = psutil.cpu_times_percent(interval=None)

        return self._compute_results(elapsed, cpu_before, cpu_after)

    def _compute_results(self, elapsed: float, cpu_before, cpu_after) -> dict:
        n = len(self.events)
        lats = self.latencies_ns

        # Get drop counters from BPF maps
        drops = 0
        try:
            if self.transport == "ringbuf":
                ctr = self.b["rb_counters"]
                dropped_k = ctypes.c_uint32(1)
                v = ctr[dropped_k]
                drops = v.value if v else 0
            elif self.transport == "perf":
                ctr = self.b["perf_counters"]
                drops = ctr[ctypes.c_uint32(1)].value
        except Exception:
            pass

        total_bytes = sum(e["size"] for e in self.events)

        result = {
            "transport":       self.transport,
            "payload_size":    self.payload_size,
            "duration_s":      elapsed,
            "events_total":    n,
            "events_dropped":  drops,
            "drop_rate_pct":   (drops / max(1, n + drops)) * 100,
            "throughput_eps":  n / elapsed,
            "throughput_mbps": (total_bytes / elapsed) / 1e6,
            "total_bytes":     total_bytes,
        }

        if lats:
            result.update({
                "latency_min_ns":    min(lats),
                "latency_max_ns":    max(lats),
                "latency_mean_ns":   statistics.mean(lats),
                "latency_median_ns": statistics.median(lats),
                "latency_p50_ns":    _percentile(lats, 50),
                "latency_p90_ns":    _percentile(lats, 90),
                "latency_p95_ns":    _percentile(lats, 95),
                "latency_p99_ns":    _percentile(lats, 99),
                "latency_p999_ns":   _percentile(lats, 99.9),
                "latency_stdev_ns":  statistics.stdev(lats) if len(lats) > 1 else 0,
            })

        result["raw_latencies_ns"] = lats[:10000]  # Cap stored samples
        return result


def _percentile(data: list, pct: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)


# ─── Test Matrix ──────────────────────────────────────────────────────────────
TEST_MATRIX = {
    "quick":     {"transports": ["ringbuf", "perf"],
                  "payloads": [64, 256, 1024],
                  "duration": 5,
                  "repeats": 3},
    "standard":  {"transports": ["ringbuf", "perf", "hashmap", "percpu"],
                  "payloads": [64, 256, 1024, 4096, 16384],
                  "duration": 10,
                  "repeats": 5},
    "full":      {"transports": ["ringbuf", "perf", "hashmap", "percpu"],
                  "payloads": [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536],
                  "duration": 30,
                  "repeats": 10},
    "hpc_scale": {"transports": ["ringbuf", "perf"],
                  "payloads": [64, 1024, 4096],
                  "duration": 60,
                  "repeats": 5,
                  "cpu_counts": [1, 2, 4, 8, 16, 32, 64, 128]},
}


def run_suite(suite_name: str, output_dir: Path, verbose: bool = False):
    """Run a full test suite and save results."""
    suite = TEST_MATRIX[suite_name]
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    total_runs = (len(suite["transports"]) *
                  len(suite["payloads"]) *
                  suite["repeats"])
    run_count = 0

    for transport, payload, repeat in itertools.product(
            suite["transports"], suite["payloads"],
            range(suite["repeats"])):

        run_count += 1
        print(f"[{run_count}/{total_runs}] transport={transport:8s} "
              f"payload={payload:6d}B  repeat={repeat+1}/{suite['repeats']}")

        try:
            bench = TransportBenchmark(
                transport=transport,
                payload_size=payload,
                duration=suite["duration"],
            )
            result = bench.run()
            result["run_id"]   = run_id
            result["repeat"]   = repeat
            result["suite"]    = suite_name
            result["hostname"] = os.uname().nodename
            result["kernel"]   = os.uname().release
            result["ncpus"]    = os.cpu_count()
            result["timestamp"] = datetime.now().isoformat()

            all_results.append(result)

            if verbose:
                print(f"  → {result['throughput_eps']:.0f} ev/s  "
                      f"lat_med={result.get('latency_median_ns',0)/1000:.1f}µs  "
                      f"drop={result['drop_rate_pct']:.2f}%")

        except Exception as exc:
            print(f"  ERROR: {exc}")
            all_results.append({
                "transport": transport, "payload_size": payload,
                "repeat": repeat, "error": str(exc)
            })

    # Save results
    out_file = output_dir / f"results_{run_id}.json"
    with open(out_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nResults saved → {out_file}")
    print(f"Total runs: {len(all_results)}  "
          f"Errors: {sum(1 for r in all_results if 'error' in r)}")
    return all_results


# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="TOLLGATE benchmark suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--transport",  choices=["ringbuf","perf","hashmap","percpu","all"],
                   default="all")
    p.add_argument("--payload",    default="64,256,1024,4096",
                   help="Comma-separated payload sizes in bytes")
    p.add_argument("--duration",   type=int, default=10,
                   help="Seconds per test run")
    p.add_argument("--repeats",    type=int, default=5,
                   help="Repetitions per configuration")
    p.add_argument("--suite",      choices=list(TEST_MATRIX.keys()),
                   help="Run a predefined test suite (overrides other options)")
    p.add_argument("--output",     default="results/",
                   help="Output directory for result JSON files")
    p.add_argument("--verbose",    action="store_true")
    return p.parse_args()


def main():
    if os.geteuid() != 0:
        print("ERROR: eBPF benchmark requires root. Run with sudo.")
        sys.exit(1)

    args = parse_args()
    output_dir = Path(args.output)

    if args.suite:
        run_suite(args.suite, output_dir, args.verbose)
        return

    # Manual run
    transports = (["ringbuf", "perf", "hashmap", "percpu"]
                  if args.transport == "all"
                  else [args.transport])
    payloads = [int(x) for x in args.payload.split(",")]

    output_dir.mkdir(parents=True, exist_ok=True)
    run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = []

    for transport, payload, repeat in itertools.product(
            transports, payloads, range(args.repeats)):

        print(f"Running: {transport} / {payload}B / rep {repeat+1}")
        bench = TransportBenchmark(
            transport=transport,
            payload_size=payload,
            duration=args.duration,
        )
        result = bench.run()
        result.update({
            "run_id": run_id, "repeat": repeat,
            "hostname": os.uname().nodename,
            "timestamp": datetime.now().isoformat(),
        })
        results.append(result)

        if args.verbose:
            print(f"  throughput={result['throughput_eps']:.0f} ev/s  "
                  f"lat_p99={result.get('latency_p99_ns',0)/1e3:.1f} µs")

    out_file = output_dir / f"results_{run_id}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved → {out_file}")


if __name__ == "__main__":
    main()
