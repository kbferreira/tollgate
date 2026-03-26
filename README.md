# TOLLGATE
### Transport Overhead of Linux Low-Granularity Asynchronous Tracing Engine

*A systematic benchmark suite for characterizing eBPF kernel-to-userspace data transport overhead in High-Performance Computing environments.*

---

## Quick Start

```bash
# 1. Check environment
make check

# 2. Install Python dependencies
make install

# 3. Build eBPF objects and userspace tools
make

# 4. Run quick smoke test (~5 min)
sudo bash scripts/run_tests.sh quick

# 5. Full benchmark suite (~6–8 hours)
sudo bash scripts/run_tests.sh all

# 6. Analyze and plot results
python3 scripts/analyze.py results/
python3 scripts/plot.py results_summary.csv
```

---

## Project Structure

```
tollgate/
├── src/
│   ├── ebpf/
│   │   ├── ringbuf_kern.c          eBPF ring buffer program
│   │   ├── perf_array_kern.c       eBPF perf event array program
│   │   └── hashmap_kern.c          eBPF hash/array map programs
│   ├── userspace/
│   │   └── ringbuf_user.c          C libbpf userspace loader (nanosecond-accurate)
│   └── bcc/
│       └── benchmark.py            BCC Python unified benchmark driver
├── scripts/
│   ├── run_tests.sh                Main test runner (handles system tuning)
│   ├── analyze.py                  Aggregate JSON results → statistics + CSV
│   └── plot.py                     Generate all publication-quality figures
├── docs/
│   ├── test_plan.md                10 test cases with pass/fail criteria
│   └── research_plan.md            Full research plan with hypotheses + timeline
├── configs/                        Per-system tuning configs
├── results/                        Output JSON files (auto-created)
├── figures/                        Output plots (auto-created)
└── Makefile
```

---

## Transport Mechanisms Under Test

| Mechanism | Map Type | Wakeup | Best For |
|-----------|----------|--------|---------|
| **Ring Buffer** | `BPF_MAP_TYPE_RINGBUF` | epoll (push) | Low latency streaming |
| **Perf Event Array** | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Per-CPU mmap | Legacy compat, per-CPU data |
| **Hash Map** | `BPF_MAP_TYPE_HASH` | Poll | Aggregated stats |
| **Per-CPU Array** | `BPF_MAP_TYPE_PERCPU_ARRAY` | Poll | Lowest-overhead counters |

---

## Test Suites

| Suite | Duration | Use Case |
|-------|---------|---------|
| `quick` | ~5 min | Smoke test / CI |
| `standard` | ~1 hour | Development benchmarking |
| `full` | ~6 hours | Publication data |
| `numa` | ~2 hours | NUMA topology analysis |
| `hpc_scale` | ~3 hours | CPU count scaling |
| `all` | ~8 hours | Complete characterization |

---

## Figures Generated

| File | Description |
|------|-------------|
| `01_latency_cdf.png` | CDF of end-to-end latency per transport |
| `02_latency_vs_payload.png` | P50 and P99 latency vs payload size |
| `03_throughput_vs_payload.png` | Event rate and bandwidth vs payload size |
| `04_drop_rate.png` | Drop rate vs payload size |
| `05_latency_boxplot.png` | Latency distribution box plots |
| `06_latency_heatmap.png` | P99 heatmap (transport × payload) |
| `07_speedup_bar.png` | Speedup relative to perf event array baseline |
| `08_latency_histogram.png` | Log2-binned latency histograms |
| `09_latency_breakdown.png` | Min/P50/P90/P99 stacked comparison |

---

## System Requirements

- **Linux 5.8+** (for ring buffer; 5.15 LTS recommended)
- **Root / CAP_BPF** for eBPF loading
- **clang ≥ 14** for eBPF compilation
- **libbpf-dev** for C userspace loader
- **python3-bcc** for BCC benchmark driver
- **stress-ng** for workload generation
- **numactl** for NUMA tests

```bash
# Ubuntu/Debian:
apt install clang libbpf-dev linux-tools-common linux-headers-$(uname -r) \
            python3-bcc stress-ng numactl bpftool

# RHEL/Rocky:
dnf install clang bcc-tools bcc-devel stress-ng numactl bpftool \
            kernel-devel-$(uname -r)
```

---

## HPC Cluster Usage (SLURM)

```bash
make slurm           # generates slurm_*.sh scripts
sbatch slurm_standard.sh
sbatch slurm_full.sh
```

---

## Name

**TOLLGATE** — every eBPF event pays a toll to cross the kernel/userspace boundary.  
This project measures exactly how much that toll costs at HPC scale.

---

## License
GPL-2.0 (matching Linux kernel eBPF programs)
