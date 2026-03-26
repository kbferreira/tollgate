# TOLLGATE Research Plan: Transport Overhead of Linux Low-Granularity Asynchronous Tracing Engine
**Status:** Active  
**Domain:** Systems Performance / High-Performance Computing  
**Security Context:** This research involves kernel instrumentation; results may be sensitive in classified system contexts.

---

## 1. Research Problem Statement

HPC applications increasingly rely on eBPF for live performance monitoring, fault detection, and adaptive runtime tuning. However, **the cost of moving data from the kernel (where eBPF executes) to userspace (where analysis occurs) is not well characterized at HPC scale.** Existing eBPF transport benchmarks focus on network observability workloads (low CPU count, moderate event rates). HPC workloads present qualitatively different challenges:

- **Extreme parallelism:** 128–256+ cores generating concurrent events
- **NUMA sensitivity:** Multi-socket systems where map memory placement matters
- **Low-tolerance for interference:** eBPF monitoring must not perturb the application being monitored
- **Large data volumes:** HPC performance counters can require multi-KB records
- **Tight latency requirements:** Adaptive runtime systems need < 10µs feedback loops

**Central research question:**  
*What is the minimum achievable overhead (latency, CPU burn, memory bandwidth) of each eBPF transport mechanism, and how does that overhead scale with core count and NUMA topology on large HPC systems?*

---

## 2. Research Hypotheses

**H1:** Ring buffer (`BPF_MAP_TYPE_RINGBUF`) provides the lowest latency at all payload sizes due to its single-copy, epoll-based wakeup model — but exhibits higher tail latency variance than perf event array at high event rates due to shared ring contention.

**H2:** Perf event array's per-CPU ring design provides better throughput scaling on large CPU counts than the shared ring buffer, but at the cost of higher baseline latency and more complex consumer code.

**H3:** NUMA-remote ring buffer access (kernel submits on Node 0, userspace reads on Node 1) increases P99 latency by ≥ 2× compared to NUMA-local access.

**H4:** For payload sizes < 256B, the dominant overhead component is wakeup/scheduling latency, not data copy. For payload sizes > 4KB, the dominant component shifts to memory bandwidth.

**H5:** At ≥ 64 parallel producers, ring buffer lock contention becomes the primary bottleneck, causing super-linear throughput degradation.

---

## 3. Related Work Gap Analysis

| Area | Prior Work | Gap Addressed Here |
|------|-----------|-------------------|
| eBPF for network observability | Cilium, Katran, bpftrace | HPC workloads not studied |
| perf subsystem overhead | Weaver et al. (2013) | eBPF abstraction layer overhead not measured |
| Ring buffer vs queues | Linux kernel commit history | No systematic latency characterization |
| HPC monitoring overhead | PAPI, LDMS, Spack Monitor | eBPF-specific transport not analyzed |
| NUMA effects on BPF maps | None found | Novel contribution |
| CPU scaling of eBPF programs | Gregg (BPF Performance Tools) | HPC core counts (64–256) not studied |

**Novelty:** This work is the first systematic characterization of eBPF transport overhead specifically at HPC scale, with NUMA analysis and large-payload testing.

---

## 4. Experimental Design

### 4.1 Target Systems

| System Tier | CPU | Cores | NUMA | RAM | Notes |
|-------------|-----|-------|------|-----|-------|
| Workstation (dev) | Intel Core i9-13900K | 24 | 1 | 64 GB | Initial development |
| Medium Node | AMD EPYC 7543 (dual socket) | 64 | 2 | 256 GB | Primary benchmark |
| Large HPC Node | AMD EPYC 9654 (dual socket) | 192 | 2–4 | 768 GB | Scale test |
| ARM HPC Node | Fujitsu A64FX | 48 | 4 | 32 GB HBM | Architecture comparison |

All tests require Linux 5.15+ (LTS) with `CONFIG_BPF_RINGBUF=y`, `CONFIG_DEBUG_INFO_BTF=y`.

### 4.2 Controlled Variables

These are held constant within a test configuration:
- Kernel version (pinned via `grub` entry or container)
- CPU frequency governor (set to `performance`)
- NUMA memory policy (`numactl --membind=N` for NUMA tests)
- Workload generator (`stress-ng` with fixed seed)
- Ring buffer size (4MB default; varied only in TC-04)
- Userspace consumer CPU pinning (`taskset`)

### 4.3 Independent Variables (what we sweep)

| Variable | Range |
|----------|-------|
| Transport mechanism | ring buffer, perf array, hash map, per-CPU array |
| Payload size (bytes) | 64, 128, 256, 512, 1K, 2K, 4K, 8K, 16K, 64K |
| CPU count (producers) | 1, 2, 4, 8, 16, 32, 64, 128, 192 |
| NUMA configuration | local, remote, interleaved |
| Wakeup strategy | forced, deferred, timed-poll |
| Ring buffer size | 1MB, 4MB, 16MB, 64MB |

### 4.4 Dependent Variables (what we measure)

**Primary:**
- End-to-end latency: `ktime_submit_ns` (kernel) → `clock_gettime` (userspace)
- Throughput: events/second, MB/second
- Drop rate: dropped / (dropped + delivered) × 100%

**Secondary:**
- CPU utilization of consumer process (via `/proc/stat` delta)
- Context switches per second (via `perf stat -e context-switches`)
- Cache miss rate (via `perf stat -e cache-misses`)
- Memory bandwidth (via `perf stat -e mem-loads,mem-stores`)
- BPF program runtime (via `bpf_stats_enabled`)
- Ring buffer high-water mark occupancy

### 4.5 Statistical Methodology

- **Minimum 5 independent runs** per configuration; 10 runs for primary metrics
- **Discard first run** (JIT warm-up, cache cold state)
- **Report:** mean ± standard deviation, plus P50/P90/P95/P99/P99.9 percentiles
- **Outlier handling:** Report but do not remove; flag using Grubbs' test (α=0.05)
- **Confidence intervals:** 95% CI via bootstrap resampling (10,000 samples)
- **Normality test:** Shapiro-Wilk; use Mann-Whitney U test for non-normal distributions when comparing mechanisms
- **Effect size:** Cohen's d for pairwise latency comparisons

---

## 5. Measurement Methodology & Noise Reduction

### 5.1 Timestamp Accuracy

The latency measurement chain has three components with different error characteristics:

```
[BPF program: bpf_ktime_get_ns()]
        ↓  (kernel ring → mmap / epoll)
[Userspace wakeup: clock_gettime(CLOCK_MONOTONIC)]
        ↓  (C struct parse)
[Record: recv_ts - submit_ts = measured latency]
```

Known biases:
- `bpf_ktime_get_ns()` uses `ktime_get()` — same clock source as `CLOCK_MONOTONIC` on x86, so no cross-clock bias
- `clock_gettime()` overhead: ~5–15ns (measured separately via calibration run)
- Epoll/scheduler wakeup latency: 5–200µs (dominant term; what we're actually measuring)

**Calibration run:** Before each suite, run a null eBPF program (submits empty event, no tracepoint firing) to measure the minimum observable latency floor.

### 5.2 System Noise Mitigation

```bash
# In run_tests.sh — applied before each test suite:
echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo  # Intel
echo -1 > /proc/sys/kernel/perf_event_paranoid
echo 0 > /proc/sys/kernel/randomize_va_space
systemctl stop irqbalance
# Pin IRQs away from measurement CPUs
for irq in /proc/irq/*/smp_affinity; do echo 1 > $irq 2>/dev/null; done
```

### 5.3 HPC-Specific Considerations

On large cluster nodes, additional sources of noise include:
- **Background daemons** (cron, syslog, NFS, Lustre/GPFS client): record active daemons in sysinfo snapshot
- **Network interrupts** from InfiniBand/Omni-Path: pin network IRQs away from measurement CPUs
- **BMC/IPMI activity**: cannot be controlled; note in run metadata
- **Memory ECC scrubbing**: occurs every 24h on some systems; schedule runs to avoid

---

## 6. Data Analysis Pipeline

```
Raw JSON runs
      ↓
scripts/analyze.py
      ↓ (aggregation, percentiles, pooled CDFs)
results_summary.csv
      ↓
scripts/plot.py
      ↓
figures/ (10 publication-quality plots)
      ↓
LaTeX / Markdown report template
```

### 6.1 Primary Analysis Questions (mapped to figures)

| Question | Figure | Analysis Method |
|---------|--------|----------------|
| Which transport has lowest tail latency? | Fig 6 (heatmap) | Pairwise Mann-Whitney U |
| How does latency scale with payload? | Fig 2 | Log-log regression slope |
| Where does ring buffer saturate? | Fig 3 | Knee detection in throughput curve |
| What is the NUMA penalty? | Fig 9 | % increase in P99 local vs remote |
| Which transport scales best with CPUs? | Fig 10 | Amdahl's law fit |
| Is ring buffer always faster than perf array? | Fig 7 | Speedup ratio with CI |

### 6.2 Regression Model

Fit a linear model to latency as a function of payload size to decompose overhead into:

```
latency(bytes) = α  +  β × bytes
                 ↑          ↑
           fixed overhead  per-byte copy cost
```

This allows estimating: (a) minimum wakeup cost (α, at zero payload), (b) memory bandwidth required (1/β × clock_rate).

---

## 7. Expected Results & Impact

### 7.1 Predicted Performance Ranking

Based on kernel internals analysis (before experiments):

```
Ring Buffer > Perf Event Array > Per-CPU Array >> Hash Map
(lower latency → higher latency)
```

Ring buffer wins because:
- Single copy path (kernel → ring → mmap)
- Shared ring with spin lock vs per-CPU (avoids N wakeup calls)
- epoll integration without per-event system call overhead

### 7.2 Expected NUMA Impact

On a 2-socket AMD EPYC system with 95ns NUMA penalty:
- Expected latency increase: +1–5% for P50 (latency dominated by wakeup, not copy)
- Expected latency increase: +20–50% for large payloads (> 4KB) where copy cost dominates

### 7.3 Impact on HPC Community

**If ring buffer is confirmed as optimal:**
- Recommend `BPF_MAP_TYPE_RINGBUF` as the standard for all HPC eBPF monitoring
- Provide ring buffer sizing formula based on core count and event rate

**If NUMA penalty is significant (> 2×):**
- Recommend per-socket ring buffers with NUMA-local reader threads
- This has implications for tools like bpftrace, Falco, and custom HPC monitors

**If CPU scaling breaks down at N > 32:**
- Recommend partitioning the ring by CPU group
- Motivates upstream kernel work on per-NUMA-domain ring buffers

---

## 8. Publication & Dissemination Plan

### 8.1 Target Venues

| Venue | Type | Deadline (approx) |
|-------|------|-------------------|
| SC (Supercomputing) | Conference | April |
| EuroSys | Conference | October |
| USENIX ATC | Conference | January |
| IEEE TPDS | Journal | Rolling |
| LSF/MM/BPF Summit | Workshop | February |

### 8.2 Open Source Release

All benchmark code, data, and analysis scripts will be published at:
- GitHub: `github.com/[org]/tollgate`
- Zenodo DOI for reproducibility archive
- Compatible with: bpftrace, libbpf, BCC Python

### 8.3 Artifacts Checklist

Per reproducibility requirements (SC Artifacts evaluation):
- [ ] Benchmark source code (this repository)
- [ ] Raw result JSON files from all test runs
- [ ] System configuration scripts
- [ ] Docker/Singularity container image with all dependencies
- [ ] Makefile that reproduces all figures from raw data
- [ ] README with exact commands to reproduce each figure

---

## 9. Timeline

| Month | Milestone |
|-------|-----------|
| M1 | eBPF programs written, BCC Python harness complete, TC-01 baseline done |
| M2 | TC-02 (CPU scaling), TC-03 (NUMA) complete; first-pass analysis |
| M3 | TC-04 through TC-06 complete; draft figures |
| M4 | TC-07 through TC-10 complete; statistical analysis |
| M5 | Writing, peer review, revision |
| M6 | Submission + artifact packaging |

---

## 10. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Kernel upgrade changes ring buffer behavior | Medium | High | Pin kernel version; test on LTS only |
| BCC Python adds measurement noise | Medium | Medium | Validate with C libbpf userspace loader (ringbuf_user.c) |
| HPC cluster downtime during test window | High | Medium | Run development tests on local workstation; use SLURM reservations |
| NUMA test results machine-specific | Medium | Medium | Test on ≥ 2 different architectures (x86, ARM) |
| Ring buffer contention not reproducible | Low | High | Use deterministic workload (stress-ng --seed) |
| Security classification limits publication | Medium | High | Use only unclassified systems; design for open publication from the start |

---

## 11. References (Background Reading)

- Starovoitov, A. et al. *BPF ring buffer* (2020). kernel.org/doc/html/latest/bpf/ringbuf.html  
- Gregg, B. *BPF Performance Tools* (2019). Addison-Wesley.  
- Gregg, B. *Systems Performance, 2nd ed.* (2020). Addison-Wesley.  
- Miano, S. et al. *Making eBPF Programmable Networks a Reality*. SIGCOMM (2021).  
- Fleming, J. *A thorough introduction to eBPF*. LWN.net (2017).  
- Linux Kernel Documentation: `Documentation/bpf/ringbuf.rst`  
- perf_event_open(2) man page — wakeup watermark semantics  
- Lameter, C. *NUMA (Non-Uniform Memory Access)* (2013). LWN.net  
