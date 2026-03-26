# TOLLGATE — Test Plan
**Version:** 1.0  
**Context:** High-Performance Computing (HPC) — Large Parallel Systems  
**Goal:** Measure and compare end-to-end overhead of all major eBPF kernel-to-userspace data transport mechanisms under realistic HPC workload conditions.

---

## 1. Objectives

1. Quantify the latency and throughput overhead of each transport mechanism at HPC-relevant payload sizes and event rates.
2. Identify bottlenecks introduced by each mechanism under parallel, multi-CPU conditions representative of large HPC nodes (128–256 core systems).
3. Characterize NUMA sensitivity of each transport (critical on multi-socket HPC nodes).
4. Provide actionable guidance for selecting transport mechanisms in production HPC eBPF instrumentation.

---

## 2. Transport Mechanisms Under Test

| ID | Mechanism | Map Type | Wakeup Model | Kernel Version |
|----|-----------|----------|--------------|----------------|
| T1 | **Ring Buffer** | `BPF_MAP_TYPE_RINGBUF` | Epoll/wakeup or polling | 5.8+ |
| T2 | **Perf Event Array** | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Per-CPU mmap ring + wakeup | 4.4+ |
| T3 | **Hash Map** | `BPF_MAP_TYPE_HASH` | Userspace polling | 3.18+ |
| T4 | **Per-CPU Array** | `BPF_MAP_TYPE_PERCPU_ARRAY` | Userspace polling | 4.6+ |
| T5 | **Array Map** | `BPF_MAP_TYPE_ARRAY` | Userspace polling (ring-style) | 3.18+ |

---

## 3. Test Cases

### TC-01: Baseline Single-CPU Latency Sweep
**Purpose:** Establish baseline latency for each transport without contention.  
**Parameters:**  
- Payloads: 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536 bytes  
- CPUs: 1 (pinned)  
- Duration: 30 seconds per configuration  
- Repeats: 10  
- Tracepoint: `syscalls/sys_enter_write`  

**Metrics collected:** Latency (min/P50/P90/P95/P99/P99.9/max), throughput (ev/s, MB/s), drop rate  
**Pass criteria:** P99 latency < 100µs at 64B payload for ring buffer; < 500µs for polling mechanisms.

---

### TC-02: Multi-CPU Throughput Scaling
**Purpose:** Measure throughput as a function of CPU count; identify saturation point.  
**Parameters:**  
- Payloads: 64, 256, 1024, 4096 bytes  
- CPU counts: 1, 2, 4, 8, 16, 32, 64, 128 (stop at system max)  
- Duration: 30 seconds  
- Repeats: 5  
- Method: Pin benchmark to first N CPUs via `taskset`  

**Metrics:** Throughput (ev/s) vs CPU count; speedup efficiency `E = T_N / (N × T_1)`  
**HPC relevance:** Simulates N parallel MPI ranks all emitting eBPF events simultaneously.  
**Expected result:** Ring buffer maintains near-linear scaling; perf event array degrades past ~16 CPUs due to wakeup storm.

---

### TC-03: NUMA Topology Impact
**Purpose:** Quantify latency penalty when submitting eBPF events from CPU on one NUMA node while userspace reader is on another.  
**Parameters:**  
- Payloads: 64, 1024, 4096 bytes  
- NUMA configurations: local (same node), cross-node (kernel CPU 0, reader CPU max)  
- Duration: 30 seconds  
- Repeats: 10  
- Tool: `numactl --cpunodebind=N --membind=N`  

**Metrics:** Latency comparison (local vs remote), NUMA miss rate (via `perf stat -e node-load-misses`)  
**HPC relevance:** Critical for multi-socket AMD EPYC / Intel Xeon HPC nodes.

---

### TC-04: High-Frequency Event Storm
**Purpose:** Stress-test transports at maximum kernel event rates; measure drop rates.  
**Parameters:**  
- Payload: 64 bytes (minimum)  
- Tracepoints: `raw_syscalls/sys_enter` (highest frequency) + `sched/sched_switch`  
- Duration: 60 seconds  
- Userspace consumer: single-threaded (to create backpressure)  
- Ring buffer size: 4MB, 8MB, 16MB variants  

**Metrics:** Drop rate (%), maximum sustainable throughput, ring buffer utilization %  
**Pass criteria:** Ring buffer < 1% drops at 4MB ring size with 64B payload.

---

### TC-05: Large Payload Latency (HPC Data Transport)
**Purpose:** Simulate HPC performance counters / profiling data requiring large records.  
**Parameters:**  
- Payloads: 4096, 8192, 16384, 65536 bytes  
- Transports: ring buffer only (perf event array max is 64KB)  
- Duration: 30 seconds  
- Repeats: 5  

**Metrics:** Throughput (MB/s), P99 latency  
**Note:** Hash/Array maps use fixed 64B record size and are excluded from large-payload tests.

---

### TC-06: Wakeup Latency vs Polling Interval
**Purpose:** Isolate the cost of different consumer wakeup strategies.  
**Sub-tests:**  
- T6a: Ring buffer with `BPF_RB_FORCE_WAKEUP` (per-event epoll wakeup)  
- T6b: Ring buffer with `BPF_RB_NO_WAKEUP` + periodic poll (0.1ms, 1ms, 5ms, 10ms intervals)  
- T6c: Perf event array with default wakeup watermark  
- T6d: Hash map polling at 0.1ms, 1ms, 10ms intervals  

**Metrics:** Latency per mode, CPU utilization per mode, events-per-wakeup ratio  
**HPC relevance:** Polling vs interrupt tradeoff is critical for HPC where CPU cycles are precious.

---

### TC-07: Concurrent Producer Contention
**Purpose:** Measure lock contention in ring buffer under parallel producers (simulates MPI allreduce + eBPF simultaneously).  
**Parameters:**  
- 16 concurrent `stress-ng` worker threads generating syscalls  
- Payloads: 64, 256, 1024 bytes  
- Duration: 60 seconds  
- Monitor: `bpf_stats` for program runtime, `lockstat` for map lock contention  

**Metrics:** Throughput degradation vs single-producer baseline, tail latency inflation, lock hold time via `bpf_stats_enabled`  

---

### TC-08: Kernel Version Regression Test
**Purpose:** Verify performance is consistent (or improving) across kernel versions.  
**Kernel targets:**  
- 5.8 (ring buffer introduction)  
- 5.15 (LTS)  
- 6.1 (LTS)  
- 6.6 (LTS, current mainline focus)  
- Latest  

**Method:** Run TC-01 and TC-04 on each kernel version in a VM or container.  
**Metrics:** P50/P99 latency, throughput at 256B payload.

---

### TC-09: CPU Isolation Mode (Production HPC Simulation)
**Purpose:** Measure overhead when eBPF consumer is pinned to an isolated CPU (as done in production HPC systems).  
**Parameters:**  
- Isolate CPUs N-1 (or last NUMA node CPU) via `isolcpus` or cgroups  
- Pin userspace reader to isolated CPU  
- All other CPUs run computation workload  
- Duration: 60 seconds  

**Metrics:** Latency (µs), interference on computation workload (via `perf stat`)  

---

### TC-10: Memory Pressure Test
**Purpose:** Measure transport overhead under memory pressure (relevant for memory-bound HPC jobs).  
**Parameters:**  
- Background: `stress-ng --vm N --vm-bytes 80%` consuming 80% of RAM  
- Payload: 1024 bytes  
- Duration: 30 seconds  
- Transports: all  

**Metrics:** Latency inflation vs baseline TC-01  

---

## 4. Test Matrix Summary

| Test | Transports | Payloads | Duration | Repeats | Priority |
|------|-----------|---------|---------|---------|---------|
| TC-01 Baseline Latency | All 5 | 10 sizes | 30s | 10 | **Critical** |
| TC-02 CPU Scaling | T1, T2 | 4 sizes | 30s | 5 | **Critical** |
| TC-03 NUMA Impact | T1, T2 | 3 sizes | 30s | 10 | **Critical** |
| TC-04 Event Storm | T1, T2 | 1 size | 60s | 5 | High |
| TC-05 Large Payload | T1 | 4 sizes | 30s | 5 | High |
| TC-06 Wakeup Strategies | T1, T2, T3 | 3 sizes | 30s | 5 | High |
| TC-07 Producer Contention | T1, T2 | 3 sizes | 60s | 5 | Medium |
| TC-08 Kernel Regression | T1, T2 | 1 size | 30s | 3 | Medium |
| TC-09 CPU Isolation | T1, T2 | 2 sizes | 60s | 5 | Medium |
| TC-10 Memory Pressure | All 5 | 1 size | 30s | 5 | Low |

Estimated total runtime: ~6–8 hours (full suite on a 128-core node)

---

## 5. Acceptance Criteria

| Metric | Ring Buffer | Perf Event Array | Hash Map |
|--------|------------|-----------------|---------|
| P50 Latency (64B) | < 5 µs | < 10 µs | < 50 µs |
| P99 Latency (64B) | < 50 µs | < 100 µs | < 500 µs |
| Drop Rate (4MB ring) | < 0.1% | < 0.5% | N/A |
| Throughput (64B) | > 1M ev/s | > 500K ev/s | > 100K ev/s |
| CPU overhead | < 2% | < 5% | < 1% (polling) |

---

## 6. Data Collection & Artifact Requirements

For each test run, the following must be collected and archived:

- **JSON result file** per configuration (auto-generated by benchmark)
- **System info snapshot** (CPU model, NUMA topology, kernel version, BPF stats)
- **`dmesg` output** for any kernel messages during the run
- **`perf stat` summary** for each run (cache misses, context switches, branch mispredictions)
- **Ring buffer size utilization** (average and peak occupancy)
- **`bpf_stats`** enabled output (program instruction count, runtime ns)

---

## 7. Known Limitations

- **Tracepoint overhead included:** Latency measurements include the tracepoint firing overhead itself. Use `kprobe` and raw tracepoints for lower-noise measurements.
- **Userspace timestamp accuracy:** Python time.time_ns() has ~100ns resolution on Linux; C clock_gettime(CLOCK_MONOTONIC) has ~1–10ns. Use the C userspace loader for P50 measurements below 10µs.
- **Ring buffer wakeup is asynchronous:** The measured latency includes scheduler latency for waking the consumer process. Use `BPF_RB_FORCE_WAKEUP` + `SCHED_FIFO` for best-case measurements.
- **Polling mechanisms have artificial floor:** Hash/array map polling latency is bounded below by the poll interval, not actual kernel submission latency.
