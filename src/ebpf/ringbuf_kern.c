// SPDX-License-Identifier: GPL-2.0
// ringbuf_kern.c — eBPF Ring Buffer transport benchmark
// Measures: submission latency, wakeup latency, throughput under load
// Compatible with: Linux 5.8+ (BPF_MAP_TYPE_RINGBUF)

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Configuration (set from userspace via .rodata) ─────────────────────────
volatile const __u32 CFG_PAYLOAD_SIZE  = 64;    // bytes per event
volatile const __u32 CFG_BATCH_SIZE    = 1;     // events per tracepoint hit
volatile const __u32 CFG_DROP_ON_FULL  = 0;     // 0=discard, 1=drop_oldest
volatile const __u32 CFG_NUMA_NODE     = 0;     // for NUMA-aware allocation

// ─── Maps ────────────────────────────────────────────────────────────────────

// Primary output ring buffer — size set at load time (must be power-of-two)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB default
} rb SEC(".maps");

// Per-CPU latency tracking: stores ktime_ns of last submission per CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} submit_ts SEC(".maps");

// Atomic counters (array map used as scalars)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

#define CTR_SUBMITTED  0
#define CTR_DROPPED    1
#define CTR_BYTES      2
#define CTR_WAKEUPS    3

// ─── Event record layout ─────────────────────────────────────────────────────
// Keep header 32 bytes so payload starts on cacheline boundary
struct event {
    __u64 ktime_submit_ns;   // ktime_get_ns() at submission
    __u64 sequence;          // monotonic per-CPU sequence number
    __u32 cpu;               // submitting CPU
    __u32 payload_size;      // actual payload bytes following header
    __u32 numa_node;         // NUMA node of submitting CPU
    __u32 _pad;
    // Variable payload follows (up to CFG_PAYLOAD_SIZE bytes)
    __u8  payload[0];
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
static __always_inline void inc_counter(__u32 idx, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&counters, &idx);
    if (val)
        __sync_fetch_and_add(val, delta);
}

// ─── Tracepoint: sys_enter_write — fires on every write(2) syscall ───────────
// This is the primary injection point; use perf_event override for
// raw cycle-accurate measurements.
SEC("tracepoint/syscalls/sys_enter_write")
int tp_ringbuf_submit(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u64 ts = bpf_ktime_get_ns();

    // Record submit timestamp for latency delta at userspace read
    __u64 *prev = bpf_map_lookup_elem(&submit_ts, &zero);
    if (prev) *prev = ts;

    // Reserve space: header + payload
    __u32 total = sizeof(struct event) + CFG_PAYLOAD_SIZE;
    struct event *e = bpf_ringbuf_reserve(&rb, total, 0);
    if (!e) {
        inc_counter(CTR_DROPPED, 1);
        return 0;
    }

    e->ktime_submit_ns = ts;
    e->sequence        = bpf_get_prandom_u32(); // replaced with percpu seq in advanced ver
    e->cpu             = bpf_get_smp_processor_id();
    e->payload_size    = CFG_PAYLOAD_SIZE;
    e->numa_node       = CFG_NUMA_NODE;

    // Fill payload with deterministic pattern for integrity checks
    #pragma unroll
    for (__u32 i = 0; i < 64 && i < CFG_PAYLOAD_SIZE; i++)
        e->payload[i] = (__u8)(i ^ e->cpu);

    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);

    inc_counter(CTR_SUBMITTED,  1);
    inc_counter(CTR_BYTES,      total);
    inc_counter(CTR_WAKEUPS,    1);

    return 0;
}

// ─── Kprobe variant for lower-overhead injection ─────────────────────────────
SEC("kprobe/finish_task_switch")
int kp_ringbuf_submit(struct pt_regs *ctx)
{
    __u32 zero = 0;
    __u64 ts   = bpf_ktime_get_ns();
    __u32 cpu  = bpf_get_smp_processor_id();

    __u32 total = sizeof(struct event) + CFG_PAYLOAD_SIZE;
    struct event *e = bpf_ringbuf_reserve(&rb, total, 0);
    if (!e) {
        inc_counter(CTR_DROPPED, 1);
        return 0;
    }

    e->ktime_submit_ns = ts;
    e->sequence        = ts;   // use ts as unique-enough seq
    e->cpu             = cpu;
    e->payload_size    = CFG_PAYLOAD_SIZE;
    e->numa_node       = CFG_NUMA_NODE;

    bpf_ringbuf_submit(e, 0);  // no forced wakeup — measure deferred wakeup cost

    inc_counter(CTR_SUBMITTED, 1);
    inc_counter(CTR_BYTES, total);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
