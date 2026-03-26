// SPDX-License-Identifier: GPL-2.0
// perf_array_kern.c — eBPF Perf Event Array transport benchmark
// Measures: per-CPU event delivery, mmap ring overhead, wakeup cost
// Compatible with: Linux 4.4+ (BPF_MAP_TYPE_PERF_EVENT_ARRAY)

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ─── Configuration ────────────────────────────────────────────────────────────
volatile const __u32 CFG_PAYLOAD_SIZE = 64;
volatile const __u32 CFG_SAMPLE_FREQ  = 0;   // 0 = every event, >0 = every Nth

// ─── Maps ─────────────────────────────────────────────────────────────────────

// Per-CPU perf event ring; one fd per CPU opened in userspace
struct {
    __uint(type,        BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  sizeof(__u32));
    __uint(max_entries, 512);   // max CPUs supported; actual count set at load
} perf_map SEC(".maps");

// Per-CPU drop counter
struct {
    __uint(type,       BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key,  __u32);
    __type(value, __u64);
} percpu_ctr SEC(".maps");

#define PCTR_SUBMITTED 0
#define PCTR_DROPPED   1

// ─── Event record ─────────────────────────────────────────────────────────────
// Note: perf_event output is NOT zero-copy; data is copied into the perf mmap
// ring by bpf_perf_event_output(). Header must be <= 64 KiB total.
#define MAX_PAYLOAD 4096

struct perf_event_record {
    __u64 ktime_ns;       // submission timestamp
    __u64 sequence;       // monotonic (per CPU via percpu_array)
    __u32 cpu;
    __u32 payload_size;
    __u8  payload[MAX_PAYLOAD];
};

// Scratch buffer avoids stack overflow for large payloads
// (BPF stack limit = 512 bytes)
struct {
    __uint(type,       BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,  __u32);
    __type(value, struct perf_event_record);
} scratch SEC(".maps");

// ─── Tracepoint: sys_enter_read ──────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_read")
int tp_perf_submit(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct perf_event_record *rec = bpf_map_lookup_elem(&scratch, &zero);
    if (!rec) return 0;

    __u32 cpu = bpf_get_smp_processor_id();
    rec->ktime_ns    = bpf_ktime_get_ns();
    rec->cpu         = cpu;
    rec->payload_size = CFG_PAYLOAD_SIZE;

    // Determine actual output size (clamped to MAX_PAYLOAD)
    __u32 out_size = sizeof(struct perf_event_record);
    if (CFG_PAYLOAD_SIZE < MAX_PAYLOAD)
        out_size = sizeof(__u64) * 2 + sizeof(__u32) * 2 + CFG_PAYLOAD_SIZE;

    // Fill payload
    #pragma unroll
    for (int i = 0; i < 64; i++)
        if ((__u32)i < CFG_PAYLOAD_SIZE)
            rec->payload[i] = (__u8)(cpu + i);

    int ret = bpf_perf_event_output(ctx, &perf_map,
                                    BPF_F_CURRENT_CPU,
                                    rec, out_size);
    __u32 ctr_idx = (ret == 0) ? PCTR_SUBMITTED : PCTR_DROPPED;
    __u64 *ctr = bpf_map_lookup_elem(&percpu_ctr, &ctr_idx);
    if (ctr) (*ctr)++;

    return 0;
}

// ─── Kprobe variant: schedule() for HPC workload simulation ──────────────────
SEC("kprobe/schedule")
int kp_perf_submit(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct perf_event_record *rec = bpf_map_lookup_elem(&scratch, &zero);
    if (!rec) return 0;

    rec->ktime_ns     = bpf_ktime_get_ns();
    rec->cpu          = bpf_get_smp_processor_id();
    rec->payload_size = CFG_PAYLOAD_SIZE;

    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU,
                          rec, sizeof(__u64) * 2 + sizeof(__u32) * 2 + CFG_PAYLOAD_SIZE);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
