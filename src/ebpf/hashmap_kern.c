// SPDX-License-Identifier: GPL-2.0
// hashmap_kern.c — eBPF Hash/Array Map polling-based transport benchmark
// Measures: polling overhead, map update latency, NUMA effects on shared maps
// Use case: production eBPF programs that accumulate stats (not streaming)

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ─── Configuration ────────────────────────────────────────────────────────────
volatile const __u32 CFG_MAP_TYPE     = 0;  // 0=hash, 1=array, 2=percpu_hash
volatile const __u32 CFG_PAYLOAD_SIZE = 64;
volatile const __u32 CFG_MAX_ENTRIES  = 65536;

// ─── Hash Map: keyed by (cpu, sequence) ──────────────────────────────────────

struct hmap_key {
    __u32 cpu;
    __u32 seq;
};

struct hmap_value {
    __u64 ktime_insert_ns;    // when kernel wrote this entry
    __u64 sequence;
    __u32 cpu;
    __u32 payload_size;
    __u8  payload[64];        // fixed 64B for hash map entries
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct hmap_key);
    __type(value, struct hmap_value);
} hash_map SEC(".maps");

// ─── Array Map: ring-style with per-CPU write index ──────────────────────────
struct array_slot {
    __u64 ktime_ns;
    __u64 sequence;
    __u32 cpu;
    __u32 valid;           // userspace clears after reading
    __u8  payload[56];     // pad to 80 bytes total
};

struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key,   __u32);
    __type(value, struct array_slot);
} array_map SEC(".maps");

// ─── Per-CPU write indices (for array map ring) ───────────────────────────────
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,  __u32);
    __type(value, __u64);
} write_idx SEC(".maps");

// ─── Per-CPU array map (avoids hash collision penalty) ───────────────────────
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1024);  // ring slots per CPU
    __type(key,  __u32);
    __type(value, struct array_slot);
} percpu_array SEC(".maps");

// ─── Global stats ─────────────────────────────────────────────────────────────
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key,  __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_HASH_INSERTS   0
#define STAT_HASH_UPDATES   1
#define STAT_HASH_DROPS     2
#define STAT_ARRAY_WRITES   3
#define STAT_PERCPU_WRITES  4
#define STAT_COLLISIONS     5

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

// ─── Hash Map insertion ───────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_close")
int tp_hashmap_insert(struct trace_event_raw_sys_enter *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 ts  = bpf_ktime_get_ns();

    // Use (cpu, ts_low32) as key — collisions counted as updates
    struct hmap_key key = {
        .cpu = cpu,
        .seq = (__u32)(ts & 0xFFFFFFFF),
    };

    struct hmap_value val = {
        .ktime_insert_ns = ts,
        .sequence        = ts,
        .cpu             = cpu,
        .payload_size    = 64,
    };

    // Fill payload
    #pragma unroll
    for (int i = 0; i < 64; i++)
        val.payload[i] = (__u8)(cpu ^ i);

    long ret = bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
    if (ret == 0)
        stat_inc(STAT_HASH_INSERTS);
    else
        stat_inc(STAT_HASH_DROPS);

    return 0;
}

// ─── Array Map (ring-buffer style) ────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_array_insert(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u64 *idx_ptr = bpf_map_lookup_elem(&write_idx, &zero);
    if (!idx_ptr) return 0;

    __u64 ts  = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 slot = ((__u32)*idx_ptr) & 0xFFFF; // mod 65536

    struct array_slot val = {
        .ktime_ns = ts,
        .sequence = *idx_ptr,
        .cpu      = cpu,
        .valid    = 1,
    };

    #pragma unroll
    for (int i = 0; i < 56; i++)
        val.payload[i] = (__u8)(i ^ cpu);

    bpf_map_update_elem(&array_map, &slot, &val, BPF_ANY);
    __sync_fetch_and_add(idx_ptr, 1);
    stat_inc(STAT_ARRAY_WRITES);

    return 0;
}

// ─── Per-CPU Array (lowest-overhead polling baseline) ────────────────────────
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_percpu_array(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 zero = 0;
    __u64 *idx_ptr = bpf_map_lookup_elem(&write_idx, &zero);
    if (!idx_ptr) return 0;

    __u32 slot = ((__u32)*idx_ptr) & 0x3FF; // mod 1024

    struct array_slot val = {
        .ktime_ns = bpf_ktime_get_ns(),
        .sequence = *idx_ptr,
        .cpu      = bpf_get_smp_processor_id(),
        .valid    = 1,
    };

    bpf_map_update_elem(&percpu_array, &slot, &val, BPF_ANY);
    __sync_fetch_and_add(idx_ptr, 1);
    stat_inc(STAT_PERCPU_WRITES);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
