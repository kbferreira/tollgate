// ringbuf_user.c — libbpf userspace loader for ring buffer benchmark
// Provides nanosecond-accurate latency measurement without Python overhead
// Compile: gcc -O2 -o ringbuf_user ringbuf_user.c -lbpf -lelf -lz

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_LATENCY_SAMPLES  (1 << 22)  // 4M samples max
#define RINGBUF_SIZE_DEFAULT (1 << 22)  // 4 MiB
#define HISTOGRAM_BUCKETS    64

// ─── Event record (must match kernel struct) ──────────────────────────────────
struct rb_event {
    __u64 ktime_submit_ns;
    __u64 sequence;
    __u32 cpu;
    __u32 payload_size;
    __u32 numa_node;
    __u32 _pad;
    // payload follows
};

// ─── Measurement state ────────────────────────────────────────────────────────
struct bench_state {
    // Latency samples (ns)
    __u64 *latencies;
    __u64   n_samples;

    // Counters
    __u64   n_events;
    __u64   n_drops;
    __u64   n_ooo;       // out-of-order sequence events
    __u64   total_bytes;

    // Timing
    struct timespec start_wall;
    struct timespec end_wall;

    // Config
    int     payload_size;
    int     duration_sec;
    int     ringbuf_pages;
    char    output_file[256];

    // Histogram: log2 buckets in nanoseconds
    __u64   hist_ns[HISTOGRAM_BUCKETS];

    // CPU stats
    double  cpu_usr_pct;
    double  cpu_sys_pct;
} state;

static volatile int running = 1;

static void sig_handler(int sig) { running = 0; }

// ─── Ringbuf callback ─────────────────────────────────────────────────────────
static int handle_rb_event(void *ctx, void *data, size_t size)
{
    struct timespec recv_ts;
    clock_gettime(CLOCK_MONOTONIC, &recv_ts);
    __u64 recv_ns = (__u64)recv_ts.tv_sec * 1000000000ULL + recv_ts.tv_nsec;

    const struct rb_event *e = data;
    __u64 latency_ns = recv_ns - e->ktime_submit_ns;

    state.n_events++;
    state.total_bytes += size;

    if (state.n_samples < MAX_LATENCY_SAMPLES)
        state.latencies[state.n_samples++] = latency_ns;

    // Log2 histogram bucket
    int bucket = 0;
    __u64 v = latency_ns;
    while (v >>= 1) bucket++;
    if (bucket >= HISTOGRAM_BUCKETS) bucket = HISTOGRAM_BUCKETS - 1;
    state.hist_ns[bucket]++;

    return 0;
}

// ─── Percentile calculation ───────────────────────────────────────────────────
static int cmp_u64(const void *a, const void *b) {
    __u64 x = *(__u64*)a, y = *(__u64*)b;
    return (x > y) - (x < y);
}

static __u64 percentile(__u64 *data, size_t n, double pct)
{
    if (n == 0) return 0;
    __u64 *sorted = malloc(n * sizeof(__u64));
    memcpy(sorted, data, n * sizeof(__u64));
    qsort(sorted, n, sizeof(__u64), cmp_u64);
    size_t idx = (size_t)((pct / 100.0) * (n - 1));
    __u64 result = sorted[idx];
    free(sorted);
    return result;
}

static __u64 mean_u64(__u64 *data, size_t n)
{
    if (n == 0) return 0;
    __u64 sum = 0;
    for (size_t i = 0; i < n; i++) sum += data[i];
    return sum / n;
}

// ─── Read /proc/stat for CPU utilization ─────────────────────────────────────
static void read_cpu_stats(__u64 *usr, __u64 *sys, __u64 *idle)
{
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return;
    fscanf(f, "cpu %llu %*llu %llu %llu", usr, sys, idle);
    fclose(f);
}

// ─── Output results as JSON ───────────────────────────────────────────────────
static void save_results(struct bpf_map *counter_map)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    double elapsed = (state.end_wall.tv_sec - state.start_wall.tv_sec) +
                     (state.end_wall.tv_nsec - state.start_wall.tv_nsec) * 1e-9;

    __u64 *lats = state.latencies;
    size_t n    = state.n_samples;

    // Get drop count from BPF map
    __u64 drops = 0;
    if (counter_map) {
        __u32 drop_key = 1;
        bpf_map_lookup_elem(bpf_map__fd(counter_map), &drop_key, &drops);
    }

    double throughput_eps  = state.n_events / elapsed;
    double throughput_mbps = (state.total_bytes / elapsed) / 1e6;
    double drop_pct        = (drops / (double)(state.n_events + drops)) * 100.0;

    FILE *out = state.output_file[0]
              ? fopen(state.output_file, "w")
              : stdout;
    if (!out) { perror("fopen output"); return; }

    fprintf(out, "{\n");
    fprintf(out, "  \"transport\": \"ringbuf\",\n");
    fprintf(out, "  \"payload_size\": %d,\n", state.payload_size);
    fprintf(out, "  \"duration_s\": %.3f,\n", elapsed);
    fprintf(out, "  \"events_total\": %llu,\n", state.n_events);
    fprintf(out, "  \"events_dropped\": %llu,\n", drops);
    fprintf(out, "  \"drop_rate_pct\": %.4f,\n", drop_pct);
    fprintf(out, "  \"throughput_eps\": %.2f,\n", throughput_eps);
    fprintf(out, "  \"throughput_mbps\": %.4f,\n", throughput_mbps);
    fprintf(out, "  \"latency_samples\": %zu,\n", n);

    if (n > 0) {
        fprintf(out, "  \"latency_min_ns\": %llu,\n", percentile(lats, n, 0));
        fprintf(out, "  \"latency_p50_ns\": %llu,\n", percentile(lats, n, 50));
        fprintf(out, "  \"latency_p90_ns\": %llu,\n", percentile(lats, n, 90));
        fprintf(out, "  \"latency_p95_ns\": %llu,\n", percentile(lats, n, 95));
        fprintf(out, "  \"latency_p99_ns\": %llu,\n", percentile(lats, n, 99));
        fprintf(out, "  \"latency_p999_ns\": %llu,\n", percentile(lats, n, 99.9));
        fprintf(out, "  \"latency_mean_ns\": %llu,\n", mean_u64(lats, n));
        fprintf(out, "  \"latency_max_ns\": %llu,\n", percentile(lats, n, 100));
    }

    // Log2 histogram
    fprintf(out, "  \"latency_histogram_ns\": {\n");
    for (int i = 0; i < HISTOGRAM_BUCKETS; i++) {
        if (state.hist_ns[i] > 0) {
            __u64 lo = i > 0 ? (1ULL << (i-1)) : 0;
            __u64 hi = (1ULL << i);
            fprintf(out, "    \"%llu-%llu\": %llu%s\n",
                    lo, hi, state.hist_ns[i],
                    i == HISTOGRAM_BUCKETS-1 ? "" : ",");
        }
    }
    fprintf(out, "  }\n");
    fprintf(out, "}\n");

    if (out != stdout) fclose(out);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    int opt;
    state.payload_size    = 64;
    state.duration_sec    = 10;
    state.ringbuf_pages   = 1024;
    state.output_file[0]  = '\0';

    while ((opt = getopt(argc, argv, "p:d:r:o:h")) != -1) {
        switch (opt) {
        case 'p': state.payload_size  = atoi(optarg); break;
        case 'd': state.duration_sec  = atoi(optarg); break;
        case 'r': state.ringbuf_pages = atoi(optarg); break;
        case 'o': strncpy(state.output_file, optarg, 255); break;
        case 'h':
            fprintf(stderr,
                "Usage: %s [-p payload_bytes] [-d duration_sec]\n"
                "          [-r ringbuf_pages] [-o output.json]\n", argv[0]);
            return 0;
        }
    }

    // Raise memory lock limit for BPF maps
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    // Allocate sample buffer
    state.latencies = calloc(MAX_LATENCY_SAMPLES, sizeof(__u64));
    if (!state.latencies) { perror("calloc"); return 1; }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
    alarm(state.duration_sec);

    // Load BPF object
    // NOTE: In production, use skeleton generated by bpftool gen skeleton
    // For dev: load directly from compiled .o file
    struct bpf_object *obj = bpf_object__open("ringbuf_kern.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: bpf_object__open failed. "
                "Build ringbuf_kern.o first.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: bpf_object__load failed\n");
        return 1;
    }

    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "rb");
    if (!rb_map) { fprintf(stderr, "ERROR: map 'rb' not found\n"); return 1; }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(rb_map), handle_rb_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ERROR: ring_buffer__new\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(
        obj, "tp_ringbuf_submit");
    if (!prog) { fprintf(stderr, "ERROR: program not found\n"); return 1; }

    struct bpf_link *link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_program__attach\n"); return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &state.start_wall);
    fprintf(stderr, "Benchmarking ringbuf: payload=%dB duration=%ds\n",
            state.payload_size, state.duration_sec);

    while (running)
        ring_buffer__poll(rb, 100 /* ms timeout */);

    clock_gettime(CLOCK_MONOTONIC, &state.end_wall);

    // Cleanup
    bpf_link__destroy(link);
    ring_buffer__free(rb);

    struct bpf_map *counter_map =
        bpf_object__find_map_by_name(obj, "counters");

    save_results(counter_map);

    bpf_object__close(obj);
    free(state.latencies);

    return 0;
}
