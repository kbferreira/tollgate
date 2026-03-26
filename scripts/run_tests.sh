#!/usr/bin/env bash
# run_tests.sh — TOLLGATE Test Runner
# =====================================================
# Automates system setup, all test suites, and data pipeline for
# HPC cluster environments. Supports NUMA pinning, CPU isolation,
# and parallel multi-node runs via SLURM or MPI.
#
# Usage:
#   sudo ./run_tests.sh [quick|standard|full|hpc_scale|numa|all]
#   sudo ./run_tests.sh --suite standard --payloads "64 256 1024" --duration 10
#   sudo SLURM_NODEID=0 ./run_tests.sh full     # HPC batch mode
#
# Dependencies: python3, bcc, stress-ng, numactl, perf, jq

set -euo pipefail

# ─── Configuration ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results"
FIGURES_DIR="$PROJECT_DIR/figures"
PYTHON="${PYTHON:-python3}"
BCC_BENCH="$PROJECT_DIR/src/bcc/benchmark.py"
ANALYZE="$SCRIPT_DIR/analyze.py"
PLOT="$SCRIPT_DIR/plot.py"

# Test parameters (override via env or CLI)
SUITE="${1:-standard}"
PAYLOADS="${PAYLOADS:-64 256 1024 4096 16384}"
DURATION="${DURATION:-10}"
REPEATS="${REPEATS:-5}"
TRANSPORT="${TRANSPORT:-all}"
VERBOSE="${VERBOSE:-0}"

# System tuning
ISOLATE_CPUS="${ISOLATE_CPUS:-0}"        # 1 = use cpuset isolation
DISABLE_HT="${DISABLE_HT:-0}"            # 1 = disable hyperthreading
DISABLE_TURBO="${DISABLE_TURBO:-0}"      # 1 = disable CPU turbo
SET_SCALING="${SET_SCALING:-performance}" # CPU frequency governor

RUN_ID="$(date +%Y%m%d_%H%M%S)_$(hostname -s)"
LOG_FILE="$RESULTS_DIR/run_${RUN_ID}.log"

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }
hdr()  { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}\n" | tee -a "$LOG_FILE"; }

# ─── Preflight checks ──────────────────────────────────────────────────────────
preflight() {
    hdr "Preflight Checks"

    [[ $EUID -eq 0 ]] || err "Must run as root (sudo)."

    # Check kernel version (≥ 5.8 for ring buffer)
    KERNEL=$(uname -r)
    KMAJOR=$(echo "$KERNEL" | cut -d. -f1)
    KMINOR=$(echo "$KERNEL" | cut -d. -f2)
    log "Kernel: $KERNEL"
    [[ $KMAJOR -gt 5 || ($KMAJOR -eq 5 && $KMINOR -ge 8) ]] \
        || warn "Kernel < 5.8: BPF_MAP_TYPE_RINGBUF unavailable, ring buffer tests will be skipped."

    # Check required tools
    for tool in python3 bpftool stress-ng numactl; do
        if ! command -v "$tool" &>/dev/null; then
            warn "Missing tool: $tool — some tests may be skipped."
        else
            log "  ✓ $tool: $(command -v $tool)"
        fi
    done

    # Check BCC
    if ! $PYTHON -c "from bcc import BPF" 2>/dev/null; then
        err "BCC not importable. Install: apt install python3-bcc  OR  pip install bcc"
    fi
    log "  ✓ BCC Python bindings available"

    # Check eBPF CAP_BPF
    if ! bpftool prog list &>/dev/null 2>&1; then
        warn "bpftool check failed — may lack CAP_BPF or CONFIG_BPF_SYSCALL"
    fi

    # Check BTF
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        log "  ✓ BTF vmlinux available (CO-RE support)"
    else
        warn "No /sys/kernel/btf/vmlinux — CO-RE not available."
    fi

    log "Preflight passed."
}

# ─── System tuning ─────────────────────────────────────────────────────────────
tune_system() {
    hdr "System Tuning"

    # CPU frequency governor
    if ls /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null; then
        CURRENT_GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
        log "Current governor: $CURRENT_GOV → setting $SET_SCALING"
        for cpu_dir in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo "$SET_SCALING" > "$cpu_dir" 2>/dev/null || true
        done
    fi

    # Disable turbo boost (Intel)
    if [[ "$DISABLE_TURBO" == "1" ]]; then
        if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
            log "Intel turbo disabled"
        fi
    fi

    # Disable SMT/hyperthreading
    if [[ "$DISABLE_HT" == "1" ]]; then
        for smt_ctl in /sys/devices/system/cpu/smt/control; do
            [[ -f "$smt_ctl" ]] && echo off > "$smt_ctl" && log "SMT disabled"
        done
    fi

    # Raise perf_event_paranoid
    PREV_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 2)
    echo -1 > /proc/sys/kernel/perf_event_paranoid
    log "perf_event_paranoid: $PREV_PARANOID → -1"
    echo "$PREV_PARANOID" > /tmp/ebpf_bench_paranoid_restore

    # Raise kernel.bpf_stats_enabled
    echo 1 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || true

    # NUMA: show topology
    if command -v numactl &>/dev/null; then
        log "NUMA topology:"
        numactl --hardware | grep -E "node [0-9]|cpus|size" | sed 's/^/    /' | tee -a "$LOG_FILE"
    fi

    # CPU info
    NCPUS=$(nproc)
    CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    log "CPUs: $NCPUS × $CPU_MODEL"

    # Collect baseline system info
    collect_sysinfo
}

# ─── Collect system info snapshot ─────────────────────────────────────────────
collect_sysinfo() {
    SYSINFO_FILE="$RESULTS_DIR/sysinfo_${RUN_ID}.json"
    python3 - <<EOF > "$SYSINFO_FILE"
import json, subprocess, os, platform

def run(cmd):
    try: return subprocess.check_output(cmd, shell=True, text=True).strip()
    except: return "N/A"

info = {
    "hostname":    platform.node(),
    "kernel":      platform.release(),
    "arch":        platform.machine(),
    "cpu_model":   run("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2"),
    "ncpus":       os.cpu_count(),
    "ncpus_online": int(run("nproc") or 0),
    "numa_nodes":  int(run("numactl --hardware 2>/dev/null | grep 'available:' | awk '{print \$2}'") or 1),
    "memtotal_kb": int(run("grep MemTotal /proc/meminfo | awk '{print \$2}'")),
    "l1d_cache":   run("getconf LEVEL1_DCACHE_SIZE 2>/dev/null"),
    "l2_cache":    run("getconf LEVEL2_CACHE_SIZE 2>/dev/null"),
    "l3_cache":    run("getconf LEVEL3_CACHE_SIZE 2>/dev/null"),
    "governor":    run("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null"),
    "turbo_state": run("cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null"),
    "bpf_stats":   run("cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null"),
    "perf_paranoid": run("cat /proc/sys/kernel/perf_event_paranoid"),
    "btf_available": os.path.exists("/sys/kernel/btf/vmlinux"),
}
print(json.dumps(info, indent=2))
EOF
    log "System info saved → $SYSINFO_FILE"
}

# ─── Restore system settings ───────────────────────────────────────────────────
restore_system() {
    if [[ -f /tmp/ebpf_bench_paranoid_restore ]]; then
        PREV=$(cat /tmp/ebpf_bench_paranoid_restore)
        echo "$PREV" > /proc/sys/kernel/perf_event_paranoid
        rm -f /tmp/ebpf_bench_paranoid_restore
        log "Restored perf_event_paranoid → $PREV"
    fi
    if [[ "$DISABLE_TURBO" == "1" ]]; then
        echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
    fi
    if [[ "$DISABLE_HT" == "1" ]]; then
        echo on > /sys/devices/system/cpu/smt/control 2>/dev/null || true
    fi
}
trap restore_system EXIT

# ─── Run a single benchmark configuration ─────────────────────────────────────
run_single() {
    local transport="$1"
    local payload="$2"
    local repeat="$3"
    local extra_args="${4:-}"

    local out_file="$RESULTS_DIR/run_${RUN_ID}_${transport}_${payload}B_rep${repeat}.json"
    local verbose_flag=""
    [[ "$VERBOSE" == "1" ]] && verbose_flag="--verbose"

    log "  → transport=$transport payload=${payload}B repeat=$repeat"

    $PYTHON "$BCC_BENCH" \
        --transport "$transport" \
        --payload "$payload" \
        --duration "$DURATION" \
        --repeats 1 \
        --output "$RESULTS_DIR" \
        $verbose_flag \
        $extra_args 2>>"$LOG_FILE" || warn "Run failed: $transport/$payload/rep$repeat"
}

# ─── NUMA-aware test suite ────────────────────────────────────────────────────
run_numa_tests() {
    hdr "NUMA Transport Tests"
    NUMA_NODES=$(numactl --hardware 2>/dev/null | grep "^available:" | awk '{print $2}' || echo 1)
    log "NUMA nodes detected: $NUMA_NODES"

    if [[ $NUMA_NODES -lt 2 ]]; then
        warn "Single NUMA node — skipping cross-node tests"
        return
    fi

    for transport in ringbuf perf; do
        for payload in 64 1024 4096; do
            for node in $(seq 0 $((NUMA_NODES-1))); do
                log "NUMA node=$node transport=$transport payload=${payload}B"
                numactl --cpunodebind="$node" --membind="$node" \
                    $PYTHON "$BCC_BENCH" \
                        --transport "$transport" \
                        --payload "$payload" \
                        --duration "$DURATION" \
                        --repeats 1 \
                        --output "$RESULTS_DIR" 2>>"$LOG_FILE" || true
            done
        done
    done
}

# ─── CPU scaling test ─────────────────────────────────────────────────────────
run_cpu_scaling_tests() {
    hdr "CPU Count Scaling Tests"
    local MAX_CPUS
    MAX_CPUS=$(nproc)
    local CPU_COUNTS=(1 2 4 8 16 32)
    CPU_COUNTS=("${CPU_COUNTS[@]/%/>$MAX_CPUS}")  # filter > max
    CPU_COUNTS=($(printf '%s\n' "${CPU_COUNTS[@]}" | awk -v m="$MAX_CPUS" '$1<=m'))

    for transport in ringbuf perf; do
        for payload in 256 1024; do
            for ncpus in "${CPU_COUNTS[@]}"; do
                log "  CPUs=$ncpus transport=$transport payload=${payload}B"
                # Limit to first N CPUs via taskset
                CPUMASK=$(python3 -c "print(hex((1<<$ncpus)-1))")
                taskset "$CPUMASK" $PYTHON "$BCC_BENCH" \
                    --transport "$transport" \
                    --payload "$payload" \
                    --duration "$DURATION" \
                    --repeats 2 \
                    --output "$RESULTS_DIR" 2>>"$LOG_FILE" || true
            done
        done
    done
}

# ─── Main test dispatch ────────────────────────────────────────────────────────
run_suite() {
    local suite="$1"
    hdr "Running suite: $suite"

    case "$suite" in
        quick)
            DURATION=5; REPEATS=3
            $PYTHON "$BCC_BENCH" --suite quick --output "$RESULTS_DIR" \
                $([ "$VERBOSE" == "1" ] && echo "--verbose") 2>>"$LOG_FILE"
            ;;
        standard)
            $PYTHON "$BCC_BENCH" --suite standard --output "$RESULTS_DIR" \
                $([ "$VERBOSE" == "1" ] && echo "--verbose") 2>>"$LOG_FILE"
            ;;
        full)
            $PYTHON "$BCC_BENCH" --suite full --output "$RESULTS_DIR" \
                $([ "$VERBOSE" == "1" ] && echo "--verbose") 2>>"$LOG_FILE"
            ;;
        numa)
            run_numa_tests
            ;;
        hpc_scale)
            run_cpu_scaling_tests
            ;;
        all)
            run_suite standard
            run_numa_tests
            run_cpu_scaling_tests
            ;;
        *)
            err "Unknown suite: $suite. Choose: quick|standard|full|numa|hpc_scale|all"
            ;;
    esac

    log "Suite '$suite' complete."
}

# ─── Post-processing ──────────────────────────────────────────────────────────
post_process() {
    hdr "Post-Processing Results"

    local csv_file="$RESULTS_DIR/summary_${RUN_ID}.csv"

    log "Analyzing results..."
    $PYTHON "$ANALYZE" "$RESULTS_DIR" --csv "$csv_file" 2>>"$LOG_FILE" \
        || warn "Analysis failed"

    log "Generating plots..."
    $PYTHON "$PLOT" "$csv_file" --output "$FIGURES_DIR" 2>>"$LOG_FILE" \
        || warn "Plotting failed (matplotlib missing?  pip install matplotlib pandas)"

    log ""
    log "Results: $RESULTS_DIR"
    log "Summary: $csv_file"
    log "Figures: $FIGURES_DIR"
    log "Log:     $LOG_FILE"

    # Quick summary table
    if command -v jq &>/dev/null; then
        log "\n=== Quick Stats ==="
        jq -rs '
          group_by(.transport, .payload_size) |
          .[] |
          (map(.latency_p50_ns // 0) | add / length) as $lat |
          (map(.throughput_eps // 0) | add / length) as $thr |
          "  \(.[0].transport | @text):  payload=\(.[0].payload_size)B  "
          + "lat_p50=\($lat/1000 | floor)µs  thr=\($thr/1000 | floor)Kev/s"
        ' "$RESULTS_DIR"/run_"${RUN_ID}"*.json 2>/dev/null \
          | tee -a "$LOG_FILE" || true
    fi
}

# ─── Entry point ──────────────────────────────────────────────────────────────
main() {
    mkdir -p "$RESULTS_DIR" "$FIGURES_DIR"
    echo "" > "$LOG_FILE"

    hdr "TOLLGATE — $(date)"
    log "Suite: $SUITE | Host: $(hostname) | Kernel: $(uname -r)"

    preflight
    tune_system
    run_suite "$SUITE"
    post_process

    hdr "Run Complete — $RUN_ID"
    log "Total elapsed: $(date -d @$SECONDS -u +%H:%M:%S 2>/dev/null || echo "${SECONDS}s")"
}

main "$@"
