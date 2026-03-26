# Makefile — TOLLGATE Build System
# ===================================================
# Builds eBPF kernel objects (.o), libbpf skeletons,
# and C userspace loaders.
#
# Usage:
#   make           # build everything
#   make ebpf      # build only eBPF programs
#   make user      # build only userspace tools
#   make check     # verify environment
#   make install   # install Python deps
#   make clean
#
# Requirements: clang ≥ 14, libbpf-dev, linux-headers, bpftool

CC      := gcc
CLANG   := clang
BPFTOOL := bpftool

ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KVER    := $(shell uname -r)
KSRC    := /lib/modules/$(KVER)/build

CFLAGS  := -O2 -g -Wall -Wextra
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I/usr/include \
              -idirafter $(KSRC)/arch/$(ARCH)/include/generated

LIBBPF_LDFLAGS := -lbpf -lelf -lz -lpthread

SRC_DIR     := src
EBPF_DIR    := $(SRC_DIR)/ebpf
USER_DIR    := $(SRC_DIR)/userspace
BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
BIN_DIR     := $(BUILD_DIR)/bin
SKEL_DIR    := $(BUILD_DIR)/skeletons

EBPF_SRCS   := $(wildcard $(EBPF_DIR)/*.c)
EBPF_OBJS   := $(patsubst $(EBPF_DIR)/%.c, $(OBJ_DIR)/%.bpf.o, $(EBPF_SRCS))
EBPF_SKELS  := $(patsubst $(EBPF_DIR)/%.c, $(SKEL_DIR)/%_skel.h, $(EBPF_SRCS))

USER_SRCS   := $(wildcard $(USER_DIR)/*.c)
USER_BINS   := $(patsubst $(USER_DIR)/%.c, $(BIN_DIR)/%, $(USER_SRCS))

.PHONY: all ebpf skeletons user check install clean help

all: check-dirs ebpf skeletons user
	@echo ""
	@echo "Build complete. Binaries in $(BIN_DIR)/"
	@ls -la $(BIN_DIR)/ 2>/dev/null || true

# ─── Directory setup ──────────────────────────────────────────────────────────
check-dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(SKEL_DIR) results figures

# ─── eBPF kernel objects ──────────────────────────────────────────────────────
ebpf: check-dirs $(EBPF_OBJS)
	@echo "eBPF objects built: $(EBPF_OBJS)"

$(OBJ_DIR)/%.bpf.o: $(EBPF_DIR)/%.c
	@echo "  CLANG  $< → $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ─── Generate libbpf skeletons ────────────────────────────────────────────────
skeletons: ebpf $(EBPF_SKELS)

$(SKEL_DIR)/%_skel.h: $(OBJ_DIR)/%.bpf.o
	@echo "  SKEL   $< → $@"
	$(BPFTOOL) gen skeleton $< > $@ 2>/dev/null || \
	  echo "  (bpftool gen skeleton failed — use BCC Python fallback)"

# ─── C userspace loaders ──────────────────────────────────────────────────────
user: check-dirs skeletons $(USER_BINS)

$(BIN_DIR)/%: $(USER_DIR)/%.c
	@echo "  GCC    $< → $@"
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_LDFLAGS) \
	  -I$(SKEL_DIR) -I/usr/include/bpf \
	  || echo "  (build failed — check libbpf-dev is installed)"

# ─── SLURM job script generation ─────────────────────────────────────────────
slurm:
	@echo "Generating SLURM job scripts for HPC cluster..."
	@python3 - <<'EOF'
import os
for suite in ["quick", "standard", "full", "hpc_scale"]:
    script = f"""#!/bin/bash
#SBATCH --job-name=ebpf_bench_{suite}
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=$${{SLURM_CPUS_ON_NODE:-64}}
#SBATCH --time=02:00:00
#SBATCH --output=results/slurm_%j_{suite}.out
#SBATCH --error=results/slurm_%j_{suite}.err
#SBATCH --exclusive

module load python/3.11 || true
module load bcc || true

cd {os.getcwd()}
sudo bash scripts/run_tests.sh {suite}
"""
    with open(f"slurm_{suite}.sh", "w") as f:
        f.write(script)
    print(f"  Created slurm_{suite}.sh")
EOF

# ─── Check environment ────────────────────────────────────────────────────────
check:
	@echo "=== Environment Check ==="
	@echo "Kernel: $$(uname -r)"
	@echo "Arch:   $(ARCH)"
	@clang --version 2>/dev/null | head -1 || echo "  [MISSING] clang"
	@$(CC) --version 2>/dev/null | head -1 || echo "  [MISSING] gcc"
	@$(BPFTOOL) version 2>/dev/null | head -1 || echo "  [MISSING] bpftool (apt: linux-tools-common)"
	@python3 -c "from bcc import BPF; print('  [OK] BCC Python bindings')" 2>/dev/null || \
	  echo "  [MISSING] BCC (apt: python3-bcc)"
	@python3 -c "import psutil; print('  [OK] psutil')" 2>/dev/null || \
	  echo "  [MISSING] psutil (pip install psutil)"
	@python3 -c "import matplotlib; print('  [OK] matplotlib')" 2>/dev/null || \
	  echo "  [MISSING] matplotlib (pip install matplotlib)"
	@python3 -c "import pandas; print('  [OK] pandas')" 2>/dev/null || \
	  echo "  [MISSING] pandas (pip install pandas)"
	@ls /sys/kernel/btf/vmlinux >/dev/null 2>&1 && echo "  [OK] BTF vmlinux" || \
	  echo "  [WARN] No BTF vmlinux — CO-RE unavailable"
	@ls $(KSRC)/Makefile >/dev/null 2>&1 && echo "  [OK] Kernel headers" || \
	  echo "  [MISSING] Kernel headers (apt: linux-headers-$$(uname -r))"

# ─── Install Python deps ──────────────────────────────────────────────────────
install:
	pip3 install --break-system-packages bcc psutil matplotlib pandas numpy || \
	pip3 install bcc psutil matplotlib pandas numpy
	@echo "Python dependencies installed."

# ─── Clean ───────────────────────────────────────────────────────────────────
clean:
	rm -rf $(BUILD_DIR) slurm_*.sh
	@echo "Build artifacts cleaned."

# ─── Help ────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "TOLLGATE — Build Targets"
	@echo "  make           — Build everything"
	@echo "  make ebpf      — Build eBPF kernel objects only"
	@echo "  make user      — Build C userspace loaders"
	@echo "  make check     — Verify environment dependencies"
	@echo "  make install   — Install Python dependencies"
	@echo "  make slurm     — Generate SLURM batch scripts"
	@echo "  make clean     — Remove build artifacts"
	@echo ""
	@echo "Run tests:"
	@echo "  sudo bash scripts/run_tests.sh quick"
	@echo "  sudo bash scripts/run_tests.sh standard"
	@echo "  sudo bash scripts/run_tests.sh full"
	@echo "  sudo bash scripts/run_tests.sh numa"
	@echo ""
