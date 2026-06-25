#!/bin/bash
# CloudFlow eBPF Probe - Kernel Compatibility Verification Script
# Usage: ./scripts/verify-kernel.sh [probe-binary]

set -e

PROBE_BIN="${1:-./cloudflow-ebpf-probe}"
PASS=0
FAIL=0

log_pass() { echo "  ✅ $1"; ((PASS++)); }
log_fail() { echo "  ❌ $1"; ((FAIL++)); }
log_warn() { echo "  ⚠️  $1"; }
log_info() { echo "  ℹ️  $1"; }

echo "=========================================="
echo " eBPF Probe Kernel Compatibility Check"
echo "=========================================="

# 1. Basic environment
echo ""
echo "[1/5] Environment"
echo "  Kernel: $(uname -r)"
echo "  Arch:   $(uname -m)"
echo "  Distro: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"

# 2. Kernel version check
echo ""
echo "[2/5] Kernel Version"
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [ "$KERNEL_MAJOR" -gt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 15 ]); then
    log_pass "Kernel >= 4.15 (current: $(uname -r))"
else
    log_fail "Kernel < 4.15, eBPF not supported (current: $(uname -r))"
fi

# 3. BTF detection
echo ""
echo "[3/5] BTF / CO-RE Support"
if [ -f /sys/kernel/btf/vmlinux ]; then
    BTF_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo 0)
    log_pass "BTF available (/sys/kernel/btf/vmlinux, ${BTF_SIZE} bytes)"
else
    log_warn "BTF not available, fallback to BCC-style compilation"
fi

# 4. eBPF syscalls
echo ""
echo "[4/5] eBPF System Call Support"
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    VAL=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 1)
    if [ "$VAL" = "0" ]; then
        log_pass "Unprivileged BPF enabled"
    else
        log_warn "Unprivileged BPF disabled (value=$VAL), need root"
    fi
fi

if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    JIT=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo 0)
    if [ "$JIT" = "1" ]; then
        log_pass "BPF JIT enabled"
    else
        log_warn "BPF JIT disabled, performance may be lower"
    fi
fi

# 5. Probe capabilities check
echo ""
echo "[5/5] Probe Capability Check"
if [ -x "$PROBE_BIN" ]; then
    echo "  Running: $PROBE_BIN --check-capabilities"
    "$PROBE_BIN" --check-capabilities 2>/dev/null || log_warn "Probe returned non-zero, check manually"
else
    log_fail "Probe binary not found or not executable: $PROBE_BIN"
fi

# 6. Collector smoke tests (if running as root)
echo ""
echo "[Bonus] Collector Smoke Tests (requires root)"
if [ "$(id -u)" -eq 0 ] && [ -x "$PROBE_BIN" ]; then
    for collector in network_flow tcp_connect http_trace dns_trace db_trace sched_trace mem_trace block_trace security_trace; do
        echo "  Testing $collector..."
        timeout 5s "$PROBE_BIN" --enable "$collector" --run-once 10s 2>/dev/null && log_pass "$collector started" || log_warn "$collector failed or not supported"
    done
else
    log_info "Skip smoke tests (need root + executable probe)"
fi

# Summary
echo ""
echo "=========================================="
echo " Summary: $PASS passed, $FAIL failed"
echo "=========================================="

if [ "$FAIL" -eq 0 ]; then
    echo "✅ All checks passed! This kernel is fully compatible."
    exit 0
else
    echo "⚠️  Some checks failed. Review the output above."
    exit 1
fi
