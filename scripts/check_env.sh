#!/bin/bash
#
# check_env.sh - Target device environment check for STB eBPF Probe
#
# This script checks:
# - Kernel version and BPF support
# - Available features (tracepoint, perf_event, etc.)
# - Permissions (root, seccomp, etc.)
# - SELinux status
# - Available resources (CPU, memory)
# - Network connectivity
#
# Usage:
#   ./scripts/check_env.sh [OPTIONS]
#
# Options:
#   -h, --help       Show this help
#   -d, --device     Target device serial (for ADB)
#   -l, --local      Check local environment (default)
#   -r, --remote     Check remote device via ADB
#   -v, --verbose    Verbose output
#

set -e

# ==================== Configuration ====================

# Default values
CHECK_LOCAL=1
CHECK_REMOTE=0
DEVICE_SERIAL=""
VERBOSE=0
OUTPUT_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==================== Functions ====================

print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help"
    echo "  -d, --device     Target device serial (for ADB)"
    echo "  -l, --local      Check local environment (default)"
    echo "  -r, --remote     Check remote device via ADB"
    echo "  -v, --verbose    Verbose output"
    echo "  -o, --output     Output file for report"
    echo ""
    echo "Examples:"
    echo "  $0 -l             # Check local"
    echo "  $0 -r -d 123456  # Check remote device 123456"
    echo ""
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ $VERBOSE -eq 1 ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# ==================== Check Functions ====================

check_kernel_version() {
    log_info "Checking kernel version..."
    
    local kernel_version=$(uname -r)
    local kernel_major=$(echo $kernel_version | cut -d. -f1)
    local kernel_minor=$(echo $kernel_version | cut -d. -f2)
    
    echo "  Kernel version: $kernel_version"
    echo "  Major: $kernel_major, Minor: $kernel_minor"
    
    # Check minimum version (4.17 for tracepoint support)
    if [ $kernel_major -lt 4 ] || ([ $kernel_major -eq 4 ] && [ $kernel_minor -lt 17 ]); then
        log_error "Kernel version too old. Need 4.17+ for BPF tracepoint."
        return 1
    fi
    
    log_ok "Kernel version OK (>= 4.17)"
    
    # Check for BPF filesystem
    if [ -d /sys/fs/bpf ]; then
        log_ok "BPF filesystem mounted at /sys/fs/bpf"
        log_verbose "  Contents: $(ls /sys/fs/bpf 2>/dev/null | head -5)"
    else
        log_warn "BPF filesystem not mounted at /sys/fs/bpf"
        echo "  Try: mount -t bpf bpf /sys/fs/bpf"
    fi
    
    # Check kernel config for BPF
    log_info "Checking kernel config for BPF support..."
    
    if [ -f /proc/config.gz ]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
            log_ok "CONFIG_BPF=y found in kernel config"
        else
            log_warn "CONFIG_BPF not found in kernel config"
        fi
        
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF_SYSCALL=y"; then
            log_ok "CONFIG_BPF_SYSCALL=y found"
        else
            log_warn "CONFIG_BPF_SYSCALL not found"
        fi
    else
        log_warn "Cannot check kernel config (/proc/config.gz not found)"
    fi
    
    return 0
}

check_bpf_support() {
    log_info "Checking BPF support..."
    
    # Check for BPF syscall
    if [ -f /proc/kallsyms ]; then
        if grep -q "bpf" /proc/kallsyms 2>/dev/null; then
            log_ok "BPF symbols found in /proc/kallsyms"
            log_verbose "  Sample: $(grep bpf /proc/kallsyms | head -3)"
        else
            log_warn "No BPF symbols found in /proc/kallsyms"
        fi
    fi
    
    # Check for BPF type format (BTF) - optional
    if [ -f /sys/kernel/btf/vmlinux ]; then
        log_ok "BTF available at /sys/kernel/btf/vmlinux"
    else
        log_warn "BTF not available (will use legacy mode)"
    fi
    
    # Check for perf event support
    if [ -d /sys/bus/event_source/devices/perf ]; then
        log_ok "Perf event support available"
    else
        log_warn "Perf event support may be missing"
    fi
    
    return 0
}

check_tracepoint() {
    log_info "Checking tracepoint support..."
    
    # Check for tracefs
    local tracefs_path=""
    if [ -d /sys/kernel/debug/tracing ]; then
        tracefs_path="/sys/kernel/debug/tracing"
    elif [ -d /sys/kernel/tracing ]; then
        tracefs_path="/sys/kernel/tracing"
    fi
    
    if [ -z "$tracefs_path" ]; then
        log_error "Tracefs not mounted"
        echo "  Try: mount -t tracefs nodev /sys/kernel/tracing"
        return 1
    fi
    
    log_ok "Tracefs mounted at $tracefs_path"
    log_verbose "  Contents: $(ls $tracefs_path | head -5)"
    
    # Check for syscalls tracepoints
    local syscall_events="$tracefs_path/events/syscalls"
    if [ -d "$syscall_events" ]; then
        log_ok "Syscalls tracepoints available"
        log_verbose "  Events: $(ls $syscall_events | head -5)"
        
        # Check for connect events
        if [ -d "$syscall_events/sys_enter_connect" ]; then
            log_ok "sys_enter_connect tracepoint available"
        else
            log_warn "sys_enter_connect tracepoint not found"
        fi
        
        if [ -d "$syscall_events/sys_exit_connect" ]; then
            log_ok "sys_exit_connect tracepoint available"
        else
            log_warn "sys_exit_connect tracepoint not found"
        fi
    else
        log_error "Syscalls tracepoints not found"
        return 1
    fi
    
    return 0
}

check_permissions() {
    log_info "Checking permissions..."
    
    # Check if running as root
    if [ $(id -u) -eq 0 ]; then
        log_ok "Running as root"
    else
        log_warn "Not running as root (UID=$(id -u))"
        echo "  Some BPF operations may fail"
    fi
    
    # Check for seccomp
    if [ -f /proc/self/status ]; then
        local seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')
        if [ -n "$seccomp" ]; then
            echo "  Seccomp status: $seccomp"
            if [ "$seccomp" -eq 2 ]; then
                log_warn "Seccomp in strict mode, BPF may be blocked"
            fi
        fi
    fi
    
    # Check for capabilities
    if command -v capsh &>/dev/null; then
        log_verbose "  Capabilities: $(capsh --print 2>/dev/null | grep -i cap)"
    fi
    
    return 0
}

check_selinux() {
    log_info "Checking SELinux status..."
    
    if command -v getenforce &>/dev/null; then
        local selinux_status=$(getenforce 2>/dev/null)
        echo "  SELinux status: $selinux_status"
        
        if [ "$selinux_status" = "Enforcing" ]; then
            log_warn "SELinux is enforcing, may block BPF"
        else
            log_ok "SELinux is not enforcing"
        fi
    else
        log_info "SELinux not installed (getenforce not found)"
    fi
    
    return 0
}

check_resources() {
    log_info "Checking system resources..."
    
    # CPU info
    if [ -f /proc/cpuinfo ]; then
        local cpu_cores=$(grep -c processor /proc/cpuinfo 2>/dev/null || echo "unknown")
        echo "  CPU cores: $cpu_cores"
    fi
    
    # Memory info
    if [ -f /proc/meminfo ]; then
        local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        local mem_free=$(grep MemFree /proc/meminfo | awk '{print $2}')
        echo "  Memory total: ${mem_total}K"
        echo "  Memory free: ${mem_free}K"
        
        # Check minimum memory (100MB)
        if [ $mem_total -lt 102400 ]; then  # 100MB in KB
            log_warn "Low memory: ${mem_total}K (recommend 100MB+)"
        else
            log_ok "Memory OK: ${mem_total}K"
        fi
    fi
    
    # Disk space
    local disk_avail=$(df -k / 2>/dev/null | tail -1 | awk '{print $4}')
    if [ -n "$disk_avail" ]; then
        echo "  Disk space available: ${disk_avail}K"
    fi
    
    return 0
}

check_network() {
    log_info "Checking network connectivity..."
    
    # Check for network interfaces
    if [ -f /proc/net/dev ]; then
        echo "  Network interfaces:"
        grep -v "lo:" /proc/net/dev 2>/dev/null | awk -F: '{print "    " $1}' | head -5
    fi
    
    # Check for default route
    if command -v ip &>/dev/null; then
        local default_route=$(ip route show default 2>/dev/null | head -1)
        if [ -n "$default_route" ]; then
            log_ok "Default route found: $default_route"
        else
            log_warn "No default route found"
        fi
    fi
    
    return 0
}

check_android() {
    log_info "Checking Android-specific features..."
    
    # Check for Android properties
    if command -v getprop &>/dev/null; then
        local api_level=$(getprop ro.build.version.sdk 2>/dev/null || echo "unknown")
        local product=$(getprop ro.product.model 2>/dev/null || echo "unknown")
        
        echo "  Android API level: $api_level"
        echo "  Product model: $product"
        
        # Check for SELinux (Android-specific)
        local selinux=$(getprop ro.boot.selinux 2>/dev/null || echo "unknown")
        echo "  SELinux policy: $selinux"
    else
        log_info "Not an Android device (getprop not found)"
    fi
    
    # Check for ADB
    if [ -f /data/local/tmp ]; then
        log_ok "/data/local/tmp exists (ADB writable)"
    else
        log_warn "/data/local/tmp not accessible"
    fi
    
    return 0
}

# ==================== Main ====================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit 0
            ;;
        -d|--device)
            DEVICE_SERIAL="$2"
            CHECK_REMOTE=1
            CHECK_LOCAL=0
            shift 2
            ;;
        -l|--local)
            CHECK_LOCAL=1
            CHECK_REMOTE=0
            shift
            ;;
        -r|--remote)
            CHECK_REMOTE=1
            CHECK_LOCAL=0
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Print header
echo "==============================================="
echo "STB eBPF Probe - Environment Check"
echo "==============================================="
echo ""

# Check local environment
if [ $CHECK_LOCAL -eq 1 ]; then
    echo "=== Local Environment ==="
    check_kernel_version
    echo ""
    check_bpf_support
    echo ""
    check_tracepoint
    echo ""
    check_permissions
    echo ""
    check_selinux
    echo ""
    check_resources
    echo ""
    check_network
    echo ""
    echo "=== End Local Environment ==="
    echo ""
fi

# Check remote device via ADB
if [ $CHECK_REMOTE -eq 1 ]; then
    if [ -z "$DEVICE_SERIAL" ]; then
        echo "Error: Device serial not specified. Use -d <serial>"
        exit 1
    fi
    
    echo "=== Remote Device ($DEVICE_SERIAL) ==="
    echo "Connecting via ADB..."
    
    # Check ADB connection
    if ! adb -s "$DEVICE_SERIAL" shell "echo test" &>/dev/null; then
        echo "Error: Cannot connect to device $DEVICE_SERIAL via ADB"
        exit 1
    fi
    
    log_ok "ADB connection established"
    
    # Run checks on remote device
    echo ""
    echo "Running remote checks..."
    
    adb -s "$DEVICE_SERIAL" shell "uname -a"
    echo ""
    
    # Kernel version
    adb -s "$DEVICE_SERIAL" shell "sh -c 'uname -r | cut -d. -f1,2'"
    echo ""
    
    # Check tracefs
    adb -s "$DEVICE_SERIAL" shell "ls -d /sys/kernel/debug/tracing /sys/kernel/tracing 2>/dev/null"
    echo ""
    
    # Memory
    adb -s "$DEVICE_SERIAL" shell "cat /proc/meminfo | grep MemTotal"
    echo ""
    
    echo "=== End Remote Device ==="
    echo ""
fi

# Print summary
echo "==============================================="
echo "Environment Check Summary"
echo "==============================================="
echo "All checks completed. Review output above for details."
echo ""

exit 0
