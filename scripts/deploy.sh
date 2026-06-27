#!/bin/bash
#
# deploy.sh - ADB deploy and run script for STB eBPF Probe
#
# This script:
# 1. Pushes binary to target device via ADB
# 2. Sets permissions
# 3. Configures environment (selinux, etc.)
# 4. Starts the probe
# 5. Optionally sets up init script
#
# Usage:
#   ./scripts/deploy.sh [OPTIONS] <device_serial>
#
# Options:
#   -h, --help       Show this help
#   -b, --binary     Path to binary (default: build/output/stb_ebpf_probe)
#   -s, --start      Start probe after deploy
#   -i, --init       Install as init service
#   -r, --restart    Restart if already running
#   -v, --verbose    Verbose output
#

set -e

# ==================== Configuration ====================

# Default values
BINARY_PATH="build/output/stb_ebpf_probe"
START_AFTER_DEPLOY=0
INSTALL_INIT=0
RESTART_IF_RUNNING=0
VERBOSE=0
DEVICE_SERIAL=""

# Target paths
TARGET_DIR="/data/local/tmp"
TARGET_BIN="$TARGET_DIR/stb_ebpf_probe"
TARGET_LOG="$TARGET_DIR/stb_ebpf_probe.log"
INIT_SCRIPT="/system/etc/init.d/stb_ebpf_probe"

# ==================== Functions ====================

print_help() {
    echo "Usage: $0 [OPTIONS] <device_serial>"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help"
    echo "  -b, --binary     Path to binary (default: $BINARY_PATH)"
    echo "  -s, --start      Start probe after deploy"
    echo "  -i, --init       Install as init service"
    echo "  -r, --restart    Restart if already running"
    echo "  -v, --verbose    Verbose output"
    echo ""
    echo "Examples:"
    echo "  $0 -s 123456      # Deploy and start"
    echo "  $0 -i -s 123456  # Install as service and start"
    echo ""
}

log_info() {
    echo "[INFO] $1"
}

log_ok() {
    echo "[OK] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1"
}

log_verbose() {
    if [ $VERBOSE -eq 1 ]; then
        echo "[DEBUG] $1"
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check ADB
    if ! command -v adb &> /dev/null; then
        log_error "ADB not found in PATH"
        exit 1
    fi
    log_ok "ADB found: $(which adb)"
    
    # Check device serial
    if [ -z "$DEVICE_SERIAL" ]; then
        log_error "Device serial not specified"
        echo "Usage: $0 [OPTIONS] <device_serial>"
        exit 1
    fi
    
    # Check ADB connection
    if ! adb -s "$DEVICE_SERIAL" shell "echo test" &> /dev/null; then
        log_error "Cannot connect to device $DEVICE_SERIAL via ADB"
        echo "Make sure:"
        echo "  1. Device is connected"
        echo "  2. USB debugging is enabled"
        echo "  3. ADB authorized on device"
        exit 1
    fi
    log_ok "ADB connection established to $DEVICE_SERIAL"
    
    # Check binary
    if [ ! -f "$BINARY_PATH" ]; then
        log_error "Binary not found: $BINARY_PATH"
        echo "Build first: make userspace"
        exit 1
    fi
    log_ok "Binary found: $BINARY_PATH ($(du -h $BINARY_PATH | cut -f1))"
    
    log_info "Prerequisites check passed"
}

push_binary() {
    log_info "Pushing binary to device..."
    
    # Create target directory
    adb -s "$DEVICE_SERIAL" shell "mkdir -p $TARGET_DIR"
    
    # Push binary
    log_verbose "Pushing $BINARY_PATH to $TARGET_BIN..."
    adb -s "$DEVICE_SERIAL" push "$BINARY_PATH" "$TARGET_BIN"
    
    # Set permissions
    log_verbose "Setting permissions..."
    adb -s "$DEVICE_SERIAL" shell "chmod 755 $TARGET_BIN"
    
    log_ok "Binary pushed and permissions set"
}

check_running() {
    log_info "Checking if probe is already running..."
    
    local pid=$(adb -s "$DEVICE_SERIAL" shell "ps -ef | grep stb_ebpf_probe | grep -v grep | awk '{print \$2}'" 2>/dev/null | tr -d '\r')
    
    if [ -n "$pid" ]; then
        log_warn "Probe is already running (PID: $pid)"
        
        if [ $RESTART_IF_RUNNING -eq 1 ]; then
            log_info "Restarting probe..."
            adb -s "$DEVICE_SERIAL" shell "kill $pid"
            sleep 2
            return 1  # Not running now
        else
            return 0  # Running
        fi
    else
        log_info "Probe is not running"
        return 1  # Not running
    fi
}

setup_environment() {
    log_info "Setting up environment on device..."
    
    # Check/setup BPF filesystem
    adb -s "$DEVICE_SERIAL" shell "mount | grep bpf" &> /dev/null || {
        log_verbose "Mounting BPF filesystem..."
        adb -s "$DEVICE_SERIAL" shell "mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf" 2>/dev/null || true
    }
    
    # Check/setup tracefs
    adb -s "$DEVICE_SERIAL" shell "mount | grep tracefs" &> /dev/null || {
        log_verbose "Mounting tracefs..."
        adb -s "$DEVICE_SERIAL" shell "mkdir -p /sys/kernel/tracing && mount -t tracefs nodev /sys/kernel/tracing" 2>/dev/null || true
    }
    
    # Set SELinux to permissive (if possible)
    local selinux=$(adb -s "$DEVICE_SERIAL" shell "getenforce" 2>/dev/null | tr -d '\r')
    if [ "$selinux" = "Enforcing" ]; then
        log_warn "SELinux is enforcing, trying to set permissive..."
        adb -s "$DEVICE_SERIAL" shell "setenforce 0" 2>/dev/null || true
    fi
    
    # Set resource limits
    log_verbose "Setting resource limits..."
    adb -s "$DEVICE_SERIAL" shell "ulimit -n 4096" 2>/dev/null || true
    adb -s "$DEVICE_SERIAL" shell "ulimit -c 0" 2>/dev/null || true
    
    log_ok "Environment setup complete"
}

start_probe() {
    log_info "Starting probe..."
    
    # Check if already running
    if check_running; then
        log_warn "Probe is already running. Use -r to restart."
        return 0
    fi
    
    # Start probe in background
    log_verbose "Starting $TARGET_BIN..."
    adb -s "$DEVICE_SERIAL" shell "$TARGET_BIN > $TARGET_LOG 2>&1 &"
    
    # Wait for start
    sleep 2
    
    # Verify
    if check_running; then
        log_ok "Probe started successfully"
        
        # Show log
        log_info "Recent log output:"
        adb -s "$DEVICE_SERIAL" shell "tail -20 $TARGET_LOG" 2>/dev/null || true
    else
        log_error "Probe failed to start"
        log_info "Check log: adb -s $DEVICE_SERIAL shell cat $TARGET_LOG"
        return 1
    fi
}

install_init_service() {
    log_info "Installing init service..."
    
    # Create init script
    local init_script=$(cat <<'EOF'
#!/system/bin/sh
#
# stb_ebpf_probe - init script for STB eBPF Probe
#

# Wait for system to be ready
sleep 10

# Start probe
/data/local/tmp/stb_ebpf_probe &

exit 0
EOF
)
    
    # Push init script
    echo "$init_script" > /tmp/stb_ebpf_probe.init
    adb -s "$DEVICE_SERIAL" push /tmp/stb_ebpf_probe.init "$INIT_SCRIPT"
    adb -s "$DEVICE_SERIAL" shell "chmod 755 $INIT_SCRIPT"
    
    # Enable init script (if init.d supported)
    adb -s "$DEVICE_SERIAL" shell "ls -d /system/etc/init.d" &> /dev/null && {
        log_ok "Init script installed at $INIT_SCRIPT"
        log_info "Service will start on boot"
    } || {
        log_warn "init.d not supported, service won't auto-start"
    }
    
    rm -f /tmp/stb_ebpf_probe.init
    
    log_ok "Init service installed"
}

stop_probe() {
    log_info "Stopping probe..."
    
    if check_running; then
        local pid=$(adb -s "$DEVICE_SERIAL" shell "ps -ef | grep stb_ebpf_probe | grep -v grep | awk '{print \$2}'" 2>/dev/null | tr -d '\r')
        adb -s "$DEVICE_SERIAL" shell "kill $pid"
        sleep 1
        log_ok "Probe stopped"
    else
        log_info "Probe is not running"
    fi
}

show_status() {
    log_info "Probe status:"
    
    # Check if running
    if check_running; then
        local pid=$(adb -s "$DEVICE_SERIAL" shell "ps -ef | grep stb_ebpf_probe | grep -v grep | awk '{print \$2}'" 2>/dev/null | tr -d '\r')
        log_ok "Probe is running (PID: $pid)"
        
        # Show resource usage
        log_info "Resource usage:"
        adb -s "$DEVICE_SERIAL" shell "ps -p $pid -o pid,ppid,pcpu,pmem,vsz,rss" 2>/dev/null || true
        
        # Show recent log
        log_info "Recent log (last 10 lines):"
        adb -s "$DEVICE_SERIAL" shell "tail -10 $TARGET_LOG" 2>/dev/null || true
    else
        log_info "Probe is not running"
    fi
}

# ==================== Main ====================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit 0
            ;;
        -b|--binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        -s|--start)
            START_AFTER_DEPLOY=1
            shift
            ;;
        -i|--init)
            INSTALL_INIT=1
            shift
            ;;
        -r|--restart)
            RESTART_IF_RUNNING=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        *)
            DEVICE_SERIAL="$1"
            shift
            ;;
    esac
done

# Main flow
echo "=============================================="
echo "STB eBPF Probe - Deploy Script"
echo "=============================================="
echo ""

# Check prerequisites
check_prerequisites
echo ""

# Push binary
push_binary
echo ""

# Setup environment
setup_environment
echo ""

# Install init service (optional)
if [ $INSTALL_INIT -eq 1 ]; then
    install_init_service
    echo ""
fi

# Start probe (optional)
if [ $START_AFTER_DEPLOY -eq 1 ]; then
    start_probe
    echo ""
    
    # Show status
    show_status
    echo ""
fi

echo "=============================================="
echo "Deploy completed successfully"
echo "=============================================="
echo ""

# Print useful commands
echo "Useful commands:"
echo "  View log:    adb -s $DEVICE_SERIAL shell cat $TARGET_LOG"
echo "  Stop probe:  adb -s $DEVICE_SERIAL shell killall stb_ebpf_probe"
echo "  Restart:     adb -s $DEVICE_SERIAL shell $TARGET_BIN"
echo "  Check status: adb -s $DEVICE_SERIAL shell ps | grep stb_ebpf_probe"
echo ""

exit 0
