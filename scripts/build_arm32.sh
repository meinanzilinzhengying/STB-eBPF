#!/bin/bash
# build_arm32.sh - Cross-compile P0 core only
set -e

PROJECT_ROOT="/opt/cloudflow/ebpf-probe"
cd "$PROJECT_ROOT"

echo "=== STB eBPF Probe ARM32 Cross-Compile (P0 Core) ==="

# Step 1: Compile P0 core BPF files
echo "=== Step 1: Compiling P0 Core BPF programs ==="
BPF_FLAGS="-O2 -g -target bpf -D__TARGET_ARCH_arm"
BPF_INCLUDES="-I bpf"

for bpf_file in tcp_connect.bpf.c network_flow.bpf.c process_exec.bpf.c; do
    base_name="${bpf_file%.bpf.c}"
    output_file="bpf/${base_name}.bpf.o"
    echo "  Compiling: $bpf_file"
    clang $BPF_FLAGS -c "bpf/$bpf_file" -o "$output_file" $BPF_INCLUDES
    llvm-strip --strip-debug "$output_file" 2>/dev/null || true
done

echo "  P0 Core BPF compilation DONE"
echo ""

# Step 2: Copy .o files to internal/collector/
echo "=== Step 2: Copying .o files ==="
cp bpf/tcp_connect.bpf.o internal/collector/ 2>/dev/null || echo "  (internal/collector/ not found)"
cp bpf/network_flow.bpf.o internal/collector/ 2>/dev/null || echo "  (internal/collector/ not found)"
cp bpf/process_exec.bpf.o internal/collector/ 2>/dev/null || echo "  (internal/collector/ not found)"
echo "  Copy DONE"
echo ""

# Step 3: Cross-compile Go binary
echo "=== Step 3: Cross-compiling Go binary (ARM32) ==="
GO_FLAGS='-ldflags "-X github.com/meinanzilinzhengying/ebpf-probe.Version=3.1.0-stb-p0-core -s -w"'
BINARY="cloudflow-ebpf-probe-arm32-p0-core"

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $GO_FLAGS -o "$BINARY" ./cmd/probe/

echo "  Binary: $BINARY"
echo "  Size: $(du -h $BINARY | cut -f1)"
echo ""

# Step 4: Create deployment package
echo "=== Step 4: Creating deployment package ==="
PKG_DIR="dist/stb-arm32-p0-core"
mkdir -p "$PKG_DIR"
cp "$BINARY" "$PKG_DIR/cloudflow-ebpf-probe"
cp config/config.yaml "$PKG_DIR/"
echo "  Package dir: $PKG_DIR"
echo ""

echo "=== Build COMPLETE (P0 Core Only) ==="
echo "Completed collectors:"
echo "  1. tcp_connect (TCP connection monitoring)"
echo "  2. network_flow (Network traffic monitoring)"
echo "  3. process_exec (Process execution monitoring)"
echo ""
echo "Next steps:"
echo "  1. adb push $PKG_DIR/cloudflow-ebpf-probe /tmp/"
echo "  2. adb shell 'chmod +x /tmp/cloudflow-ebpf-probe'"
echo "  3. adb shell '/tmp/cloudflow-ebpf-probe -v 2'"
