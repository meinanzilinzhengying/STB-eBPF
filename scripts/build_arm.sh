#!/bin/bash
#
# build_arm.sh - One-click cross-compilation script for STB eBPF Probe
#
# This script cross-compiles the entire project for ARMv7l (STB target).
#
# Requirements:
# - Android NDK 25+ (set ANDROID_NDK environment variable)
# - Clang/LLVM (for BPF compilation)
# - libbpf, libelf, libz (for userspace)
#
# Usage:
#   ./scripts/build_arm.sh [OPTIONS]
#
# Options:
#   -h, --help      Show this help
#   -c, --clean     Clean before build
#   -v, --verbose  Verbose output
#   -t, --test     Build test mode (stdout output)
#

set -e  # Exit on error

# ==================== Configuration ====================

# Project root (relative to this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
CLEAN_BUILD=0
VERBOSE=0
TEST_MODE=0

# Android NDK path
if [ -z "$ANDROID_NDK" ]; then
    # Try to find NDK
    if [ -d "$HOME/Android/Sdk/ndk" ]; then
        ANDROID_NDK=$(ls -d $HOME/Android/Sdk/ndk/* 2>/dev/null | sort -V | tail -1)
    fi
    
    if [ -z "$ANDROID_NDK" ]; then
        echo "Error: ANDROID_NDK not set and not found automatically"
        echo "Please set ANDROID_NDK environment variable"
        exit 1
    fi
fi

# Toolchain
NDK_TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64"
CC_ARM="$NDK_TOOLCHAIN/bin/armv7a-linux-androideabi21-clang"
CXX_ARM="$NDK_TOOLCHAIN/bin/armv7a-linux-androideabi21-clang++"
AR_ARM="$NDK_TOOLCHAIN/bin/arm-linux-androideabi-ar"
LD_ARM="$NDK_TOOLCHAIN/bin/arm-linux-androideabi-ld"

# Build directories
BUILD_DIR="$PROJECT_ROOT/build"
OUTPUT_DIR="$BUILD_DIR/output"
BPF_DIR="$PROJECT_ROOT/bpf"
SRC_DIR="$PROJECT_ROOT/src"
INCLUDE_DIR="$PROJECT_ROOT/include"

# ==================== Functions ====================

print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help"
    echo "  -c, --clean     Clean before build"
    echo "  -v, --verbose  Verbose output"
    echo "  -t, --test     Build test mode"
    echo ""
    echo "Environment variables:"
    echo "  ANDROID_NDK     Path to Android NDK (current: $ANDROID_NDK)"
    echo ""
}

print_config() {
    echo "==============================================="
    echo "STB eBPF Probe - Cross-compilation Script"
    echo "==============================================="
    echo "Project root: $PROJECT_ROOT"
    echo "Android NDK:  $ANDROID_NDK"
    echo "Toolchain:     $NDK_TOOLCHAIN"
    echo "CC (ARM):     $CC_ARM"
    echo "Build dir:     $BUILD_DIR"
    echo "Output dir:    $OUTPUT_DIR"
    echo "Clean build:   $CLEAN_BUILD"
    echo "Verbose:       $VERBOSE"
    echo "Test mode:     $TEST_MODE"
    echo "==============================================="
    echo ""
}

check_prerequisites() {
    echo "[CHECK] Checking prerequisites..."
    
    # Check NDK
    if [ ! -d "$ANDROID_NDK" ]; then
        echo "Error: Android NDK not found at $ANDROID_NDK"
        exit 1
    fi
    echo "[OK] Android NDK found"
    
    # Check ARM compiler
    if [ ! -x "$CC_ARM" ]; then
        echo "Error: ARM compiler not found at $CC_ARM"
        exit 1
    fi
    echo "[OK] ARM compiler found"
    
    # Check Clang (for BPF)
    if ! command -v clang &> /dev/null; then
        echo "Error: Clang not found (required for BPF compilation)"
        exit 1
    fi
    echo "[OK] Clang found"
    
    # Check libbpf
    if ! pkg-config --exists libbpf 2>/dev/null; then
        echo "Warning: libbpf not found via pkg-config"
        echo "  (Will attempt to build anyway)"
    else
        echo "[OK] libbpf found"
    fi
    
    echo "[CHECK] Prerequisites check passed"
    echo ""
}

clean_build() {
    if [ $CLEAN_BUILD -eq 1 ]; then
        echo "[CLEAN] Cleaning build directory..."
        rm -rf "$BUILD_DIR"
        echo "[CLEAN] Done"
        echo ""
    fi
}

create_dirs() {
    echo "[SETUP] Creating build directories..."
    mkdir -p "$BUILD_DIR"
    mkdir -p "$OUTPUT_DIR"
    echo "[SETUP] Done"
    echo ""
}

compile_bpf() {
    echo "[BPF] Compiling BPF programs..."
    
    local bpf_src="$BPF_DIR/stb_connect.bpf.c"
    local bpf_obj="$BUILD_DIR/stb_connect.bpf.o"
    
    if [ ! -f "$bpf_src" ]; then
        echo "Error: BPF source not found: $bpf_src"
        exit 1
    fi
    
    # BPF compilation flags
    local bpf_flags="-target bpf -O2 -g -Wall -Werror"
    bpf_flags="$bpf_flags -D__TARGET_ARCH_arm"
    bpf_flags="$bpf_flags -I$INCLUDE_DIR"
    bpf_flags="$bpf_flags -I/usr/include/bpf"
    bpf_flags="$bpf_flags -fno-stack-protector"
    bpf_flags="$bpf_flags -Wno-unused-variable -Wno-unused-function"
    
    # Compile
    echo "[BPF] Command: clang $bpf_flags -c $bpf_src -o $bpf_obj"
    
    if [ $VERBOSE -eq 1 ]; then
        clang $bpf_flags -c "$bpf_src" -o "$bpf_obj"
    else
        clang $bpf_flags -c "$bpf_src" -o "$bpf_obj" 2>&1 | tee "$BUILD_DIR/bpf_compile.log"
        if [ ${PIPESTATUS[0]} -ne 0 ]; then
            echo "Error: BPF compilation failed. See $BUILD_DIR/bpf_compile.log"
            exit 1
        fi
    fi
    
    echo "[BPF] Generated: $bpf_obj"
    echo "[BPF] Done"
    echo ""
}

compile_userspace() {
    echo "[USR] Compiling userspace program..."
    
    # Find all .c files in src/
    local src_files=$(find "$SRC_DIR" -name "*.c" -type f)
    
    if [ -z "$src_files" ]; then
        echo "Error: No source files found in $SRC_DIR"
        exit 1
    fi
    
    # Compilation flags
    local c_flags="-O2 -Wall -Wextra -Werror"
    c_flags="$c_flags -D_GNU_SOURCE -DANDROID -D__ANDROID_API__=21"
    c_flags="$c_flags -I$INCLUDE_DIR -I$SRC_DIR"
    c_flags="$c_flags -static"
    c_flags="$c_flags -fPIE -pie"
    c_flags="$c_flags -fstack-protector-strong"
    c_flags="$c_flags -Wno-unused-variable -Wno-unused-function"
    
    if [ $TEST_MODE -eq 1 ]; then
        c_flags="$c_flags -DTEST_MODE=1"
    fi
    
    # Compile each source file
    local obj_files=""
    for src in $src_files; do
        local obj="$BUILD_DIR/$(basename $src .c)-arm.o"
        obj_files="$obj_files $obj"
        
        echo "[USR] Compiling: $src -> $obj"
        
        if [ $VERBOSE -eq 1 ]; then
            "$CC_ARM" $c_flags -c "$src" -o "$obj"
        else
            "$CC_ARM" $c_flags -c "$src" -o "$obj" 2>&1 | tee "$BUILD_DIR/$(basename $src .c).log"
            if [ ${PIPESTATUS[0]} -ne 0 ]; then
                echo "Error: Compilation failed for $src. See $BUILD_DIR/$(basename $src .c).log"
                exit 1
            fi
        fi
    done
    
    echo "[USR] Done compiling"
    echo ""
    
    # Link
    echo "[USR] Linking..."
    
    local output="$OUTPUT_DIR/stb_ebpf_probe"
    local ld_flags="-static"
    ld_flags="$ld_flags -lbpf -lelf -lz"
    ld_flags="$ld_flags -llog"
    ld_flags="$ld_flags -pthread"
    
    echo "[USR] Command: $CC_ARM -o $output $obj_files $ld_flags"
    
    if [ $VERBOSE -eq 1 ]; then
        "$CC_ARM" -o "$output" $obj_files $ld_flags
    else
        "$CC_ARM" -o "$output" $obj_files $ld_flags 2>&1 | tee "$BUILD_DIR/link.log"
        if [ ${PIPESTATUS[0]} -ne 0 ]; then
            echo "Error: Linking failed. See $BUILD_DIR/link.log"
            exit 1
        fi
    fi
    
    echo "[USR] Generated: $output"
    echo "[USR] Binary info:"
    file "$output" || true
    "$NDK_TOOLCHAIN/bin/arm-linux-androideabi-readelf" -h "$output" 2>/dev/null || true
    echo "[USR] Done"
    echo ""
}

run_tests() {
    echo "[TEST] Running post-build tests..."
    
    local output="$OUTPUT_DIR/stb_ebpf_probe"
    
    # Check if binary exists
    if [ ! -f "$output" ]; then
        echo "Error: Binary not found: $output"
        exit 1
    fi
    
    # Check architecture
    local arch=$(file "$output" | grep -o "ARM")
    if [ -z "$arch" ]; then
        echo "Warning: Binary may not be ARM architecture"
    else
        echo "[TEST] Architecture: $arch"
    fi
    
    # Check static linking
    if readelf -d "$output" 2>/dev/null | grep -q "NEEDED"; then
        echo "Warning: Binary has dynamic dependencies"
    else
        echo "[TEST] Static linking: OK"
    fi
    
    echo "[TEST] Done"
    echo ""
}

print_summary() {
    echo "==============================================="
    echo "Build Summary"
    echo "==============================================="
    echo "Output: $OUTPUT_DIR/stb_ebpf_probe"
    echo "Size:   $(du -h $OUTPUT_DIR/stb_ebpf_probe | cut -f1)"
    echo "Arch:   $(file $OUTPUT_DIR/stb_ebpf_probe | cut -d: -f2 | xargs)"
    echo "==============================================="
    echo ""
    echo "To deploy to target:"
    echo "  ./scripts/deploy.sh <target_serial>"
    echo ""
}

# ==================== Main ====================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit 0
            ;;
        -c|--clean)
            CLEAN_BUILD=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -t|--test)
            TEST_MODE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Main flow
print_config
check_prerequisites
clean_build
create_dirs
compile_bpf
compile_userspace
run_tests
print_summary

echo "Build completed successfully!"
exit 0
