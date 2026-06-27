# Makefile - Main build file for STB eBPF Probe
# 
# This Makefile handles:
# - Host BPF compilation (Clang/LLVM)
# - Target C cross-compilation (ARMv7l, Android NDK)
# - Linking and packaging
# 
# Requirements:
# - Clang/LLVM (for BPF compilation)
# - Android NDK (for ARMv7l cross-compilation)
# - libbpf (for BPF loader)
# - libelf, libz (dependencies)

# ==================== Configuration ====================

# Project info
PROJECT_NAME := stb_ebpf_probe
VERSION := 4.2.0

# Directories
ROOT_DIR := $(shell pwd)
BPF_DIR := $(ROOT_DIR)/bpf
SRC_DIR := $(ROOT_DIR)/src
INCLUDE_DIR := $(ROOT_DIR)/include
BUILD_DIR := $(ROOT_DIR)/build
OUTPUT_DIR := $(BUILD_DIR)/output

# Target configuration
TARGET_ARCH := armv7l
TARGET_OS := android
TARGET_KERNEL := 5.4.210

# Toolchain (Android NDK)
ANDROID_NDK ?= $(HOME)/Android/Sdk/ndk/25.2.9519653
NDK_TOOLCHAIN := $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64
CC_ARM := $(NDK_TOOLCHAIN)/bin/armv7a-linux-androideabi21-clang
CXX_ARM := $(NDK_TOOLCHAIN)/bin/armv7a-linux-androideabi21-clang++
AR_ARM := $(NDK_TOOLCHAIN)/bin/arm-linux-androideabi-ar
LD_ARM := $(NDK_TOOLCHAIN)/bin/arm-linux-androideabi-ld

# Host tools
CC_HOST := clang
CC := $(CC_HOST)
BPF_CC := clang
BPF_CFLAGS := -target bpf -O2 -g -Wall -Werror
BPF_CFLAGS += -D__TARGET_ARCH_arm -I$(INCLUDE_DIR)
BPF_CFLAGS += -I/usr/include/bpf
BPF_CFLAGS += -fno-stack-protector

# C flags for target
CFLAGS := -O2 -Wall -Wextra -Werror
CFLAGS += -D_GNU_SOURCE -DANDROID -D__ANDROID_API__=21
CFLAGS += -I$(INCLUDE_DIR) -I$(SRC_DIR)
CFLAGS += -static  # Static linking for Android
CFLAGS += -fPIE -pie  # Position Independent Executable
CFLAGS += -fstack-protector-strong
CFLAGS += -Wno-unused-variable -Wno-unused-function

# LDFLAGS
LDFLAGS := -static
LDFLAGS += -lbpf -lelf -lz  # BPF libraries
LDFLAGS += -llog  # Android logging
LDFLAGS += -pthread

# ==================== Source Files ====================

# BPF source files
BPF_SRCS := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(BPF_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))

# Userspace source files
USR_SRCS := $(wildcard $(SRC_DIR)/*.c)
USR_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(USR_SRCS))

# ==================== Build Targets ====================

.PHONY: all clean bpf userspace help install deploy

# Default target
all: bpf userspace

# Help
help:
	@echo "STB eBPF Probe Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build everything (default)"
	@echo "  bpf        - Compile BPF programs only"
	@echo "  userspace  - Compile userspace program only"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to target (requires ADB)"
	@echo "  deploy     - Deploy to target (alias for install)"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  ANDROID_NDK   - Path to Android NDK (default: $(ANDROID_NDK))"
	@echo "  TARGET_ARCH   - Target architecture (default: $(TARGET_ARCH))"
	@echo ""

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(OUTPUT_DIR)

# ==================== BPF Compilation ====================

# Compile BPF C file to object file
$(BUILD_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BUILD_DIR)
	@echo "[BPF] Compiling $<..."
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@
	@echo "[BPF] Generated $@"

# BPF target: compile all BPF programs
bpf: $(BPF_OBJS)
	@echo "[BPF] All BPF programs compiled successfully"
	@ls -la $(BUILD_DIR)/*.bpf.o

# ==================== Userspace Compilation ====================

# Compile userspace C file to object file (host)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "[USR] Compiling (host) $<..."
	$(CC_HOST) $(CFLAGS) -c $< -o $@

# Cross-compile userspace C file to object file (ARM)
$(BUILD_DIR)/%-arm.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "[USR] Cross-compiling (ARM) $<..."
	$(CC_ARM) $(CFLAGS) -c $< -o $@

# Userspace target (host build)
userspace-host: $(USR_OBJS)
	@echo "[USR] Linking (host)..."
	$(CC_HOST) -o $(OUTPUT_DIR)/$(PROJECT_NAME) $(USR_OBJS) $(LDFLAGS)
	@echo "[USR] Built: $(OUTPUT_DIR)/$(PROJECT_NAME)"

# Userspace target (ARM cross-compile)
userspace: $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%-arm.o,$(USR_SRCS))
	@echo "[USR] Linking (ARM)..."
	$(CC_ARM) -o $(OUTPUT_DIR)/$(PROJECT_NAME) \
		$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%-arm.o,$(USR_SRCS)) \
		$(LDFLAGS)
	@echo "[USR] Built: $(OUTPUT_DIR)/$(PROJECT_NAME)"
	@echo "[USR] Binary info:"
	@file $(OUTPUT_DIR)/$(PROJECT_NAME) || true
	@$(NDK_TOOLCHAIN)/bin/arm-linux-androideabi-readelf -h $(OUTPUT_DIR)/$(PROJECT_NAME) || true

# ==================== Clean ====================

# Clean build artifacts
clean:
	@echo "[CLEAN] Removing build directory..."
	rm -rf $(BUILD_DIR)
	@echo "[CLEAN] Done"

# ==================== Install/Deploy ====================

# Install to target via ADB
install: userspace
	@echo "[INSTALL] Installing to target..."
	@if [ -z "$(TARGET_DEVICE)" ]; then \
		echo "Error: TARGET_DEVICE not set. Usage: make install TARGET_DEVICE=<serial>"; \
		exit 1; \
	fi
	adb -s $(TARGET_DEVICE) push $(OUTPUT_DIR)/$(PROJECT_NAME) /data/local/tmp/
	adb -s $(TARGET_DEVICE) shell "chmod +x /data/local/tmp/$(PROJECT_NAME)"
	@echo "[INSTALL] Done"

# Deploy (alias for install)
deploy: install

# ==================== Test ====================

# Test BPF compilation (host)
test-bpf: bpf
	@echo "[TEST] Testing BPF object files..."
	@for obj in $(BUILD_DIR)/*.bpf.o; do \
		echo "Checking $$obj..."; \
		llvm-objdump -h $$obj || true; \
	done

# ==================== Dependencies ====================

# Print dependencies
deps:
	@echo "Dependencies:"
	@echo "  Clang/LLVM: $(shell which $(CC_HOST) >/dev/null 2>&1 && echo "OK" || echo "MISSING")"
	@echo "  Android NDK: $(shell test -d $(ANDROID_NDK) && echo "OK" || echo "MISSING")"
	@echo "  libbpf: $(shell pkg-config --exists libbpf && echo "OK" || echo "MISSING")"
	@echo "  libelf: $(shell pkg-config --exists libelf && echo "OK" || echo "MISSING")"
	@echo "  libz: $(shell pkg-config --exists zlib && echo "OK" || echo "MISSING")"

# ==================== Docker Build (optional) ====================

# Docker build for reproducible environment
docker-build:
	docker build -t stb-ebpf-builder -f Dockerfile .
	docker run --rm -v $(ROOT_DIR):/src stb-ebpf-builder

# ==================== Package ====================

# Package for distribution
package: userspace
	@echo "[PACKAGE] Creating package..."
	mkdir -p $(OUTPUT_DIR)/package
	cp $(OUTPUT_DIR)/$(PROJECT_NAME) $(OUTPUT_DIR)/package/
	cp scripts/deploy.sh $(OUTPUT_DIR)/package/
	cd $(OUTPUT_DIR)/package && tar czf ../$(PROJECT_NAME)-$(VERSION)-$(TARGET_ARCH).tar.gz *
	@echo "[PACKAGE] Created: $(OUTPUT_DIR)/$(PROJECT_NAME)-$(VERSION)-$(TARGET_ARCH).tar.gz"

# ==================== Debug ====================

# Debug info
debug:
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Root dir: $(ROOT_DIR)"
	@echo "BPF sources: $(BPF_SRCS)"
	@echo "BPF objects: $(BPF_OBJS)"
	@echo "Userspace sources: $(USR_SRCS)"
	@echo "Userspace objects: $(USR_OBJS)"
	@echo "Output: $(OUTPUT_DIR)/$(PROJECT_NAME)"

# ==================== End of Makefile ====================
