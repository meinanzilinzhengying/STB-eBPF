#!/bin/bash
set -e

# CloudFlow eBPF Probe 一键安装脚本
# 支持: ECS, VM, 物理机, 机顶盒, 容器

VERSION="3.0.0"
ARCH=$(uname -m)
INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
PROBE_NAME="cloudflow-ebpf-probe"

# 检测架构
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
else
    echo "不支持架构: $ARCH"
    exit 1
fi

echo "=========================================="
echo "CloudFlow eBPF Probe 安装脚本"
echo "版本: $VERSION"
echo "架构: $ARCH"
echo "=========================================="

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用 root 权限运行"
    exit 1
fi

# 检查内核版本
KERNEL=$(uname -r)
MAJOR=$(echo $KERNEL | cut -d. -f1)
MINOR=$(echo $KERNEL | cut -d. -f2)
if [ "$MAJOR" -lt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 15 ]); then
    echo "警告: 内核版本 $KERNEL 低于 4.15，部分功能可能不可用"
fi

# 检查依赖
if ! command -v tc &> /dev/null; then
    echo "安装 iproute2..."
    if command -v yum &> /dev/null; then
        yum install -y iproute2 2>/dev/null || yum install -y iproute 2>/dev/null || true
    elif command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y iproute2 2>/dev/null || true
    fi
fi

if ! command -v bpftool &> /dev/null; then
    echo "警告: bpftool 未安装，部分功能受限"
fi

# 下载二进制
BIN_URL="https://github.com/meinanzilinzhengying/ebpf-probe/releases/download/v${VERSION}/${PROBE_NAME}-${VERSION}-linux-${ARCH}.tar.gz"
echo "下载二进制..."
if command -v curl &> /dev/null; then
    curl -L -o /tmp/${PROBE_NAME}.tar.gz "$BIN_URL" 2>/dev/null || echo "下载失败，请手动下载"
elif command -v wget &> /dev/null; then
    wget -O /tmp/${PROBE_NAME}.tar.gz "$BIN_URL" 2>/dev/null || echo "下载失败，请手动下载"
else
    echo "需要 curl 或 wget"
    exit 1
fi

# 如果下载失败，尝试本地二进制
if [ ! -f /tmp/${PROBE_NAME}.tar.gz ]; then
    if [ -f "./${PROBE_NAME}" ]; then
        echo "使用本地二进制..."
        cp "./${PROBE_NAME}" "${INSTALL_DIR}/${PROBE_NAME}"
    else
        echo "未找到二进制文件，请手动放置"
        exit 1
    fi
else
    tar xzf /tmp/${PROBE_NAME}.tar.gz -C /tmp/
    cp /tmp/${PROBE_NAME}-*/${PROBE_NAME} "${INSTALL_DIR}/${PROBE_NAME}"
    chmod +x "${INSTALL_DIR}/${PROBE_NAME}"
fi

# 安装 systemd 服务
if [ -d "$SERVICE_DIR" ] && command -v systemctl &> /dev/null; then
    echo "安装 systemd 服务..."
    if [ -f "./cloudflow-ebpf-probe.service" ]; then
        cp "./cloudflow-ebpf-probe.service" "${SERVICE_DIR}/"
    else
        cat > "${SERVICE_DIR}/cloudflow-ebpf-probe.service" << 'EOF'
[Unit]
Description=CloudFlow eBPF Probe
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflow-ebpf-probe
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload
    systemctl enable cloudflow-ebpf-probe
    systemctl start cloudflow-ebpf-probe
    echo "systemd 服务已启动"
else
    echo "未检测到 systemd，请手动启动: ${INSTALL_DIR}/${PROBE_NAME}"
fi

echo "=========================================="
echo "安装完成!"
echo "二进制: ${INSTALL_DIR}/${PROBE_NAME}"
echo "API: http://localhost:9090/api/probe/status"
echo "=========================================="
