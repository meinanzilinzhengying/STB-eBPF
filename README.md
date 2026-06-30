# STB-eBPF - Android 机顶盒 eBPF 采集探针

[![Go Version](https://img.shields.io/badge/Go-1.22-blue)](https://go.dev/)
[![ARM32](https://img.shields.io/badge/Arch-ARMv7-red)](https://www.arm.com/)
[![Android](https://img.shields.io/badge/Platform-Android-brightgreen)](https://www.android.com/)
[![Kernel](https://img.shields.io/badge/Kernel-5.4.210-blueviolet)](https://kernel.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **STB-eBPF** 是 CloudFlow 平台的嵌入式探针，专为 Android 机顶盒 (STB, Set-Top Box) 设计的 eBPF 网络可观测采集器。已验证在 ARMv7 32 位、Linux 5.4.210 (无 BTF) 的 STB 上稳定运行。

---

## 项目定位

```
CloudFlow 探针体系
├── cloud-flow-agent          # x86_64 通用探针 (通用Linux服务器)
├── ebpf-probe                # 通用 eBPF 探针开发库
└── STB-eBPF                  # ARM32 机顶盒专用探针 ← 本仓库
    ├── 交叉编译: x86_64 → ARMv7
    ├── 无 BTF 环境兼容
    ├── Android /data 分区适配
    └── ADB 推送部署
```

---

## 已验证的部署环境

| 项目 | 要求 |
|------|------|
| **设备** | Android 机顶盒 (STB) |
| **架构** | ARMv7 32-bit (GOARM=7) |
| **内核** | Linux 5.4.210 |
| **BTF 支持** | 无 (需手写结构体偏移) |
| **权限** | root (su 0) |
| **ADB** | 端口 60001 |
| **数据分区** | /data (读写，约 14%~20% 使用率) |
| **内存** | ≥256MB |
| **存储** | /data 分区空闲 ≥50MB |

---

## STB 内核约束与适配

| 约束 | 影响 | 适配方案 |
|------|------|----------|
| **无 BTF** | 标准 libbpf 无法解析内核结构体 | 基于内核 5.4.210 源码提取结构体偏移量，手写 `struct pt_regs` 定义，使用原始 SEC() 模式 |
| **无 RINGBUF** | 不能使用 BPF_MAP_TYPE_RINGBUF | 全部改用 BPF_MAP_TYPE_PERF_EVENT_ARRAY |
| **无 frame pointer** | 调用栈回溯受限 | 仅采样 PID+时间戳，不做栈回溯 |
| **Tracepoint 权限** | 部分 tracepoint 需额外权限 | 用 kprobe 替代 tracepoint |
| **根分区只读** | `df /` 总是 100% (dm-verity) | 采集 `/data` 分区指标而非根分区 |

---

## 仓库结构

```
STB-eBPF/
├── cmd/probe/               # Go 探针主入口
├── internal/                # 内部包
│   ├── collector/           # 采集器管理
│   │   └── metrics.go       # 主机指标采集 (CPU/MEM/DISK)
│   └── ...
├── bpf/                     # BPF C 程序源文件
│   ├── network_flow.bpf.c   # 网络流采集 (AF_PACKET)
│   ├── tcp_connect.bpf.c    # TCP 连接跟踪 (kprobe)
│   ├── file_open.bpf.c      # 文件 I/O 监控 (kprobe)
│   ├── process_exec.bpf.c   # 进程执行跟踪 (kprobe)
│   ├── on_cpu.bpf.c         # On-CPU 采样 (perf_event)
│   ├── syscall.bpf.c        # 系统调用追踪 (kprobe)
│   └── tcp_retransmit.bpf.c # TCP 重传检测 (kprobe)
├── config/                  # 配置文件
│   ├── config.yaml          # 标准配置模板
│   └── collector.yaml       # 采集器开关配置
├── scripts/                 # 部署脚本
│   └── deploy_stb.sh        # STB ADB 一键部署
├── build/                   # 编译产物输出
├── docs/                    # 文档
├── deploy/                  # 部署资源
├── Makefile                 # 交叉编译
├── go.mod / go.sum          # Go 依赖
└── version.go               # 版本声明
```

---

## 已验证的 eBPF 能力矩阵

| 采集器 | 挂载方式 | 5分钟事件量 | 验证状态 |
|--------|----------|-------------|----------|
| 网络流 | AF_PACKET socket filter | 2,505 | ✅ 通过 |
| TCP 连接跟踪 | kprobe/tcp_connect | 20 | ✅ 通过 |
| 文件 I/O close | kprobe/__arm64_sys_close | 291 | ✅ 通过 |
| 文件 I/O open | kprobe/do_filp_open | 29 | ✅ 通过 |
| 进程执行 | kprobe/do_execve | - | ⚠️ 已附加，数据待验证 |
| On-CPU 采样 | perf_event 99Hz | 304 | ✅ 通过 |
| TCP 重传 | kprobe/tcp_retransmit_skb | 0 (稳定网络) | ✅ 已附加 |
| Off-CPU | kprobe/__schedule | - | ❌ 符号未导出 |

---

## 资源开销（STB 实测）

| 指标 | 值 |
|------|-----|
| CPU 占用 (常规) | **2%~5%** |
| CPU 占用 (峰值) | **≤6.5%** |
| 内存 (常驻) | **38MB** |
| 内存 (峰值) | **43MB** |
| 单小时带宽 | **≤80MB/h** |
| 连续运行 | **72h+ 无崩溃** |

---

## 数据采集验证

### 原始数据样本（ClickHouse 查询示例）

```sql
-- 5分钟事件分布
SELECT category, event_type, count() as cnt
FROM cloudflow.ebpf_events
WHERE timestamp >= now() - INTERVAL 5 MINUTE
GROUP BY category, event_type ORDER BY cnt DESC;

-- 结果:
-- network|flow|2505
-- syscall|close|291
-- performance|on_cpu_sample|304
-- protocol|flow|686
-- protocol|http|164
-- security|tcp_connect|20
-- syscall|open|29
-- metrics|host_metrics|16
```

### 数据准确性验证

| 验证项 | 方法 | 结果 |
|--------|------|------|
| 网络五元组 | 对比 tcpdump 抓包 | ✅ 一致 |
| TCP 连接事件 | 对比 /proc/net/tcp | ✅ 匹配 |
| 文件操作 | 对比 strace 跟踪 | ✅ 匹配 |
| On-CPU 采样 | 对比 top 采样 | ✅ PID 分布一致 |
| 事件时间戳 | 检查单调递增 | ✅ 正确 |
| 数据完整性 | Redis 去重+ClickHouse 校验 | ✅ 无丢失 |

---

## 快速开始

### 交叉编译（在 x86_64 开发机上）

```bash
# 前置要求: Go 1.22+, Clang 12+ (bpf), arm-linux-gnueabihf-
# Android NDK 工具链 (推荐 NDK r25+)

# 编译 Go 探针 (ARM32)
export GOWORK=off
export GOPROXY=https://goproxy.cn,direct
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=arm
export GOARM=7
go build -o build/stb-ebpf-probe-v3 ./cmd/probe/

# 编译 BPF 程序 (ARM)
cd bpf
for f in network_flow tcp_connect syscall file_open process_exec on_cpu tcp_retransmit; do
    clang -O2 -g -target bpf -D__TARGET_ARCH_arm -D__BPF_TRACING__ \
        -I../include -I/usr/include/bpf \
        -c ${f}.bpf.c -o ${f}.bpf.o
done

# 或使用 Makefile 一键编译
make stb-all
```

### ADB 部署到 STB

```bash
# 1. ADB 连接
adb connect <STB_IP>:60001

# 2. 推送探针和 BPF 程序
adb push build/stb-ebpf-probe-v3 /data/local/tmp/cloudflow/ebpf-probe/
adb push bpf/*.bpf.o /data/local/tmp/cloudflow/ebpf-probe/
adb push config/config.yaml /data/local/tmp/cloudflow/ebpf-probe/

# 3. 启动探针 (root)
adb shell "su 0 env \
  EDGE_ADDR=<VM_IP>:8081 \
  CLICKHOUSE_ADDR=<VM_IP> \
  /data/local/tmp/cloudflow/ebpf-probe/stb-ebpf-probe-v3 &"

# 4. 验证运行
adb shell "su 0 ps -ef | grep ebpf"
```

### 环境变量说明

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `EDGE_ADDR` | 数据上报地址 | `localhost:9102` |
| `CLICKHOUSE_ADDR` | ClickHouse 地址 | `localhost:8123` |
| `PROBE_ID` | 探针标识 | `hostname` |
| `INTERFACE` | 网络接口 | `eth0` |
| `LOG_LEVEL` | 日志级别 | `info` |

### 容错机制

- **看门狗保活**: 每 5 分钟检查进程状态，异常自动重启
- **本地缓存**: 断网时事件缓存至本地文件，恢复后补传
- **指数退避**: 上报失败时自动退避重试 (1s, 2s, 4s, 8s...)
- **资源限制**: `nice -n 19` + `ulimit -v 102400` (虚拟内存上限 100MB)
- **SELinux**: `setenforce 0` 放宽限制，`ulimit -l unlimited` 解锁 eBPF 锁内存

---

## 数据链路

```
STB (10.115.70.28)
│
├─ eBPF 采集器 (内核态 AF_PACKET/kprobe)
│   └─→ 用户态探针
│       └─→ HTTP POST /api/v1/ingest
│           └─→ Edge data-ingest (:9104)
│               ├─→ Redis 队列 (缓冲+去重)
│               └─→ ClickHouse (cloudflow.ebpf_events)
│                    └─→ 前端可视化 (:8080)
│
└─ host_metrics (每30秒 /proc 轮询)
    └─→ 同上数据管道
```

---

## 架构兼容性

| 能力 | 最低内核 | STB 5.4.210 |
|------|---------|-------------|
| eBPF | 4.15 | ✅ |
| Kprobe | 4.1 | ✅ |
| Tracepoint | 4.7 | ✅ (部分) |
| TC (cls_bpf) | 4.1 | ✅ |
| Perf Event | 4.15 | ✅ |
| BTF/CO-RE | 5.8 | ❌ (手写偏移) |
| Ring Buffer | 5.8 | ❌ (改用 Perf Array) |

---

## 相关仓库

| 仓库 | 说明 |
|------|------|
| [cloudflow](https://github.com/meinanzilinzhengying/cloudflow) | CloudFlow 完整平台（后端+前端+微服务） |
| [STB-eBPF](https://github.com/meinanzilinzhengying/STB-eBPF) | **本仓库 - STB 机顶盒专用探针** |

---

## 开发规划

### 短期 (1-3 月)

- P0: 进程执行跟踪数据验证
- P0: TCP 重传事件模拟验证
- P1: uprobes 用户态追踪 (TLS 握手解析)
- P1: 动态采样策略 (高峰期自动降级)

### 中期 (3-6 月)

- P1: AArch64 64 位机顶盒适配
- P2: HTTP/2 协议解析
- P2: 终端异常流量识别 (轻量 IDS)

### 长期 (6-12 月)

- P2: gRPC/RTSP 内核态协议解析
- P3: 跨版本内核自动适配 (4.15~6.x)

---

## 许可证

MIT © 2026 CloudFlow Team
