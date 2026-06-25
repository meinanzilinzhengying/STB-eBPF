# CloudFlow eBPF Probe v3.1.0

生产级、全场景、自适应内核的通用 eBPF 采集探针。支持 L7 协议解析、系统性能深度追踪、安全审计等高级能力。

---

## 核心架构

```
┌─────────────────────────────────────────────────────────────┐
│                        用户态 (Go)                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ API服务  │ │ 配置管理 │ │ 采集调度 │ │ 输出引擎 │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│       └─────────────┴──────────┴─────────────┘              │
│       ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│       │协议解析器│ │性能分析器│ │安全审计器│             │
│       │ HTTP/DNS│ │ CPU/IO/ │ │  LSM/   │             │
│       │ DB/MySQL│ │ Mem/Blk │ │ Cap/Mod │             │
│       └────┬─────┘ └────┬─────┘ └────┬─────┘             │
│            └─────────────┴──────────┘                      │
├─────────────────────────────────────────────────────────────┤
│                      Ring Buffer                            │
│                   (BPF_MAP_TYPE_RINGBUF)                    │
├─────────────────────────────────────────────────────────────┤
│                        内核态 (eBPF)                         │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │网络流  │ │进程    │ │文件    │ │TCP连接 │ │系统调用│   │
│  │TC/XDP  │ │Exec/  │ │Open   │ │Connect│ │SysEnter│   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │HTTP L7  │ │DNS L7   │ │CPU调度  │ │磁盘IO   │ │内存分配 │   │
│  │Kprobe   │ │Kprobe   │ │Tracept  │ │Block   │ │Kmem    │   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
│  ┌────────┐ ┌────────┐ ┌────────┐                        │
│  │安全审计 │ │数据库   │ │应用协议 │                        │
│  │LSM/Cap  │ │kprobe   │ │kprobe   │                        │
│  └────────┘ └────────┘ └────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 12 个 BPF 采集器

| 类别 | 采集器 | 钩子类型 | 事件类型 | 说明 |
|------|--------|----------|----------|------|
| 网络 | `network_flow` | TC/XDP | `FLOW` | 五元组流量统计 |
| 网络 | `tcp_connect` | kprobe | `TCP_CONNECT` | TCP 连接追踪 |
| 进程 | `process_exec` | tracepoint | `EXEC` / `EXIT` | 进程生命周期 |
| 文件 | `file_open` | kprobe | `FILE_OPEN` | 文件访问审计 |
| 系统调用 | `syscall_trace` | tracepoint | `SYSCALL` | 系统调用频率 |
| L7 协议 | `http_trace` | kprobe | `HTTP` | HTTP/1.1 请求解析 |
| L7 协议 | `dns_trace` | kprobe | `DNS` | DNS 查询解析 |
| L7 协议 | `db_trace` | kprobe | `DB` | MySQL/Redis 协议 |
| 性能 | `sched_trace` | tracepoint | `SCHED_*` | CPU 调度追踪 |
| 性能 | `block_trace` | tracepoint | `BLOCK_*` | 磁盘 IO 延迟 |
| 性能 | `mem_trace` | kprobe | `KMALLOC` / `KFREE` | 内存分配追踪 |
| 安全 | `security_trace` | LSM/kprobe | `CAP_*` / `SECURITY_*` | 安全审计 |

---

## 7 个用户态分析器

| 分析器 | 输入 | 输出 | 用途 |
|--------|------|------|------|
| `HTTP` | `event.data` 原始载荷 | 状态码、URI、方法、延迟 | 错误率、慢请求 |
| `DNS` | `event.data` 原始载荷 | 域名、记录类型、响应码 | DNS 故障排查 |
| `MySQL` | `event.data` 原始载荷 | 语句类型、表名、耗时 | 慢查询定位 |
| `Redis` | `event.data` 原始载荷 | 命令、Key 前缀、耗时 | 热点 Key 发现 |
| `CPU` | `SCHED_SWITCH` / `SCHED_WAKEUP` | `pid` 级 CPU 使用率 | 高 CPU 进程定位 |
| `Block` | `BLOCK_ISSUE` / `BLOCK_COMPLETE` | IO 延迟分布 | 磁盘瓶颈分析 |
| `Memory` | `KMALLOC` / `KFREE` | 分配频率、泄漏趋势 | 内存泄漏预警 |

---

## 配置化采集开关

通过 `config/collector.yaml` 或环境变量控制每个采集器的启用状态：

```yaml
collector:
  network_flow: true
  process_exec: true
  file_open: true
  tcp_connect: true
  syscall: true
  http_trace: true
  dns_trace: true
  db_trace: true
  sched_trace: true
  mem_trace: true
  block_trace: true
  security_trace: true
  host_metrics: true
```

**环境变量**（优先级高于配置文件）：
- `COLLECTOR_HTTP_TRACE=1` → 启用 HTTP 采集
- `COLLECTOR_SECURITY_TRACE=0` → 禁用安全审计

**自适应内核**：启动时自动探测 `BTF` / `TC` / `XDP` / `Kprobe` / `Tracepoint` / `LSM` 能力，不支持的功能自动静默跳过，无需手动配置。

---

## 快速开始

### 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/meinanzilinzhengying/ebpf-probe/main/deploy/install/install.sh | bash
```

### 手动编译

```bash
# 环境要求：Linux 4.15+，Clang 12+，Go 1.22+
make all        # 编译所有 BPF + Go 二进制
make bpf        # 仅编译 BPF 目标文件
make build      # 仅编译 Go 二进制
make install    # 安装到 /usr/local/bin/ebpf-probe
make test       # 运行测试
```

### 启动探针

```bash
# 默认配置（所有支持的采集器）
sudo ebpf-probe

# 指定配置文件
sudo ebpf-probe -config /etc/ebpf-probe/collector.yaml

# 仅网络+HTTP
COLLECTOR_HTTP_TRACE=1 COLLECTOR_DNS_TRACE=0 sudo -E ebpf-probe
```

---

## 数据流

```
┌─────────┐   Ring Buffer   ┌─────────────┐   gRPC/HTTP   ┌─────────────┐
│ eBPF    │ ──────────────→ │ Go 采集器   │ ────────────→ │ CloudFlow   │
│ 内核    │   高性能事件    │ 协议/性能   │   批量上报    │ 数据平台    │
│ 12 探针 │   通道          │ 解析/分析   │   聚合压缩    │ 130 节点    │
└─────────┘                 └─────────────┘               └─────────────┘
```

---

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| v3.1.0 | 2025-06 | 高级能力扩展：L7 协议、性能追踪、安全审计、配置开关 |
| v3.0.0 | 2025-06 | 基础采集：网络、进程、文件、TCP、系统调用、主机指标 |
| v2.0.0 | 2025-05 | 原型验证：TC 流量 + 简单日志 |
| v1.0.0 | 2025-04 | 预研：BTF/CO-RE 技术可行性 |

---

## 仓库

- **主仓库**: [github.com/meinanzilinzhengying/ebpf-probe](https://github.com/meinanzilinzhengying/ebpf-probe)
- **下游同步**: [github.com/meinanzilinzhengying/cloudflow/ebpf-probe](https://github.com/meinanzilinzhengying/cloudflow/ebpf-probe)

---

## 内核兼容性

| 能力 | 最低内核版本 | 探测方式 |
|------|-------------|----------|
| BTF / CO-RE | 5.8 | `/sys/kernel/btf/vmlinux` |
| Ring Buffer | 5.8 | `bpf_map_type` 枚举 |
| TC (cls_bpf) | 4.1 | `tc` 工具可用性 |
| XDP | 4.8 | `ip link` 支持 |
| LSM | 5.7 | `security` 子系统可用 |
| Tracepoint | 4.7 | `/sys/kernel/debug/tracing` |
| Kprobe | 4.1 | `kallsyms` 符号解析 |

---

## 许可证

MIT License © 2025 CloudFlow Team
