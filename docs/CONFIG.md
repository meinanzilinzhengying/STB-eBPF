# 配置指南

> 版本: v3.1.0

---

## 配置文件位置

优先级（从高到低）：

1. 命令行参数: `-config /path/to/config.yaml`
2. 环境变量: `EBPF_PROBE_CONFIG=/path/to/config.yaml`
3. 默认路径: `/etc/ebpf-probe/collector.yaml`
4. 当前目录: `./config/collector.yaml`

---

## 完整配置示例

```yaml
probe:
  id: "node-001"
  log_level: "info"          # debug | info | warn | error
  data_dir: "/var/lib/ebpf-probe"

collector:
  # 核心采集器
  network_flow: true
  tcp_connect: true
  process_exec: true
  file_open: true
  syscall: true

  # L7 协议解析
  http_trace: true
  dns_trace: true
  db_trace: true

  # 性能追踪
  sched_trace: true
  mem_trace: true
  block_trace: true

  # 安全审计
  security_trace: true

  # 主机指标
  host_metrics: true

output:
  type: "clickhouse"          # clickhouse | tidb | redis | stdout | grpc
  clickhouse:
    addr: "192.168.0.130:9000"
    database: "cloudflow"
    batch_size: 1000
    flush_interval: "5s"
  tidb:
    addr: "192.168.0.130:4000"
    database: "cloudflow"
    user: "root"
    password: ""

api:
  addr: ":8080"
  metrics_addr: ":9100"
  enable_pprof: false

# 性能保护
protection:
  max_cpu_percent: 70          # CPU 超限时降低采样率
  max_memory_mb: 50            # 内存超限时自动重启
  ring_buffer_size: "1MB"      # 单个 Ring Buffer 大小
```

---

## 配置项详解

### `probe`

| 项 | 类型 | 默认值 | 说明 |
|----|------|--------|------|
| id | string | 主机名 | 探针唯一标识 |
| log_level | string | info | 日志级别 |
| data_dir | string | /var/lib/ebpf-probe | 数据/缓存目录 |

### `collector`

每个采集器对应一个独立开关。如果内核不支持该采集器，会自动静默跳过。

| 采集器 | 默认 | 说明 |
|--------|------|------|
| network_flow | true | 网络流量统计 |
| tcp_connect | true | TCP 连接追踪 |
| process_exec | true | 进程生命周期 |
| file_open | true | 文件访问审计 |
| syscall | true | 系统调用频率 |
| http_trace | false | HTTP 协议解析 |
| dns_trace | false | DNS 协议解析 |
| db_trace | false | MySQL/Redis 协议解析 |
| sched_trace | false | CPU 调度追踪 |
| mem_trace | false | 内存分配追踪 |
| block_trace | false | 磁盘 IO 追踪 |
| security_trace | false | 安全审计 |
| host_metrics | true | 主机指标 |

### `output`

| 项 | 类型 | 默认值 | 说明 |
|----|------|--------|------|
| type | string | clickhouse | 输出后端类型 |
| batch_size | int | 1000 | 批量写入大小 |
| flush_interval | duration | 5s | 强制刷新间隔 |

### `protection`

| 项 | 类型 | 默认值 | 说明 |
|----|------|--------|------|
| max_cpu_percent | int | 70 | CPU 超限时自动降采样 |
| max_memory_mb | int | 50 | 内存超限时自动重启 |
| ring_buffer_size | string | 1MB | Ring Buffer 大小 |

---

## 环境变量覆盖

所有配置项都可以通过环境变量覆盖，格式：`EBPF_PROBE_<SECTION>_<KEY>`

```bash
# 示例
export EBPF_PROBE_COLLECTOR_HTTP_TRACE=1
export EBPF_PROBE_COLLECTOR_SECURITY_TRACE=0
export EBPF_PROBE_OUTPUT_CLICKHOUSE_ADDR="192.168.0.130:9000"
export EBPF_PROBE_PROTECTION_MAX_CPU_PERCENT=80
sudo -E cloudflow-ebpf-probe
```

---

## 配置模板

### 最小配置（嵌入式/机顶盒）

```yaml
collector:
  network_flow: true
  tcp_connect: true
  process_exec: true
  host_metrics: true
protection:
  max_cpu_percent: 50
  max_memory_mb: 15
  ring_buffer_size: "256KB"
```

### 生产标准配置

```yaml
collector:
  network_flow: true
  tcp_connect: true
  process_exec: true
  file_open: true
  syscall: true
  http_trace: true
  dns_trace: true
  host_metrics: true
output:
  type: "clickhouse"
  clickhouse:
    addr: "192.168.0.130:9000"
```

### 全功能调试配置

```yaml
probe:
  log_level: "debug"
collector:
  network_flow: true
  tcp_connect: true
  process_exec: true
  file_open: true
  syscall: true
  http_trace: true
  dns_trace: true
  db_trace: true
  sched_trace: true
  mem_trace: true
  block_trace: true
  security_trace: true
  host_metrics: true
output:
  type: "stdout"
```
