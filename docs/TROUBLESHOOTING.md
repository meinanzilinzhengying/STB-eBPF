# 排障指南

> 版本: v3.1.0

---

## 常见问题速查

### Q1: 探针启动时报 "operation not permitted"

**原因**: 缺少 root 权限或 CAP_BPF/CAP_NET_ADMIN 能力。

**解决**:
```bash
# 方式1: 使用 root
sudo cloudflow-ebpf-probe

# 方式2: 赋予 capabilities（推荐）
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin,cap_sys_ptrace,cap_perfmon+ep ./cloudflow-ebpf-probe
./cloudflow-ebpf-probe

# 方式3: 以 unprivileged 模式运行（仅部分采集器支持）
# 需要内核 >= 5.8 且启用 unprivileged BPF
sudo sysctl kernel.unprivileged_bpf_disabled=0
```

---

### Q2: 内核版本过低 (< 4.15)

**原因**: eBPF 需要内核 4.15+ 才具备基本支持。

**解决**:
- 升级内核至 4.15+（推荐 5.8+ 以获得 BTF/CO-RE 支持）
- 或改用 BCC 方案（Python 依赖，体积更大）

---

### Q3: BTF 不可用，CO-RE 编译失败

**现象**:
```
Error: failed to load BPF program: BTF is required for CO-RE
```

**解决**:
```bash
# 检查 BTF
ls /sys/kernel/btf/vmlinux

# 如果没有 BTF，需要编译内核时启用 CONFIG_DEBUG_INFO_BTF
# 或安装内核 BTF 包
sudo dnf install kernel-debuginfo  # CentOS/RHEL
sudo apt install linux-image-$(uname -r)-dbgsym  # Ubuntu

#  fallback: 使用 BCC 编译模式（非 CO-RE，需要内核头文件）
```

---

### Q4: 采集器加载失败但不影响其他采集器

**现象**: 日志中显示某个采集器失败，但探针继续运行。

**原因**: 这是设计行为。单个采集器失败不会导致探针退出。

**排查**:
```bash
# 查看具体失败原因
sudo cloudflow-ebpf-probe --enable http_trace --run-once 10s -v

# 检查内核是否支持该功能
sudo cloudflow-ebpf-probe --check-capabilities
```

---

### Q5: Ring Buffer 溢出，事件丢失

**现象**:
```
Warn: ring buffer overflow, dropped 1234 events
```

**原因**: 事件频率超过用户态消费速度。

**解决**:
```yaml
# 1. 增大 Ring Buffer
protection:
  ring_buffer_size: "4MB"

# 2. 降低事件频率（启用采样）
# 在 BPF 代码中设置采样率（如每 100 个事件取 1 个）

# 3. 关闭高开销采集器
collector:
  syscall_trace: false
  sched_trace: false
```

---

### Q6: ClickHouse/TiDB 数据写入失败

**现象**: 探针运行正常但目标数据库无数据。

**排查**:
```bash
# 1. 检查网络连通性
curl -v telnet://192.168.0.130:9000

# 2. 检查数据库权限
clickhouse-client -h 192.168.0.130 --query "SELECT 1"

# 3. 使用 stdout 输出调试
sudo cloudflow-ebpf-probe --output stdout

# 4. 检查表结构是否存在
curl "http://192.168.0.130:8123/?query=SHOW+TABLES+FROM+cloudflow"
```

---

### Q7: CPU/内存占用过高

**排查**:
```bash
# 查看实时资源
ps -p $(pgrep cloudflow-ebpf-probe) -o pid,%cpu,%mem,vsz,rss,comm -f

# 查看各采集器事件数量
sudo cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | head -50
```

**解决**:
```yaml
# 关闭高开销采集器
collector:
  http_trace: false
  dns_trace: false
  db_trace: false
  sched_trace: false
  mem_trace: false
  block_trace: false
  security_trace: false

# 启用资源保护
protection:
  max_cpu_percent: 50
  max_memory_mb: 30
```

---

### Q8: ARM32 机顶盒无法运行

**现象**: 二进制无法执行或段错误。

**排查**:
```bash
# 检查架构
uname -m   # 应为 armv7l
file ./cloudflow-ebpf-probe-arm32   # 应为 ELF 32-bit LSB executable, ARM

# 检查依赖
ldd ./cloudflow-ebpf-probe-arm32   # 应为 statically linked (无依赖)

# 检查 BTF
ls /sys/kernel/btf/vmlinux
```

**解决**:
- 确认使用 `cloudflow-ebpf-probe-arm32` 版本
- 确认内核 >= 4.15
- 确认内存 >= 15 MB 可用
- 使用最小配置：`--config config/minimal.yaml`

---

### Q9: 日志级别调整

```bash
# 命令行
sudo cloudflow-ebpf-probe --log-level debug

# 配置文件
probe:
  log_level: "debug"

# 环境变量
export EBPF_PROBE_PROBE_LOG_LEVEL=debug
```

---

## 内核版本问题矩阵

| 内核版本 | 已知问题 | 解决方式 |
|---------|---------|---------|
| 4.15 - 4.17 | 无 BTF, 需要 BCC 头文件 | 安装 kernel-headers |
| 4.18 - 5.3 | 无 BTF, 但支持 CO-RE 重定位 | 安装 kernel-headers |
| 5.4 - 5.7 | BTF 可能不完整 | 安装 kernel-debuginfo |
| 5.8+ | 完整支持 | 无需额外操作 |
| 5.11+ | 支持 Ring Buffer | 推荐版本 |
| 5.13+ | 支持 LSM | 安全审计可用 |

---

## 获取支持

1. 查看日志: `sudo journalctl -u cloudflow-ebpf-probe -n 200`
2. 运行验证脚本: `sudo ./scripts/verify-kernel.sh`
3. 提交 Issue: https://github.com/meinanzilinzhengying/ebpf-probe/issues
