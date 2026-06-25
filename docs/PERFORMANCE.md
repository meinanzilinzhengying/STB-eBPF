# eBPF Probe 性能基准报告

> 版本: v3.1.0  
> 日期: 2025-06-18  
> 状态: 基于架构设计的预期值，实测数据将在 CI/CD 中补充

---

## 测试环境

| 项 | 配置 |
|----|------|
| CPU | 8 vCPU (AMD EPYC 7B13) |
| 内存 | 16 GB |
| 内核 | 5.14.0-710.el9.x86_64 (CentOS Stream 9) |
| BTF | 支持 |
| Ring Buffer | 1 MB/采集器 |
| Go 版本 | 1.24.1 |
| 编译器 | Clang 22.1.3 |

---

## 1. 配置组合开销矩阵

以下数据为 **idle 状态**（无业务流量）下的预期资源开销。实际负载下的开销见第 2 节。

| 测试场景 | 启用采集器 | 预期 CPU | 预期内存 | 说明 |
|---------|-----------|---------|---------|------|
| **最小配置** | network_flow + tcp_connect | < 0.5% | < 20 MB | 仅网络基础追踪，无 L7 |
| **基础配置** | + process_exec + file_open | < 0.8% | < 30 MB | 增加进程/文件生命周期 |
| **标准配置** | + syscall | < 1.2% | < 40 MB | 增加系统调用频率统计 |
| **L7 增强** | + http_trace + dns_trace | < 2.0% | < 50 MB | 增加 HTTP/DNS 协议解析 |
| **性能追踪** | + sched_trace + block_trace | < 2.5% | < 60 MB | 增加 CPU/磁盘 性能分析 |
| **全功能** | 全部 12 个采集器 + host_metrics | < 3.5% | < 80 MB | 全量开启，最大覆盖 |
| **机顶盒** | network_flow + tcp_connect + process_exec | < 0.5% | < 15 MB | ARM32 精简版，默认关闭 L7 |

---

## 2. 不同负载下的开销变化

### 2.1 网络流量 (QPS) 对 network_flow 的影响

| QPS | CPU 开销 | 内存增长 | 说明 |
|-----|---------|---------|------|
| 0 (idle) | 0.2% | 基准 | 无流量时仅 map 轮询 |
| 1K | 0.5% | +2 MB | 低频率事件，Ring Buffer 无压力 |
| 10K | 1.2% | +5 MB | 中等频率，用户态解析启动 |
| 50K | 2.5% | +10 MB | 高频事件，需关注 Ring Buffer 溢出 |
| 100K+ | 3.5% | +15 MB | 建议开启采样或分流 |

### 2.2 HTTP 请求量对 http_trace 的影响

| 请求/秒 | CPU 开销 | 内存增长 | 说明 |
|---------|---------|---------|------|
| 0 | 0.3% | 基准 | 仅 kprobe 挂载开销 |
| 100 | 0.8% | +3 MB | 请求解析活跃 |
| 1K | 1.5% | +8 MB | 匹配器窗口内请求堆积 |
| 5K | 2.8% | +15 MB | 建议缩短匹配窗口或降低采样率 |

### 2.3 DNS 查询量对 dns_trace 的影响

| 查询/秒 | CPU 开销 | 内存增长 | 说明 |
|---------|---------|---------|------|
| 0 | 0.2% | 基准 | 仅 kprobe 挂载开销 |
| 100 | 0.6% | +2 MB | 查询解析活跃 |
| 1K | 1.2% | +5 MB | 匹配器正常处理 |
| 5K | 2.2% | +10 MB | 高频率，需关注超时清理 |

---

## 3. 采集器级别单独开销

| 采集器 | 内核钩子 | 预期 CPU(idle) | 预期内存 | 主要开销来源 |
|--------|---------|---------------|---------|-------------|
| network_flow | TC cls_bpf | 0.1% | 5 MB | 每包 map 更新 |
| tcp_connect | kprobe | 0.1% | 3 MB | 连接事件低频 |
| process_exec | tracepoint | 0.1% | 3 MB | 进程生命周期事件 |
| file_open | kprobe | 0.2% | 4 MB | 文件访问高频 |
| syscall_trace | tracepoint | 0.3% | 5 MB | 系统调用高频 |
| http_trace | kprobe × 2 | 0.3% | 6 MB | 请求-响应匹配器 |
| dns_trace | kprobe × 2 | 0.2% | 5 MB | 查询-响应匹配器 |
| db_trace | kprobe × 2 | 0.2% | 5 MB | MySQL/Redis 解析 |
| sched_trace | tracepoint × 2 | 0.3% | 6 MB | CPU 调度事件高频 |
| mem_trace | kprobe × 2 | 0.3% | 5 MB | 内存分配高频 |
| block_trace | tracepoint × 2 | 0.2% | 5 MB | IO 完成事件 |
| security_trace | LSM/kprobe | 0.2% | 4 MB | 安全审计事件低频 |
| host_metrics | procfs | 0.1% | 2 MB | 定时读取 /proc |

---

## 4. 性能优化建议

### 4.1 配置优化

1. **按需启用**：生产环境只启用需要的采集器，禁止全功能开启
2. **采样控制**：高流量场景开启事件采样（如每 10 个包采集 1 个）
3. **匹配窗口**：HTTP/DNS 请求-响应匹配窗口默认 30s，高并发场景缩短至 10s
4. **Ring Buffer 大小**：机顶盒/嵌入式环境缩小至 256 KB

### 4.2 内核优化

1. **启用 BPF JIT**：确保 `/proc/sys/net/core/bpf_jit_enable = 1`
2. **增大 JIT 编译器限制**：`/proc/sys/net/core/bpf_jit_kallsyms = 1`
3. **调整 Ring Buffer 大小**：根据内存预算调整 `max_entries`

### 4.3 运行时优化

1. **CPU 过载保护**：当 CPU > 70% 时自动降低采样率（待实现）
2. **内存上限保护**：当内存 > 50 MB 时自动重启（待实现）
3. **事件批处理**：用户态批量读取 Ring Buffer，减少系统调用次数

---

## 5. 测试方法

### 5.1 手动测试

```bash
# 1. 最小配置测试
sudo ./cloudflow-ebpf-probe --config config/minimal.yaml &
PID=$!
sleep 30
ps -p $PID -o %cpu,%mem,rss,vsz
kill $PID

# 2. 全功能测试
sudo ./cloudflow-ebpf-probe --config config/full.yaml &
PID=$!
sleep 30
ps -p $PID -o %cpu,%mem,rss,vsz
kill $PID

# 3. 压力测试 (配合 wrk/ab)
wrk -t4 -c100 -d30s http://localhost:8080/ &
sudo ./cloudflow-ebpf-probe --enable http_trace &
PID=$!
sleep 30
ps -p $PID -o %cpu,%mem,rss,vsz
kill $PID
```

### 5.2 自动化测试

```bash
make test        # 单元测试
make bench       # 基准测试（待实现）
make perf-test   # 集成性能测试（待实现）
```

---

## 6. 已知瓶颈与上限

| 瓶颈 | 上限 | 说明 |
|------|------|------|
| Ring Buffer 溢出 | 取决于 max_entries | 高频事件下可能丢包 |
| 用户态解析延迟 | 1-5 ms | HTTP/DNS 匹配窗口内处理 |
| Go GC 停顿 | 1-3 ms | 内存增长时触发 |
| 内核验证器时间 | 1-10 s | 复杂 BPF 程序加载时间 |
| 单核 CPU 上限 | 100% | 单采集器事件处理线程 |

---

## 7. 版本对比

| 版本 | 全功能 CPU | 全功能内存 | 最小配置 CPU | 最小配置内存 |
|------|-----------|-----------|-------------|-------------|
| v3.0.0 | 2.5% | 60 MB | 0.5% | 20 MB |
| v3.1.0 | 3.5% | 80 MB | 0.5% | 20 MB |
| 变化 | +40% | +33% | 0% | 0% | 新增 7 个采集器 |

---

*报告由架构设计推导，实测数据将通过 GitHub Actions 自动化测试补充。*
