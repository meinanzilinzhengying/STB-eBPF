# 采集器参考手册

> 版本: v3.1.0  
> 共 13 个采集器，覆盖网络、进程、文件、系统调用、L7 协议、性能、安全、主机指标

---

## 1. 网络类

### 1.1 network_flow (TC/XDP)

| 属性 | 说明 |
|------|------|
| 钩子类型 | TC cls_bpf / XDP |
| 内核版本 | 4.1+ (TC), 4.8+ (XDP) |
| 事件类型 | `FLOW` |
| 采集字段 | 五元组、包数、字节数、协议 |
| 开销 | 0.1% CPU, 5 MB 内存 |
| 适用场景 | 网络流量监控、DDoS 检测、流量分析 |
| 注意事项 | 需要 CAP_NET_ADMIN 或 root |

### 1.2 tcp_connect (kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | kprobe: tcp_v4_connect, tcp_v6_connect |
| 内核版本 | 4.1+ |
| 事件类型 | `TCP_CONNECT` |
| 采集字段 | 四元组、连接状态、进程信息 |
| 开销 | 0.1% CPU, 3 MB 内存 |
| 适用场景 | 连接追踪、异常连接检测、端口扫描发现 |
| 注意事项 | 仅捕获连接建立，不跟踪数据传输 |

---

## 2. 进程/文件类

### 2.1 process_exec (tracepoint)

| 属性 | 说明 |
|------|------|
| 钩子类型 | tracepoint: sched_process_exec, sched_process_exit |
| 内核版本 | 4.7+ |
| 事件类型 | `EXEC` / `EXIT` |
| 采集字段 | PID, PPID, 命令行, 参数, 退出码 |
| 开销 | 0.1% CPU, 3 MB 内存 |
| 适用场景 | 进程生命周期监控、可疑命令检测 |
| 注意事项 | exec 事件可能高频，注意 Ring Buffer 大小 |

### 2.2 file_open (kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | kprobe: do_filp_open |
| 内核版本 | 4.1+ |
| 事件类型 | `FILE_OPEN` |
| 采集字段 | 文件名、进程、UID、标志 |
| 开销 | 0.2% CPU, 4 MB 内存 |
| 适用场景 | 文件访问审计、敏感文件监控 |
| 注意事项 | 文件访问可能非常频繁，建议按需启用 |

---

## 3. 系统调用类

### 3.1 syscall_trace (tracepoint)

| 属性 | 说明 |
|------|------|
| 钩子类型 | tracepoint: raw_syscalls:sys_enter |
| 内核版本 | 4.7+ |
| 事件类型 | `SYSCALL` |
| 采集字段 | 系统调用号、进程、频率统计 |
| 开销 | 0.3% CPU, 5 MB 内存 |
| 适用场景 | 系统调用行为分析、异常行为检测 |
| 注意事项 | 系统调用频率极高，需关注性能影响 |

---

## 4. L7 协议类

### 4.1 http_trace (kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | kprobe: tcp_sendmsg, tcp_recvmsg |
| 内核版本 | 4.1+ |
| 事件类型 | `HTTP` |
| 采集字段 | 方法、URL、Host、状态码、延迟 |
| 开销 | 0.3% CPU, 6 MB 内存 |
| 适用场景 | HTTP 性能分析、错误率监控、API 追踪 |
| 注意事项 | 内核态仅复制 payload，解析在用户态完成 |

### 4.2 dns_trace (kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | kprobe: udp_sendmsg, udp_recvmsg (port 53) |
| 内核版本 | 4.1+ |
| 事件类型 | `DNS` |
| 采集字段 | 查询域名、记录类型、响应码、应答 |
| 开销 | 0.2% CPU, 5 MB 内存 |
| 适用场景 | DNS 故障排查、DGA 检测、DNS 隧道发现 |
| 注意事项 | 支持 UDP 53 端口，TCP DNS 需要额外配置 |

### 4.3 db_trace (kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | kprobe: tcp_sendmsg, tcp_recvmsg (port 3306, 6379) |
| 内核版本 | 4.1+ |
| 事件类型 | `DB` |
| 采集字段 | SQL 语句、命令类型、影响行数、错误码 |
| 开销 | 0.2% CPU, 5 MB 内存 |
| 适用场景 | 慢查询定位、危险操作检测、数据库审计 |
| 注意事项 | 支持 MySQL (3306) 和 Redis (6379)，其他端口可配置 |

---

## 5. 性能类

### 5.1 sched_trace (tracepoint)

| 属性 | 说明 |
|------|------|
| 钩子类型 | tracepoint: sched_switch, sched_wakeup |
| 内核版本 | 4.7+ |
| 事件类型 | `SCHED_SWITCH` / `SCHED_WAKEUP` |
| 采集字段 | 进程切换、运行时间、等待时间、状态 |
| 开销 | 0.3% CPU, 6 MB 内存 |
| 适用场景 | CPU 调度分析、高 CPU 进程定位、调度延迟 |
| 注意事项 | 调度事件极频繁，建议高负载时关闭 |

### 5.2 mem_trace (kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | kprobe: __kmalloc, kfree |
| 内核版本 | 4.1+ |
| 事件类型 | `KMALLOC` / `KFREE` |
| 采集字段 | 分配大小、调用栈、分配/释放频率 |
| 开销 | 0.3% CPU, 5 MB 内存 |
| 适用场景 | 内存泄漏分析、高频分配检测 |
| 注意事项 | 内存分配事件极频繁，注意性能影响 |

### 5.3 block_trace (tracepoint)

| 属性 | 说明 |
|------|------|
| 钩子类型 | tracepoint: block_rq_issue, block_rq_complete |
| 内核版本 | 4.7+ |
| 事件类型 | `BLOCK_ISSUE` / `BLOCK_COMPLETE` |
| 采集字段 | IO 延迟、设备、扇区、大小 |
| 开销 | 0.2% CPU, 5 MB 内存 |
| 适用场景 | 磁盘瓶颈分析、IO 延迟分布 |
| 注意事项 | 块设备事件频率适中，适合长期开启 |

---

## 6. 安全类

### 6.1 security_trace (LSM/kprobe)

| 属性 | 说明 |
|------|------|
| 钩子类型 | LSM: security_file_open, cap_capable; kprobe: do_init_module |
| 内核版本 | 5.7+ (LSM), 4.1+ (kprobe fallback) |
| 事件类型 | `SECURITY_FILE_OPEN` / `CAP_CAPABLE` / `LOAD_MODULE` |
| 采集字段 | 权限请求、文件访问、模块加载 |
| 开销 | 0.2% CPU, 4 MB 内存 |
| 适用场景 | 安全审计、权限提升检测、模块加载监控 |
| 注意事项 | LSM 需要 5.7+ 内核，旧内核降级为 kprobe |

---

## 7. 主机指标

### 7.1 host_metrics (procfs)

| 属性 | 说明 |
|------|------|
| 采集方式 | 读取 /proc, /sys 文件系统 |
| 内核版本 | 任意 |
| 事件类型 | 周期性指标（非事件驱动） |
| 采集字段 | CPU、内存、磁盘、网络、负载 |
| 开销 | 0.1% CPU, 2 MB 内存 |
| 适用场景 | 主机资源监控、基线对比 |
| 注意事项 | 无内核依赖，任何环境均可开启 |

---

## 采集器选择决策树

```
需要网络流量监控?
  ├─ 是 → network_flow
  └─ 需要连接追踪? → tcp_connect

需要进程/文件审计?
  ├─ 是 → process_exec + file_open

需要系统调用分析?
  ├─ 是 → syscall_trace

需要应用层协议?
  ├─ HTTP → http_trace
  ├─ DNS → dns_trace
  └─ DB → db_trace

需要性能分析?
  ├─ CPU → sched_trace
  ├─ 内存 → mem_trace
  └─ IO → block_trace

需要安全审计?
  └─ 是 → security_trace

所有场景都需要?
  └─ host_metrics (默认开启)
```
