# 开发指南

> 版本: v3.1.0

---

## 环境搭建

### 必需工具

| 工具 | 版本 | 用途 |
|------|------|------|
| Go | 1.22+ | 用户态程序编译 |
| Clang/LLVM | 12+ | eBPF 字节码编译 |
| bpftool | 5.8+ | BTF 生成和程序加载 |
| Linux 内核 | 4.15+ | 运行环境（5.8+ 推荐） |
| make | 任意 | 构建编排 |
| git | 任意 | 版本控制 |

### 安装步骤 (CentOS/RHEL)

```bash
# 1. 安装 Go
curl -L https://go.dev/dl/go1.24.1.linux-amd64.tar.gz | sudo tar -C /usr/local -xzf -
export PATH=$PATH:/usr/local/go/bin

# 2. 安装 Clang
dnf install -y clang llvm llvm-devel

# 3. 安装 bpftool
dnf install -y bpftool

# 4. 安装内核头文件（非 BTF 环境需要）
dnf install -y kernel-headers kernel-devel

# 5. 验证
clang --version
bpftool --version
go version
```

### 安装步骤 (Ubuntu/Debian)

```bash
apt-get update
apt-get install -y clang llvm libbpf-dev bpftool linux-headers-$(uname -r)
```

---

## 项目结构

```
ebpf-probe/
├── bpf/                  # eBPF 内核程序
│   ├── common.h          # 共享事件结构体
│   ├── network_flow.bpf.c
│   ├── process_exec.bpf.c
│   └── ...
├── cmd/probe/            # 主程序入口
│   └── main.go
├── internal/             # 内部实现
│   ├── api/              # HTTP API 服务
│   ├── collector/        # 采集器管理器 + 13 个采集器
│   ├── kernel/           # 内核能力探测
│   └── output/           # 输出后端 (ClickHouse/TiDB/...)
├── pkg/                  # 可复用包
│   ├── protocol/         # L7 协议解析 (HTTP/DNS/DB)
│   ├── perf/             # 性能分析 (CPU/IO/Mem)
│   └── platform/         # 平台检测
├── config/               # 配置文件示例
├── deploy/               # 部署脚本
│   ├── docker/
│   ├── systemd/
│   └── install/
├── docs/                 # 文档
├── scripts/              # 工具脚本
└── Makefile
```

---

## 新增采集器指南

### 步骤 1: 创建 BPF 程序

在 `bpf/` 目录创建 `{name}_trace.bpf.c`:

```c
#include "common.h"
#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("kprobe/target_function")
int BPF_KPROBE(target_function, struct param *p) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) return 0;
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_YOUR_TYPE;  // 在 common.h 添加
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // ... 填充数据
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 步骤 2: 在 common.h 添加事件类型

```c
enum event_type {
    // ... 现有类型
    EVENT_TYPE_YOUR_TYPE = 21,  // 新增
};
```

### 步骤 3: 创建 Go 采集器

在 `internal/collector/` 创建 `{name}_trace.go`:

```go
package collector

type YourTraceCollector struct {
    output  Output
    probeID string
}

func NewYourTraceCollector(output Output, probeID string) *YourTraceCollector {
    return &YourTraceCollector{output: output, probeID: probeID}
}

func (c *YourTraceCollector) Name() string { return "your_trace" }
func (c *YourTraceCollector) Description() string { return "Your trace collector" }

func (c *YourTraceCollector) Load() (*ebpf.CollectionSpec, error) {
    return loadYourTrace()
}

func (c *YourTraceCollector) Attach(coll *ebpf.Collection) ([]link.Link, error) {
    // 挂载 kprobe/tracepoint/LSM
}

func (c *YourTraceCollector) ProcessEvent(data []byte) error {
    // 解析事件并输出
}
```

### 步骤 4: 在 Makefile 添加编译规则

```makefile
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/your_trace.bpf.c -o bpf/your_trace.bpf.o -I bpf
```

### 步骤 5: 在 manager.go 注册

```go
func (m *Manager) Init(cap kernel.Capabilities) error {
    if m.config.YourTrace && cap.HasKprobe {
        m.collectors = append(m.collectors, NewYourTraceCollector(m.output, m.probeID))
    }
    // ...
}
```

### 步骤 6: 测试

```bash
make bpf
make build
sudo ./cloudflow-ebpf-probe --enable your_trace --run-once 10s
```

---

## 调试技巧

### 1. 查看 BPF 验证器日志

```bash
# 加载失败时，内核会输出验证器日志到 trace_pipe
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 使用 bpftool 查看加载的程序
sudo bpftool prog list
sudo bpftool prog show id <ID>
```

### 2. 使用 bpftrace 快速验证钩子

```bash
# 验证 kprobe 是否可用
sudo bpftrace -e 'kprobe:tcp_sendmsg { @[comm] = count(); }'

# 验证 tracepoint 是否可用
sudo bpftrace -e 'tracepoint:sched:sched_switch { @[comm] = count(); }'
```

### 3. Go 调试

```bash
# 使用 delve 调试
sudo dlv exec ./cloudflow-ebpf-probe -- --config config.yaml

# 打印所有 BPF 加载详情
sudo ./cloudflow-ebpf-probe --log-level debug --enable all
```

### 4. Ring Buffer 监控

```bash
# 查看 Ring Buffer 使用情况
sudo bpftool map show

# 查看 map 内容
sudo bpftool map dump name rb
```

### 5. 内核 BTF 检查

```bash
# 查看 BTF 信息
bpftool btf dump file /sys/kernel/btf/vmlinux | head -50

# 查看特定类型的 BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A 20 "struct task_struct"
```

---

## 代码规范

### BPF 代码规范

1. 所有内存访问使用 `BPF_CORE_READ` 宏
2. 禁止使用循环（或确保循环有界）
3. Ring Buffer 预留失败时立即返回
4. 字符串复制使用 `bpf_probe_read_kernel_str`
5. 避免在内核态做复杂计算和字符串解析

### Go 代码规范

1. 错误处理：所有错误必须返回或记录，禁止忽略
2. 日志级别：debug 仅用于开发，info 用于正常运行，warn 用于降级，error 用于可恢复失败
3. 采集器隔离：单个采集器失败不影响其他采集器
4. 资源清理：信号处理时正确卸载 BPF 程序

---

## 测试

```bash
# 单元测试
go test ./pkg/protocol/...
go test ./pkg/perf/...

# 集成测试（需要 root）
sudo go test ./internal/collector/...

# 完整测试
make test

# 性能测试
make bench
```

---

## 提交规范

```
feat: 新增 HTTP 协议解析器
fix: 修复 DNS 压缩指针解析错误
docs: 更新性能基准报告
refactor: 重构采集器管理器
perf: 优化 Ring Buffer 批处理
test: 添加 MySQL 协议解析测试
chore: 更新 Makefile 依赖
```
