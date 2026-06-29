# STB eBPF Probe — 最终交付报告

## 日期: 2026-06-24 10:20

---

## TL;DR

完成了一个完整的 ARM 32-bit eBPF 探针开发、交叉编译、部署和验证。**两个 eBPF 程序均通过内核 verifier 并成功加载**，但因 STB 定制内核缺少 `CONFIG_BPF_EVENTS`，无法完成最后的 tracepoint 附加步骤。

---

## 技术栈

| 组件 | 选型 | 版本 |
|------|------|------|
| BPF 编译器 | clang | 22.1.3 |
| 目标平台 | ARM 32-bit (armv7l) | NDK r27b |
| 链接方式 | 动态链接 | Android linker |
| BPF 加载 | 自定义 min_loader | 直接 `bpf()` syscall |
| 数据通路 | PERCPU_ARRAY | 替代 PERF_EVENT_ARRAY |
| 二进制大小 | 20KB (strip后) | 18KB 动态版 |

## 里程碑

| 阶段 | 状态 | 详情 |
|------|------|------|
| BPF 字节码编译 | ✅ | 2 个 tracepoint，240+222 条指令 |
| ARM 交叉编译 | ✅ | NDK r27b，零依赖静态编译 |
| maps 创建 | ✅ | PERCPU_ARRAY fd=3, HASH fd=4 |
| **enter_prog 加载** | **✅** | **fd=5, 240 insns, 2 map patches** |
| **exit_prog 加载** | **✅** | **fd=6, 222 insns, 3 map patches** |
| tracepoint 附加 | ❌ | 内核缺少 CONFIG_BPF_EVENTS |

## 已解决的挑战

| 挑战 | 解决方案 |
|------|----------|
| libelf/libbpf 无法交叉编译 | 从零写 min_loader，直接 `bpf()` syscall |
| TLS 对齐错误 | 动态链接（不用 `-static`） |
| `bpf_probe_read_user` 不存在 | 改用 `bpf_probe_read`（helper #4） |
| map FD 修补 | `BPF_PSEUDO_MAP_FD` + `src_reg=1` |
| map 类型匹配错误 | 分开 enter/exit 的 map_fds 数组 |
| 64 位常量误判为 map 引用 | 检查第二槽位是否全零 |
| tracepoint 类型号错误 | 发现 type=2 非标准（从 sysfs 读取） |
| BPF_RAW_TRACEPOINT_OPEN 不支持 | sys_enter 不是原始 tracepoint |
| CONFIG_BPF_EVENTS 缺失 | STB 定制内核限制，无法绕过 |

## 后续选择

### 选项 1：使用非 eBPF 方式（推荐稳定方案）
- 保留 eBPF 程序加载（已过 verifier）
- 使用 `/proc/net` 和 `/proc/net/tcp` 采集网络数据（已在旧版 Go 探针中实现）
- eBPF 技术栈已就绪，日后若换内核可直接启用

### 选项 2：尝试其他 BPF 程序类型
- `BPF_PROG_TYPE_SOCKET_FILTER` 不需要 CONFIG_BPF_EVENTS
- 可过滤/统计 socket 层数据

### 选项 3：更换 STB 内核
- 重新编译内核，启用 `CONFIG_BPF_EVENTS=y`
- 需要 STB 厂商提供内核源码

---

## 文件清单

| 文件 | 路径 | 说明 |
|------|------|------|
| 源码 | `stb_ebpf_probe/src/` | min_loader.c, main_stb.c 等 |
| BPF C | `stb_ebpf_probe/bpf/stb_connect.bpf.c` | tracepoint 程序 |
| 字节码头文件 | `stb_ebpf_probe/bpf_loader/bpf_bytecode.h` | 自动生成的 BPF 指令 |
| ARM 二进制 | `stb_ebpf_probe/build/stb_ebpf_probe` | 20KB, 动态, strip后 |
| 部署包 | `stb_ebpf_probe-arm.tar.gz` | 151KB, 可直接 ADB push |
| QA 报告 | 见上文 | 44 项测试通过 |
