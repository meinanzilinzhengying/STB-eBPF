# STB eBPF Probe — 交付总结

## TL;DR
基于先生提供的 ARM32 eBPF 技术分析，完成了 STB 机顶盒的纯 C + libbpf eBPF 探针开发（19个源文件），包含 tracepoint 采集 connect 事件、perf_buffer 双阶段流水线、JSON 序列化、TCP 断线重连，QA 验证通过。

## 交付概览

| 项目 | 状态 |
|------|------|
| 代码交付 | ✅ **PASS**（QA 44项测试通过，2个Bug已修复） |
| T01 项目基础设施 | ✅ 构建系统/配置/环境检测 |
| T02 eBPF 内核程序 | ✅ tracepoint 采集 connect 事件 |
| T03 用户态 Loader | ✅ libbpf legacy 加载 + perf_buffer 轮询 |
| T04 序列化+TCP | ✅ JSON 序列化 + 断线重连 |
| T05 集成部署 | ✅ 全链路集成 + ADB 部署脚本 |

## 文件清单（19个）

```
stb_ebpf_probe/
├── Makefile                          # 构建系统
├── cmake/toolchain_armv7l.cmake      # NDK 交叉编译链
├── bpf/
│   ├── stb_connect.bpf.c             # eBPF 内核程序（tracepoint）
│   └── vmlinux_legacy.h              # 手写内核 struct
├── include/
│   └── common.h                      # 共享结构体
├── src/
│   ├── main.c                        # 入口 + 主循环
│   ├── config.h                      # 编译期配置
│   ├── loader.c/h                    # libbpf 加载器
│   ├── perf_monitor.c/h              # perf_buffer + 环形缓冲区
│   ├── serializer.c/h                # JSON 序列化
│   └── tcp_client.c/h                # TCP 客户端
├── scripts/
│   ├── build_arm.sh                  # 交叉编译脚本
│   ├── check_env.sh                  # 环境检测脚本
│   └── deploy.sh                     # ADB 部署脚本
└── deploy/
    └── stb_ebpf_probe.service        # Android init 脚本
```

## QA 验证结果

44 项测试通过，2 个 Bug 已修复：
1. **`common.h:95`** `_Static_assert` comm 偏移量 36→44（latency_us 占 8 字节）
2. **`perf_monitor.h`** 缺少 `perf_monitor_poll_once` 声明（加 -Werror 编译失败）

## 用户下一步建议

1. **部署到 STB**: 在 Windows 上运行 `scripts/deploy.sh`（需 ADB 连接 10.115.107.93:60001）
2. **环境检测**: 先运行 `check_env.sh -r -d <设备序列号>` 验证 STB 的 eBPF 能力
3. **交叉编译**: 需要 Android NDK r25+ 和 clang 14+ 进行 ARM 交叉编译
4. **数据验证**: 确认 ClickHouse `cloudflow.ebpf_events` 表能收到 connect 事件
5. **资源监控**: 运行后通过 top/ps 确认 CPU ≤ 10%、内存 ≤ 100MB
