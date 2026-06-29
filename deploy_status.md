# STB eBPF 探针部署状态

## 已完成的里程碑（2026-06-23）

| 阶段 | 状态 | 详情 |
|------|------|------|
| BPF 字节码编译 | ✅ | `stb_connect.bpf.o`，2 个 tracepoint（enter + exit），共 139 条指令 |
| ARM 交叉编译 | ✅ | NDK r27b，静态链接，ARM 32-bit ELF，~260KB |
| 编译产物路径 | ✅ | `build/stb_ebpf_probe`（VM），`deploy/stb_ebpf_probe-arm.tar.gz`（VM） |

## 编译产物

**二进制文件**: `C:\Users\PC\WorkBuddy\2026-06-12-10-53-25\stb_ebpf_probe-arm.tar.gz` (151KB)
- 解压后: `stb_ebpf_probe` (260KB, ARM 32-bit, statically linked)
- 可直接 ADB push 到 STB 运行

## 部署步骤（待完成）

ADB push 到 STB 后运行：
```
cd C:\platform-tools
adb connect 10.115.107.93:60001
adb push stb_ebpf_probe /data/local/tmp/stb_ebpf_probe_new
adb shell "chmod +x /data/local/tmp/stb_ebpf_probe_new"
adb shell "cd /data/local/tmp && ./stb_ebpf_probe_new -v"
```

## 验证要点
1. `./stb_ebpf_probe_new -v` 显示版本信息
2. `./stb_ebpf_probe_new` 启动采集（需要 root 或 BPF 权限）
3. 检查是否能打开 tracepoint
4. 检查是否能加载 BPF 程序
5. 观察是否能收到 connect 事件
