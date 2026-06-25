# 安装指南

> 版本: v3.1.0  
> 支持平台: Linux amd64 / arm64 / arm32  
> 最低内核: 4.15 (5.8+ 推荐)

---

## 1. 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/meinanzilinzhengying/ebpf-probe/main/deploy/install/install.sh | bash
```

安装脚本会自动：
1. 检测内核版本和 BTF 支持
2. 下载匹配架构的二进制
3. 安装 systemd 服务
4. 启动探针

---

## 2. 手动安装

### 2.1 下载预编译二进制

```bash
# AMD64
wget https://github.com/meinanzilinzhengying/ebpf-probe/releases/download/v3.1.0/cloudflow-ebpf-probe-v3.1.0-linux-amd64.tar.gz

# ARM64
wget https://github.com/meinanzilinzhengying/ebpf-probe/releases/download/v3.1.0/cloudflow-ebpf-probe-v3.1.0-linux-arm64.tar.gz

# ARM32 (机顶盒/嵌入式)
wget https://github.com/meinanzilinzhengying/ebpf-probe/releases/download/v3.1.0/cloudflow-ebpf-probe-v3.1.0-linux-arm32.tar.gz
```

### 2.2 解压安装

```bash
tar xzf cloudflow-ebpf-probe-v3.1.0-linux-amd64.tar.gz
cd cloudflow-ebpf-probe-v3.1.0/
sudo install -Dm755 cloudflow-ebpf-probe /usr/local/bin/
sudo install -Dm644 cloudflow-ebpf-probe.service /etc/systemd/system/
sudo install -Dm644 config.yaml /etc/ebpf-probe/
```

### 2.3 启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflow-ebpf-probe
sudo systemctl status cloudflow-ebpf-probe
```

---

## 3. Docker 部署

```bash
docker run -d --name ebpf-probe \
  --privileged \
  --pid host \
  --network host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /proc:/host/proc:ro \
  -v /etc/ebpf-probe:/config \
  cloudflow/ebpf-probe:v3.1.0 \
  -config /config/config.yaml
```

> ⚠️ Docker 模式下部分采集器（如 TC/XDP）可能受限，建议使用 host network 模式。

---

## 4. K8s DaemonSet 部署

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-probe
spec:
  selector:
    matchLabels:
      app: ebpf-probe
  template:
    metadata:
      labels:
        app: ebpf-probe
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: probe
        image: cloudflow/ebpf-probe:v3.1.0
        securityContext:
          privileged: true
        volumeMounts:
        - name: debug
          mountPath: /sys/kernel/debug
          readOnly: true
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: config
          mountPath: /etc/ebpf-probe
      volumes:
      - name: debug
        hostPath:
          path: /sys/kernel/debug
      - name: proc
        hostPath:
          path: /proc
      - name: config
        configMap:
          name: ebpf-probe-config
```

---

## 5. 排障指南

### 5.1 启动失败

```bash
# 检查日志
sudo journalctl -u cloudflow-ebpf-probe -f

# 检查内核版本
uname -r                    # 需要 >= 4.15
ls /sys/kernel/btf/vmlinux  # BTF 支持 (5.8+)

# 检查权限
sudo ls /sys/kernel/debug/tracing  # 需要 root 或 CAP_BPF
```

### 5.2 采集器加载失败

```bash
# 查看能力检测
sudo /usr/local/bin/cloudflow-ebpf-probe --check-capabilities

# 逐个启用排查
sudo cloudflow-ebpf-probe --enable network_flow --run-once 10s
```

### 5.3 内存/CPU 过高

```bash
# 查看资源占用
ps -p $(pgrep cloudflow-ebpf-probe) -o pid,ppid,%cpu,%mem,vsz,rss,comm

# 调整配置，关闭高开销采集器
sudo sed -i 's/http_trace: true/http_trace: false/' /etc/ebpf-probe/config.yaml
sudo systemctl restart cloudflow-ebpf-probe
```

### 5.4 无数据输出

```bash
# 检查 ClickHouse/TiDB 连接
sudo cloudflow-ebpf-probe --config /etc/ebpf-probe/config.yaml --dry-run

# 检查 Ring Buffer 是否溢出
cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null || true
```

---

## 6. 卸载

```bash
sudo systemctl stop cloudflow-ebpf-probe
sudo systemctl disable cloudflow-ebpf-probe
sudo rm -f /usr/local/bin/cloudflow-ebpf-probe
sudo rm -f /etc/systemd/system/cloudflow-ebpf-probe.service
sudo rm -rf /etc/ebpf-probe
sudo systemctl daemon-reload
```
