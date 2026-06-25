#!/bin/sh
set -e

# CloudFlow eBPF Probe Docker Entrypoint

# 设置默认环境变量
: ${PROBE_ID:=container-probe}
: ${INTERFACE:=eth0}
: ${CLICKHOUSE_ADDR:=127.0.0.1}
: ${CLICKHOUSE_USER:=default}
: ${CLICKHOUSE_PASSWORD:=}
: ${CLICKHOUSE_DATABASE:=cloudflow}
: ${API_PORT:=9090}
: ${COLLECT_ALL:=true}

# 启动探针
exec ./cloudflow-ebpf-probe
