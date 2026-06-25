FROM golang:1.24-alpine AS builder
RUN apk add --no-cache clang llvm make linux-headers
WORKDIR /build
COPY . .
RUN make build-static

FROM alpine:3.19
RUN apk add --no-cache iproute2 bpftool
WORKDIR /opt/cloudflow-ebpf-probe
COPY --from=builder /build/cloudflow-ebpf-probe-static ./cloudflow-ebpf-probe
COPY config/config.yaml ./config.yaml
COPY deploy/install/entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh cloudflow-ebpf-probe
ENV PROBE_ID=container-probe
ENV CLICKHOUSE_ADDR=127.0.0.1
ENV INTERFACE=eth0
ENTRYPOINT ["./entrypoint.sh"]
