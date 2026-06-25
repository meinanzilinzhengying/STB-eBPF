/* SPDX-License-Identifier: GPL-2.0 */
/* tcp_connect.bpf.c - kprobe tcp_v4_connect using ringbuf */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} start_ts SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect_entry, struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ts, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect_exit) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&start_ts, &pid_tgid);
    if (!start) {
        return 0;
    }
    __u64 latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&start_ts, &pid_tgid);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_TCP_CONNECT;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->latency_ns = latency;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_TCP_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取目标地址信息
    struct sock_common *skc = &sk->__sk_common;
    e->dst_ip = BPF_CORE_READ(skc, skc_daddr);
    e->dst_port = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));
    e->src_ip = BPF_CORE_READ(skc, skc_rcv_saddr);
    e->src_port = bpf_ntohs(BPF_CORE_READ(skc, skc_num));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
