/* SPDX-License-Identifier: GPL-2.0 */
/* http_trace.bpf.c - kprobe tcp_sendmsg/tcp_recvmsg for HTTP payload capture */

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
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} start_ts SEC(".maps");

static __always_inline int handle_tcp_msg(struct sock *sk, struct msghdr *msg, __u64 size, __u8 direction) {
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // 仅捕获 HTTP/HTTPS 端口
    if (sport != 80 && sport != 443 && sport != 8080 && dport != 80 && dport != 443 && dport != 8080)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_HTTP;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = sport;
    e->dst_port = dport;
    e->protocol = 6; // TCP
    e->bytes = size;
    e->packets = 1;
    e->latency_ns = 0;
    e->count = direction;

    // 尝试读取 payload (最多 200 bytes)
    struct iov_iter *iter = &msg->msg_iter;
    const struct kvec *kvec = (const struct kvec *)BPF_CORE_READ(iter, kvec);
    if (kvec) {
        void *iov_base = BPF_CORE_READ(kvec, iov_base);
        __u64 iov_len = BPF_CORE_READ(kvec, iov_len);
        if (iov_base && iov_len > 0) {
            __u64 copy_len = iov_len;
            if (copy_len > sizeof(e->data) - 1)
                copy_len = sizeof(e->data) - 1;
            bpf_probe_read_user(e->data, copy_len, iov_base);
            e->data[copy_len] = '\0';
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return handle_tcp_msg(sk, msg, size, 1); // 1 = request
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return handle_tcp_msg(sk, msg, size, 2); // 2 = response
}
