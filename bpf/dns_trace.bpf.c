/* SPDX-License-Identifier: GPL-2.0 */
/* dns_trace.bpf.c - kprobe udp_sendmsg/udp_recvmsg for DNS payload capture */

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
} dns_start_ts SEC(".maps");

static __always_inline int handle_udp_msg(struct sock *sk, struct msghdr *msg, __u64 size, __u8 direction) {
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // 仅捕获 DNS 端口 (53)
    if (sport != 53 && dport != 53)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_DNS;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = sport;
    e->dst_port = dport;
    e->protocol = 17; // UDP
    e->bytes = size;
    e->packets = 1;
    e->latency_ns = 0;
    e->count = direction;

    // 读取 UDP payload
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

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return handle_udp_msg(sk, msg, size, 1);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size, int flags) {
    return handle_udp_msg(sk, msg, size, 2);
}
