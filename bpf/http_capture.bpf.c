/* http_capture.bpf.c - kprobe for HTTP payload capture */
#include "vmlinux_legacy.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "common.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} perf_map SEC(".maps");

static __always_inline int handle_tcp_msg(struct pt_regs *ctx, struct sock *sk, 
                                          void *msg, __u64 size, __u8 direction) {
    struct event e = {};
    e.timestamp_ns = bpf_ktime_get_ns();
    e.type = EVENT_TYPE_HTTP;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.protocol = 6;
    e.bytes = size;
    e.packets = 1;
    e.count = direction;
    
    struct sock_common *skc = &sk->__sk_common;
    e.src_ip = skc->skc_rcv_saddr;
    e.dst_ip = skc->skc_daddr;
    e.src_port = skc->skc_num;
    e.dst_port = bpf_ntohs(skc->skc_dport);
    
    if (e.src_port != 80 && e.src_port != 443 && e.src_port != 8080 &&
        e.dst_port != 80 && e.dst_port != 443 && e.dst_port != 8080) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);
    __u64 size = (__u64)PT_REGS_PARM3(ctx);
    return handle_tcp_msg(ctx, sk, msg, size, 1);
}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);
    __u64 size = (__u64)PT_REGS_PARM3(ctx);
    return handle_tcp_msg(ctx, sk, msg, size, 2);
}
