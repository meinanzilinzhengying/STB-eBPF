/* SPDX-License-Identifier: GPL-2.0 */
/* syscall.bpf.c - tracepoint raw_syscalls:sys_enter/exit using ringbuf */

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
} syscall_start SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int tracepoint_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&syscall_start, &pid_tgid, &ts, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = ts;
    e->type = EVENT_TYPE_SYSCALL;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->count = ctx->id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int tracepoint_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
    if (!start) {
        return 0;
    }
    __u64 latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&syscall_start, &pid_tgid);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_SYSCALL;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->latency_ns = latency;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
