/* SPDX-License-Identifier: GPL-2.0 */
/* sched_trace.bpf.c - tracepoint sched_switch for CPU scheduling trace */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "common.h"

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} sched_start SEC(".maps");

SEC("tp/sched/sched_switch")
int tracepoint_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_MAX; // 12 = sched_switch
    e->pid = BPF_CORE_READ(ctx, prev_pid);
    e->ppid = BPF_CORE_READ(ctx, next_pid);
    e->latency_ns = BPF_CORE_READ(ctx, prev_state); // 用 latency_ns 存 prev_state
    e->bytes = 0;
    e->packets = 0;
    e->count = 0;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), ctx->prev_comm);
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_wakeup")
int tracepoint_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 13; // sched_wakeup
    e->pid = BPF_CORE_READ(ctx, pid);
    e->ppid = 0;
    e->latency_ns = 0;
    e->bytes = 0;
    e->packets = 0;
    e->count = 0;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), ctx->comm);
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
