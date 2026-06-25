/* SPDX-License-Identifier: GPL-2.0 */
/* process_exec.bpf.c - trace sched:sched_process_exec using ringbuf */

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

SEC("tp/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_EXEC;
    e->pid = BPF_CORE_READ(ctx, pid);
    e->ppid = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u64 arg_start = BPF_CORE_READ(task, mm, arg_start);
    __u64 arg_end = BPF_CORE_READ(task, mm, arg_end);
    __u64 arg_len = arg_end - arg_start;
    if (arg_len > sizeof(e->data) - 1)
        arg_len = sizeof(e->data) - 1;

    if (arg_len > 0) {
        bpf_probe_read_user_str(e->data, sizeof(e->data), (void *)arg_start);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int tracepoint_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_EXIT;
    e->pid = BPF_CORE_READ(ctx, pid);
    e->ppid = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
