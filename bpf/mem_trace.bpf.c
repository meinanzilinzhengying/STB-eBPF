/* SPDX-License-Identifier: GPL-2.0 */
/* mem_trace.bpf.c - kprobe kmalloc/kfree for memory allocation trace */

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
    __type(key, __u64);
    __type(value, struct event);
} alloc_map SEC(".maps");

SEC("kprobe/__kmalloc")
int BPF_KPROBE(trace_kmalloc, size_t size, gfp_t flags) {
    __u64 ptr = PT_REGS_RC(ctx);
    if (ptr == 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 14; // kmalloc
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->bytes = size;
    e->packets = 0;
    e->latency_ns = 0;
    e->count = 1;
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/kfree")
int BPF_KPROBE(trace_kfree, const void *objp) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 15; // kfree
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->bytes = 0;
    e->packets = 0;
    e->latency_ns = 0;
    e->count = 1;
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
