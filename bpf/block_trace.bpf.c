/* SPDX-License-Identifier: GPL-2.0 */
/* block_trace.bpf.c - tracepoint block_rq_issue/complete for disk IO trace */

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
    __type(value, __u64);
} block_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} block_size_map SEC(".maps");

SEC("tp/block/block_rq_issue")
int tracepoint_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
    __u64 dev = BPF_CORE_READ(ctx, dev);
    __u64 sector = BPF_CORE_READ(ctx, sector);
    __u64 nr_sector = BPF_CORE_READ(ctx, nr_sector);
    __u64 key = (dev << 32) | sector;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&block_start, &key, &ts, BPF_ANY);
    bpf_map_update_elem(&block_size_map, &key, &nr_sector, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = ts;
    e->type = 16; // block_issue
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->bytes = nr_sector * 512;
    e->packets = 0;
    e->latency_ns = 0;
    e->count = 0;
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/block/block_rq_complete")
int tracepoint_block_rq_complete(struct trace_event_raw_block_rq *ctx) {
    __u64 dev = BPF_CORE_READ(ctx, dev);
    __u64 sector = BPF_CORE_READ(ctx, sector);
    __u64 key = (dev << 32) | sector;
    __u64 *start = bpf_map_lookup_elem(&block_start, &key);
    if (!start) {
        return 0;
    }
    __u64 latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&block_start, &key);
    bpf_map_delete_elem(&block_size_map, &key);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 17; // block_complete
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->latency_ns = latency;
    e->bytes = 0;
    e->packets = 0;
    e->count = 1;
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
