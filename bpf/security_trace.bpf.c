/* SPDX-License-Identifier: GPL-2.0 */
/* security_trace.bpf.c - kprobe cap_capable/security_file_open/load_module for security audit */

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
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} cap_count SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable, const struct cred *cred, int cap, int opt) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 18; // cap_capable
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->count = cap;
    e->latency_ns = opt;
    e->bytes = 0;
    e->packets = 0;
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open, struct file *file) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 19; // security_file_open
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->bytes = 0;
    e->packets = 0;

    struct path *path = &file->f_path;
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    const char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(e->data, sizeof(e->data), name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/load_module")
int BPF_KPROBE(trace_load_module) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = 20; // load_module
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->bytes = 0;
    e->packets = 0;
    __builtin_memset(e->data, 0, sizeof(e->data));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
