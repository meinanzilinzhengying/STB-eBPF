/* SPDX-License-Identifier: GPL-2.0 */
/* file_open.bpf.c - kprobe do_filp_open using ringbuf */

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

SEC("kprobe/do_filp_open")
int BPF_KPROBE(trace_do_filp_open, int dfd, struct filename *name) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_FILE_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 清零 data 字段，避免 ringbuf 残留数据污染
    __builtin_memset(e->data, 0, sizeof(e->data));

    const char *fname = BPF_CORE_READ(name, name);
    bpf_probe_read_kernel_str(e->data, sizeof(e->data), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write, struct file *file) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_TYPE_FILE_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 清零 data 字段
    __builtin_memset(e->data, 0, sizeof(e->data));

    e->data[0] = 'W';
    e->data[1] = 'R';
    e->data[2] = 'I';
    e->data[3] = 'T';
    e->data[4] = 'E';
    e->data[5] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
