/**
 * stb_connect.bpf.c - eBPF kernel program for tracing connect() syscalls
 * 
 * This BPF program attaches to tracepoints for sys_enter_connect and
 * sys_exit_connect to capture network connection events.
 * 
 * Uses legacy libbpf mode (no BTF/CO-RE) for compatibility with
 * kernel 5.4.x on ARMv7l STB devices.
 * 
 * Instruction count: ≤ 4096 (verifier limit)
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Include legacy kernel structure definitions */
#include "vmlinux_legacy.h"

/* Include shared structure definitions */
#include "../include/common.h"

/* ==================== BPF Maps ==================== */

/**
 * perf_map - PERF_EVENT_ARRAY for sending data to userspace
 * 
 * Uses BPF_MAP_TYPE_PERF_EVENT_ARRAY (required for kernel 5.4).
 * Ring buffer (BPF_MAP_TYPE_RINGBUF) is not available until kernel 5.8.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} perf_map SEC(".maps");

/**
 * connect_start - HASH map to store connect start timestamps
 * 
 * Key: PID (upper 32 bits) + TID (lower 32 bits) from bpf_get_current_pid_tgid()
 * Value: Timestamp in nanoseconds when connect() was called
 * 
 * Used to calculate latency between sys_enter_connect and sys_exit_connect.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  /* PID+TID */
    __uint(value_size, sizeof(__u64)); /* timestamp_ns */
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} connect_start SEC(".maps");

/* ==================== Helper Functions ==================== */

/**
 * get_pid_tgid - Get PID and TGID from bpf_get_current_pid_tgid()
 * 
 * Returns: __u64 where upper 32 bits = TGID (PID), lower 32 bits = PID (TID)
 */
static __always_inline __u64 get_pid_tgid(void) {
    return bpf_get_current_pid_tgid();
}

/**
 * get_uid_gid - Get UID and GID from bpf_get_current_uid_gid()
 * 
 * Returns: __u64 where upper 32 bits = GID, lower 32 bits = UID
 */
static __always_inline __u64 get_uid_gid(void) {
    return bpf_get_current_uid_gid();
}

/**
 * read_sockaddr_in - Safely read sockaddr_in from userspace
 * 
 * @ctx: BPF context (for probe_read_user)
 * @user_addr: Userspace pointer to sockaddr structure
 * @addr_len: Length of the sockaddr structure
 * @family: Output - address family (AF_INET or AF_INET6)
 * @daddr: Output - destination IPv4 address (network byte order)
 * @dport: Output - destination port (host byte order)
 * 
 * Returns: 0 on success, -1 on failure
 * 
 * Note: Uses bpf_probe_read_user() for safe userspace memory access.
 *       This is required for correctness and to pass BPF verifier.
 */
static __always_inline int read_sockaddr_in(struct pt_regs *ctx,
                                           const void *user_addr,
                                           int addr_len,
                                           __u16 *family,
                                           __u32 *daddr,
                                           __u16 *dport) {
    /* Read address family first (sa_family is always 2 bytes at offset 0) */
    __u16 fam;
    if (bpf_probe_read_user(&fam, sizeof(fam), user_addr) != 0) {
        return -1;
    }
    *family = fam;
    
    /* Handle IPv4 */
    if (fam == AF_INET && addr_len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr;
        if (bpf_probe_read_user(&addr, sizeof(addr), user_addr) != 0) {
            return -1;
        }
        *daddr = addr.sin_addr;
        /* Convert port from network to host byte order */
        *dport = __builtin_bswap16(addr.sin_port);
        return 0;
    }
    
    /* Handle IPv6 - not fully supported yet, just record family */
    if (fam == AF_INET6) {
        *daddr = 0;
        *dport = 0;
        return 0;
    }
    
    /* Unknown family */
    *daddr = 0;
    *dport = 0;
    return -1;
}

/**
 * submit_event - Submit a connect_event_t to userspace via perf_buffer
 * 
 * @ctx: BPF context
 * @event: Pointer to connect_event_t to submit
 * 
 * Returns: 0 on success, negative error code on failure
 */
static __always_inline int submit_event(struct pt_regs *ctx,
                                       struct connect_event_t *event) {
    /* Use bpf_perf_event_output() to send event to userspace */
    int ret = bpf_perf_event_output(ctx, &perf_map,
                                     BPF_F_CURRENT_CPU, event,
                                     sizeof(*event));
    return ret;
}

/* ==================== Tracepoint Handlers ==================== */

/**
 * tracepoint__sys_enter_connect - Handle sys_enter_connect tracepoint
 * 
 * Called when a process calls connect() syscall.
 * Records the start timestamp for latency calculation.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__sys_enter_connect(struct sys_enter_connect_args *args) {
    __u64 pid_tgid = get_pid_tgid();
    __u64 timestamp_ns = bpf_ktime_get_ns();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    /* Read connect() arguments */
    int fd = (int)args->args[0];
    const void *user_addr = (const void *)args->args[1];
    int addr_len = (int)args->args[2];
    
    /* Only trace IPv4 for now */
    if (addr_len < sizeof(short)) {
        return 0;
    }
    
    /* Read destination address */
    __u16 family;
    __u32 daddr;
    __u16 dport;
    if (read_sockaddr_in(args, user_addr, addr_len, &family, &daddr, &dport) != 0) {
        return 0;
    }
    
    /* Only process IPv4 */
    if (family != AF_INET) {
        return 0;
    }
    
    /* Store start timestamp for latency calculation */
    bpf_map_update_elem(&connect_start, &pid_tgid, &timestamp_ns, BPF_ANY);
    
    /* Prepare event */
    struct connect_event_t event = {0};
    event.timestamp_ns = timestamp_ns;
    event.pid = pid;
    event.uid = get_uid_gid() & 0xFFFFFFFF;  /* Lower 32 bits = UID */
    event.saddr = 0;  /* Source address - could be read from socket */
    event.daddr = daddr;
    event.sport = 0;  /* Source port - not available at connect enter */
    event.dport = dport;
    event.family = family;
    event.protocol = IPPROTO_TCP;
    event.event_type = EVENT_CONNECT_ENTER;
    event.retval = 0;
    event.latency_us = 0;
    
    /* Get process name */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    /* Submit event to userspace */
    submit_event(args, &event);
    
    return 0;
}

/**
 * tracepoint__sys_exit_connect - Handle sys_exit_connect tracepoint
 * 
 * Called when connect() syscall returns.
 * Calculates latency and submits exit event.
 */
SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__sys_exit_connect(struct sys_exit_connect_args *args) {
    __u64 pid_tgid = get_pid_tgid();
    __u64 timestamp_ns = bpf_ktime_get_ns();
    
    /* Get start timestamp */
    __u64 *start_ts = bpf_map_lookup_elem(&connect_start, &pid_tgid);
    __u64 latency_us = 0;
    if (start_ts != NULL) {
        latency_us = (timestamp_ns - *start_ts) / 1000;  /* Convert ns to us */
        /* Delete entry from map */
        bpf_map_delete_elem(&connect_start, &pid_tgid);
    }
    
    __u32 pid = pid_tgid >> 32;
    
    /* Prepare event */
    struct connect_event_t event = {0};
    event.timestamp_ns = timestamp_ns;
    event.pid = pid;
    event.uid = get_uid_gid() & 0xFFFFFFFF;
    event.saddr = 0;
    event.daddr = 0;  /* Address info not available at exit */
    event.sport = 0;
    event.dport = 0;
    event.family = AF_INET;
    event.protocol = IPPROTO_TCP;
    event.event_type = EVENT_CONNECT_EXIT;
    event.retval = (int)args->ret;
    event.latency_us = latency_us;
    
    /* Get process name */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    /* Submit event to userspace */
    submit_event(args, &event);
    
    return 0;
}

/* ==================== License ==================== */

char _license[] SEC("license") = "GPL";
