/**
 * vmlinux_legacy.h - Legacy kernel structure definitions for STB eBPF
 * 
 * This file provides hand-written kernel structure definitions to replace
 * BTF/CO-RE based vmlinux.h. Used for older kernels (5.4.x) without BTF support.
 * 
 * These definitions are based on Linux kernel 5.4.x for ARMv7l.
 */

#ifndef _VMLINUX_LEGACY_H
#define _VMLINUX_LEGACY_H

/* Include kernel types */
#include <linux/types.h>
#include <linux/bpf.h>

/* ==================== Basic Kernel Types ==================== */

/* Task struct forward declaration */
struct task_struct;

/* Cred struct forward declaration */
struct cred;

/* ==================== Socket Structures ==================== */

/**
 * struct sockaddr - Socket address structure
 * 
 * Generic socket address structure used by connect() syscall.
 */
struct sockaddr {
    unsigned short  sa_family;    /* Address family */
    char            sa_data[14];  /* Protocol-specific address */
};

/**
 * struct sockaddr_in - IPv4 socket address
 * 
 * IPv4-specific socket address structure.
 */
struct sockaddr_in {
    unsigned short  sin_family;   /* Address family (AF_INET) */
    unsigned short  sin_port;     /* Port number (network byte order) */
    unsigned int    sin_addr;     /* IPv4 address (network byte order) */
    char            sin_zero[8];  /* Padding */
};

/**
 * struct sockaddr_in6 - IPv6 socket address
 * 
 * IPv6-specific socket address structure.
 */
struct sockaddr_in6 {
    unsigned short  sin6_family;   /* Address family (AF_INET6) */
    unsigned short  sin6_port;     /* Port number (network byte order) */
    unsigned int    sin6_flowinfo; /* IPv6 flow information */
    unsigned char   sin6_addr[16];/* IPv6 address */
    unsigned int    sin6_scope_id; /* Scope ID */
};

/* ==================== System Call Arguments ==================== */

/**
 * Syscall enter_connect arguments
 * 
 * tracepoint/syscalls/sys_enter_connect format:
 * - args[0]: int fd
 * - args[1]: struct sockaddr *addr
 * - args[2]: int addrlen
 */
struct sys_enter_connect_args {
    long long pad;                /* Padding */
    long long id;                 /* Tracepoint common fields */
    unsigned long args[3];       /* Syscall arguments */
};

/**
 * Syscall exit_connect arguments
 * 
 * tracepoint/syscalls/sys_exit_connect format:
 * - ret: return value
 */
struct sys_exit_connect_args {
    long long pad;                /* Padding */
    long long id;                 /* Tracepoint common fields */
    long ret;                     /* Return value */
};

/* ==================== Tracepoint Common Fields ==================== */

/**
 * Tracepoint common fields
 * 
 * All tracepoints have these common fields at the beginning.
 */
struct trace_entry {
    unsigned short type;
    unsigned char  flags;
    unsigned char  preempt_count;
    int            pid;
};

/* ==================== Task and Process Information ==================== */

/**
 * Helper to get current task struct
 * 
 * Note: In BPF, we use bpf_get_current_pid_tgid() and
 * bpf_get_current_comm() instead of accessing task_struct directly.
 */

/* ==================== Network Namespace ==================== */

/**
 * struct net - Network namespace structure (simplified)
 * 
 * We don't need full definition since we're using helper functions.
 */

/* ==================== Socket Structures (simplified) ==================== */

/**
 * struct socket - Socket structure (simplified)
 * 
 * We don't need full definition since we're using helper functions.
 */

/**
 * struct sock - Socket kernel structure (simplified)
 * 
 * We don't need full definition since we're using helper functions.
 */

/* ==================== BPF Helper Aliases ==================== */

/* These are already defined in linux/bpf.h, but we add aliases for clarity */

#ifndef bpf_get_current_pid_tgid
#define bpf_get_current_pid_tgid()                                      \
    ((__u64)bpf_get_current_pid_tgid())
#endif

#ifndef bpf_get_current_comm
#define bpf_get_current_comm(comm, size)                                 \
    bpf_get_current_comm(comm, size)
#endif

#ifndef bpf_ktime_get_ns
#define bpf_ktime_get_ns()                                              \
    ((__u64)bpf_ktime_get_ns())
#endif

#ifndef bpf_probe_read
#define bpf_probe_read(dst, size, src)                             \
    bpf_probe_read(dst, size, src)
#endif

#ifndef bpf_perf_event_output
#define bpf_perf_event_output(ctx, map, flags, data, size)             \
    bpf_perf_event_output(ctx, map, flags, data, size)
#endif

/* ==================== Byte Order Helpers ==================== */

/**
 * Byte order conversion helpers
 * 
 * Note: Network byte order is big-endian.
 * These are simplified versions for BPF programs.
 */

/* Convert 16-bit from host to network byte order */
static inline __u16 htons(__u16 hostshort) {
    return ((hostshort & 0x00FF) << 8) |
           ((hostshort & 0xFF00) >> 8);
}

/* Convert 16-bit from network to host byte order */
static inline __u16 ntohs(__u16 netshort) {
    return htons(netshort);  /* Same operation */
}

/* Convert 32-bit from host to network byte order */
static inline __u32 htonl(__u32 hostlong) {
    return ((hostlong & 0x000000FF) << 24) |
           ((hostlong & 0x0000FF00) << 8)  |
           ((hostlong & 0x00FF0000) >> 8)  |
           ((hostlong & 0xFF000000) >> 24);
}

/* Convert 32-bit from network to host byte order */
static inline __u32 ntohl(__u32 netlong) {
    return htonl(netlong);  /* Same operation */
}

/* ==================== IP Address Helpers ==================== */

/* Extract IPv4 address from __u32 (network byte order) */
#define IPQUAD(ip) \
    ((unsigned char *)&ip)[0], \
    ((unsigned char *)&ip)[1], \
    ((unsigned char *)&ip)[2], \
    ((unsigned char *)&ip)[3]

/* ==================== Network Protocol Headers ==================== */

/**
 * struct iphdr - IPv4 header (20 bytes, no options)
 * 
 * Standard IPv4 header format.
 */
struct iphdr {
    __u8  ver_ihl;        /* version(4) + ihl(4) */
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

/**
 * struct tcphdr - TCP header (20 bytes, no options)
 * 
 * Standard TCP header format.
 */
struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 data_offset_flags;  /* data_offset(4) + reserved(3) + flags(9) */
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

/**
 * struct udphdr - UDP header (8 bytes)
 * 
 * Standard UDP header format.
 */
struct udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
};

/**
 * struct dnshdr - DNS header (12 bytes)
 * 
 * Standard DNS header format.
 */
struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

/* ==================== Memory Operations ==================== */

/**
 * memset - Simplified memset for BPF programs
 * 
 * Note: Use bpf_memset() or loop-based implementation in BPF.
 */

/* ==================== Compile-time Checks ==================== */

/* Ensure we're in BPF compilation context */
#ifndef __BPF__
#error "This file should only be included in BPF programs"
#endif

#endif /* _VMLINUX_LEGACY_H */
