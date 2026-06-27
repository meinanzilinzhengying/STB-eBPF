/**
 * common.h - Shared structures, enums, and constants for STB eBPF Probe
 * 
 * This file is shared between kernel BPF code and userspace code.
 * Must be compatible with both Clang (BPF) and GCC (userspace).
 */

#ifndef _STB_COMMON_H
#define _STB_COMMON_H

/* For userspace compilation */
#if !defined(__BPF__)
#include <stdint.h>
#include <string.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;
#else
/* For BPF compilation, linux/types.h provides these */
#endif

/* Event types */
#define EVENT_CONNECT_ENTER    0
#define EVENT_CONNECT_EXIT     1

/* Protocol numbers */
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17

/* Address families */
#define AF_INET        2
#define AF_INET6       10

/* Maximum lengths */
#define MAX_COMM_LEN   16
#define MAX_PROBE_ID   64
#define MAX_EVENTS_BATCH  32
#define MAX_JSON_LEN   4096

/* Ring buffer size (must be power of 2) */
#define RING_BUF_SIZE  4096

/* TCP reconnect settings */
#define RECONNECT_BASE_DELAY_MS   1000
#define RECONNECT_MAX_DELAY_MS    30000
#define RECONNECT_MAX_RETRIES     10

/* Performance settings */
#define MAX_CPU_USAGE_PERCENT     10
#define MAX_MEMORY_MB             100

/**
 * struct connect_event_t - Connection event structure
 * 
 * This structure is used to pass data from BPF program to userspace.
 * It must be packed to ensure consistent layout between kernel and userspace.
 */
struct connect_event_t {
    __u64 timestamp_ns;      /* bpf_ktime_get_ns() (monotonic clock) */
    __u32 pid;               /* Process PID */
    __u32 uid;               /* User UID */
    __u32 saddr;             /* Source IPv4 (network byte order) */
    __u32 daddr;             /* Destination IPv4 (network byte order) */
    __u16 sport;             /* Source port (host byte order) */
    __u16 dport;             /* Destination port (host byte order) */
    __u16 family;            /* AF_INET=2 / AF_INET6=10 */
    __u8  protocol;          /* IPPROTO_TCP=6 */
    __u8  event_type;        /* EVENT_CONNECT_ENTER / EVENT_CONNECT_EXIT */
    __s32 retval;            /* Return value (only valid for EXIT) */
    __u64 latency_us;        /* Latency in microseconds (only valid for EXIT) */
    char  comm[MAX_COMM_LEN];/* Process name */
} __attribute__((packed));

/**
 * struct ring_buffer - Lock-free ring buffer for inter-thread communication
 * 
 * Used to pass events from perf_buffer callback (Phase 1) to
 * main loop flush (Phase 2).
 */
struct ring_buffer {
    struct connect_event_t events[RING_BUF_SIZE];
    volatile __u32 write_idx;
    volatile __u32 read_idx;
};

/* Static assertions to ensure structure sizes */
#if !defined(__BPF__)
_Static_assert(sizeof(struct connect_event_t) == 60,
               "connect_event_t size mismatch");
_Static_assert(__builtin_offsetof(struct connect_event_t, comm) == 44,
               "comm field offset mismatch");
#endif

#endif /* _STB_COMMON_H */
