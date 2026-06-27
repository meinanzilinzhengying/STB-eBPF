/**
 * config.h - Compile-time configuration for STB eBPF Probe
 * 
 * This file contains all configurable parameters for the project.
 * Modify these values to adapt to different deployment environments.
 */

#ifndef _STB_CONFIG_H
#define _STB_CONFIG_H

/* ==================== Network Configuration ==================== */

/* Windows relay server address and port */
#define RELAY_SERVER_IP      "10.115.69.95"
#define RELAY_SERVER_PORT    9104

/* Probe identifier (reported to relay server) */
#define PROBE_ID            "stb-tyson-01"

/* ==================== BPF Configuration ==================== */

/* BPF map sizes */
#define CONNECT_START_MAP_SIZE  1024    /* Max concurrent connect operations */
#define PERF_MAP_SIZE           64      /* perf_buffer pages (must be power of 2) */

/* BPF program limits */
#define MAX_INSTRUCTIONS        4096    /* Max BPF instructions per program */

/* ==================== Buffer Configuration ==================== */

/* Ring buffer size for inter-thread communication */
#define RING_BUFFER_SIZE       4096

/* JSON serialization buffer size */
#define JSON_BUFFER_SIZE       4096

/* TCP send buffer size */
#define TCP_SEND_BUFFER_SIZE   65536

/* Batch settings */
#define MAX_EVENTS_PER_BATCH   32      /* Max events to batch before sending */
#define BATCH_FLUSH_TIMEOUT_MS 1000   /* Max time to wait before flushing batch */

/* ==================== Performance Configuration ==================== */

/* CPU affinity (set to -1 to disable) */
#define CPU_AFFINITY           -1

/* Memory limit (in bytes) */
#define MAX_MEMORY_LIMIT       (100 * 1024 * 1024)  /* 100 MB */

/* ==================== Reconnection Configuration ==================== */

/* Reconnection delay settings (exponential backoff) */
#define RECONNECT_INITIAL_DELAY_MS   1000
#define RECONNECT_MAX_DELAY_MS       30000
#define RECONNECT_MAX_RETRIES        10

/* ==================== Logging Configuration ==================== */

/* Log level */
#define LOG_LEVEL              2  /* 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG */

/* Log to stdout/stderr */
#define LOG_TO_STDOUT          1

/* ==================== Feature Flags ==================== */

/* Enable/disable features */
#define ENABLE_TCP_CLIENT      1
#define ENABLE_SERIALIZER      1
#define ENABLE_PERF_MONITOR    1
#define ENABLE_LOADER          1

/* Debug mode (verbose logging) */
#define DEBUG_MODE             0

/* ==================== Default Values ==================== */

/* Default values for optional parameters */
#define DEFAULT_SADDR          0
#define DEFAULT_SPORT          0

/* ==================== Helper Macros ==================== */

/* Convert IP address from __u32 to string */
#define IP_TO_STRING(ip) \
    ((ip) >> 24) & 0xFF, ((ip) >> 16) & 0xFF, ((ip) >> 8) & 0xFF, (ip) & 0xFF

/* Convert IP address from string to __u32 */
#define STRING_TO_IP(a, b, c, d) \
    (((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

/* Check if address is IPv4 */
#define IS_IPV4(family)       ((family) == AF_INET)

/* Check if protocol is TCP */
#define IS_TCP(protocol)       ((protocol) == IPPROTO_TCP)

#endif /* _STB_CONFIG_H */
