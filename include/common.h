#ifndef _STB_COMMON_H
#define _STB_COMMON_H

#if !defined(__BPF__)
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;
#endif

#define CAT_NETWORK     "network"
#define CAT_METRICS     "metrics"
#define CAT_IPTV        "iptv"
#define CAT_DNS         "dns"
#define CAT_ICMP        "icmp"

#define EVT_FLOW        "flow"
#define EVT_CONNECT     "connect"
#define EVT_DISCONNECT  "disconnect"
#define EVT_TCP_STATE   "tcp_state"
#define EVT_DNS_QUERY   "dns_query"
#define EVT_DNS_REPLY   "dns_reply"
#define EVT_ICMP_ECHO   "icmp_echo"
#define EVT_IPTV_STREAM "iptv_stream"
#define EVT_IPTV_STUTTER "iptv_stutter"
#define EVT_HOST_METRICS "host_metrics"

#define PROTO_TCP   "TCP"
#define PROTO_UDP   "UDP"
#define PROTO_ICMP  "ICMP"

/* Payload types */
#define PAYLOAD_NONE      0
#define PAYLOAD_HTTP_REQ  1
#define PAYLOAD_HTTP_RESP 2

/* Anomaly types */
#define ANOMALY_NONE     0
#define ANOMALY_SPIKE    1
#define ANOMALY_SCAN     2
#define ANOMALY_DROP     3

/* TCP flags - only define if not already defined by system headers */
#ifndef TCP_FLAG_SYN
#define TCP_FLAG_SYN  0x02
#endif
#ifndef TCP_FLAG_ACK
#define TCP_FLAG_ACK  0x10
#endif
#ifndef TCP_FLAG_FIN
#define TCP_FLAG_FIN  0x01
#endif
#ifndef TCP_FLAG_RST
#define TCP_FLAG_RST  0x04
#endif
#ifndef TCP_FLAG_PSH
#define TCP_FLAG_PSH  0x08
#endif
#ifndef TCP_FLAG_URG
#define TCP_FLAG_URG  0x20
#endif

/* Port constants */
#define PORT_DNS     53
#define PORT_HTTP    80
#define PORT_HTTPS   443

#define MAX_COMM_LEN    16
#define MAX_PROBE_ID    64
#define MAX_FLOWS       4096
#define MAX_JSON_LEN    8192
#define RING_BUF_SIZE   4096
#define MAX_EVENTS_BATCH 64

#define RECONNECT_BASE_DELAY_MS   1000
#define RECONNECT_MAX_DELAY_MS    30000
#define RECONNECT_MAX_RETRIES     10

#define MAX_MEMORY_MB     100
#define POLL_INTERVAL_MS  5000
#define FLOW_CLEANUP_INTERVAL_S 60

struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  ip_version;   /* 4 or 6 */
    __u8  _pad[2];
};

struct flow_value_t {
    __u64 bytes;
    __u64 packets;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 pid;
    char  comm[MAX_COMM_LEN];
    __u16 max_pkt_size;
    __u16 min_pkt_size;
    __u32 tcp_flags_seen;  /* bitmask of all TCP flags seen */
};

struct flow_event_t {
    __u64 timestamp_ns;
    char  probe_id[MAX_PROBE_ID];
    char  category[16];
    char  event_type[16];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    char  protocol[8];
    __u8  ip_version;     /* 4 or 6 */
    __u8  tcp_flags;      /* SYN/ACK/FIN/RST bitmask */
    __u8  payload_type;   /* 0=none, 1=HTTP_REQ, 2=HTTP_RESP */
    __u8  anomaly;        /* 0=normal, 1=spike, 2=port_scan */
    __u16 pkt_len;
    __u64 bytes;
    __u64 packets;
    __u64 latency_us;     /* SYN→SYN-ACK latency in microseconds */
    __u64 bandwidth_bps;  /* instantaneous bandwidth in bits/sec */
    __u32 pid;
    char  service[32];
    char  details[128];
    char  tags[64];
} __attribute__((packed));

struct host_metric_t {
    __u64 timestamp_ns;
    char  probe_id[MAX_PROBE_ID];
    double cpu_percent;
    double memory_percent;
    double disk_percent;
    __u64 net_rx_bytes;
    __u64 net_tx_bytes;
    __u64 disk_read_bytes;
    __u64 disk_write_bytes;
} __attribute__((packed));

struct proc_net_entry {
    __u32 local_ip;
    __u16 local_port;
    __u32 remote_ip;
    __u16 remote_port;
    __u8  state;
    __u8  protocol;
    __u8  ip_version;
    __u64 rx_queue;
    __u64 tx_queue;
    __u32 uid;
    __u32 inode;
};

#define NS_TO_SEC(ns)   ((ns) / 1000000000ULL)
#define NS_TO_MS(ns)    ((ns) / 1000000ULL)
#define MS_TO_NS(ms)    ((__u64)(ms) * 1000000ULL)
#define IS_MULTICAST(ip) (((ip) & 0xF0000000) == 0xE0000000)
#define IS_LOOPBACK(ip) (((ip) & 0xFF000000) == 0x7F000000)

static inline void ip_to_str(__u32 ip, char *buf, int buflen) {
    unsigned char *b = (unsigned char *)&ip;
    snprintf(buf, buflen, "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
}

#endif /* _STB_COMMON_H */
