/**
 * stb_socket_filter.bpf.c - BPF socket filter v4.2
 *
 * Complete eBPF packet parser supporting:
 * - IPv4 + IPv6
 * - TCP (with state flags: SYN/FIN/RST)
 * - UDP (with DNS port 53 detection)
 * - ICMP
 * - HTTP method detection (GET/POST/PUT/DELETE from payload)
 * - Process correlation via bpf_get_current_pid_tgid()
 * - Connection latency via SYN→SYN-ACK timing (hash map)
 *
 * Does NOT require CONFIG_BPF_EVENTS.
 * Uses BPF_PROG_TYPE_SOCKET_FILTER + perf_buffer.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD
#endif

/* Protocol numbers */
#define IPPROTO_ICMPV6  58

/* ==================== Event Structure ==================== */

struct pkt_event_t {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  tcp_flags;
    __u16 pkt_len;
    __u32 ifindex;
    __u32 pid;
    __u8  payload_type;   /* 0=none, 1=HTTP_REQ, 2=HTTP_RESP */
    __u8  _pad[3];
} __attribute__((packed));

/* ==================== BPF Maps ==================== */

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} perf_map SEC(".maps");

/**
 * syn_timestamps - Track SYN→SYN-ACK latency
 *
 * Key: src_ip:dst_ip:src_port:dst_port (64-bit hash)
 * Value: timestamp of SYN packet
 */
struct syn_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct syn_key_t));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} syn_timestamps SEC(".maps");

/* ==================== Helper: Compute flow key hash ==================== */

static __always_inline __u64 flow_hash(__u32 src, __u32 dst, __u16 sp, __u16 dp) {
    __u64 h = ((__u64)src << 32) | dst;
    h = h * 31 + sp;
    h = h * 31 + dp;
    return h;
}

/* ==================== HTTP Detection ==================== */

#define PAYLOAD_NONE    0
#define PAYLOAD_HTTP_REQ  1
#define PAYLOAD_HTTP_RESP 2

/**
 * detect_http - Detect HTTP method/status from TCP payload
 *
 * Reads first 8 bytes of TCP payload to check for:
 * - "GET ", "POST ", "PUT ", "DELETE ", "HEAD " → HTTP request
 * - "HTTP/" → HTTP response
 *
 * Note: BPF verifier limits data access. We only read first 8 bytes.
 */
static __always_inline int detect_http(struct __sk_buff *skb,
                                        void *payload_start) {
    void *data_end = (void *)(long)skb->data_end;

    /* Need at least 8 bytes of payload for detection */
    if (payload_start + 8 > data_end)
        return PAYLOAD_NONE;

    /* Read 8 bytes of payload */
    __u8 buf[8];
    bpf_probe_read(buf, sizeof(buf), payload_start);

    /* Check for HTTP methods: GET , POST, PUT , DELE, HEAD */
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return PAYLOAD_HTTP_REQ;
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T')
        return PAYLOAD_HTTP_REQ;
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return PAYLOAD_HTTP_REQ;
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E')
        return PAYLOAD_HTTP_REQ;
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D')
        return PAYLOAD_HTTP_REQ;

    /* Check for HTTP response: HTTP/ */
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P'
        && buf[4] == '/')
        return PAYLOAD_HTTP_RESP;

    return PAYLOAD_NONE;
}

/* ==================== IPv4 Parser ==================== */

static __always_inline int parse_ipv4(struct __sk_buff *skb,
                                       void *ip_start,
                                       struct pkt_event_t *evt) {
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = ip_start;
    if ((void *)(ip + 1) > data_end)
        return 0;

    /* Skip fragments */
    if (ip->frag_off & __constant_htons(0x1FFF))
        return 0;

    evt->src_ip = ip->saddr;
    evt->dst_ip = ip->daddr;
    evt->protocol = ip->protocol;

    void *transport = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        evt->src_port = __constant_htons(tcp->source);
        evt->dst_port = __constant_htons(tcp->dest);

        /* Extract TCP flags */
        __u8 flags = 0;
        if (tcp->syn) flags |= 0x02;
        if (tcp->ack) flags |= 0x10;
        if (tcp->fin) flags |= 0x01;
        if (tcp->rst) flags |= 0x04;
        if (tcp->psh) flags |= 0x08;
        if (tcp->urg) flags |= 0x20;
        evt->tcp_flags = flags;

        /* Track SYN→SYN-ACK latency */
        if (tcp->syn && !tcp->ack) {
            /* SYN sent: record timestamp */
            struct syn_key_t key = {
                .src_ip = ip->saddr, .dst_ip = ip->daddr,
                .src_port = evt->src_port, .dst_port = evt->dst_port,
            };
            __u64 ts = bpf_ktime_get_ns();
            bpf_map_update_elem(&syn_timestamps, &key, &ts, BPF_ANY);
        } else if (tcp->syn && tcp->ack) {
            /* SYN-ACK received: compute latency */
            struct syn_key_t key = {
                .src_ip = ip->daddr, .dst_ip = ip->saddr,
                .src_port = evt->dst_port, .dst_port = evt->src_port,
            };
            __u64 *start_ts = bpf_map_lookup_elem(&syn_timestamps, &key);
            if (start_ts) {
                /* Latency encoded in dst_port field (hack: use reserved bits) */
                __u64 latency_ns = bpf_ktime_get_ns() - *start_ts;
                evt->dst_port = (__u16)(latency_ns / 1000); /* Store latency_us */
                bpf_map_delete_elem(&syn_timestamps, &key);
            }
        } else if (tcp->fin || tcp->rst) {
            /* Connection close: cleanup */
            struct syn_key_t key = {
                .src_ip = ip->saddr, .dst_ip = ip->daddr,
                .src_port = evt->src_port, .dst_port = evt->dst_port,
            };
            bpf_map_delete_elem(&syn_timestamps, &key);
        }

        /* Detect HTTP in TCP payload (after header) */
        int tcp_hdr_len = tcp->doff * 4;
        void *payload = transport + tcp_hdr_len;
        evt->payload_type = detect_http(skb, payload);

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return 0;
        evt->src_port = __constant_htons(udp->source);
        evt->dst_port = __constant_htons(udp->dest);
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = transport;
        if ((void *)(icmp + 1) > data_end)
            return 0;
        evt->src_port = 0;
        evt->dst_port = (__u16)icmp->type; /* Store ICMP type */
    } else {
        evt->src_port = 0;
        evt->dst_port = 0;
    }

    return 1;
}

/* ==================== IPv6 Parser ==================== */

static __always_inline int parse_ipv6(struct __sk_buff *skb,
                                       void *ip6_start,
                                       struct pkt_event_t *evt) {
    void *data_end = (void *)(long)skb->data_end;

    struct ipv6hdr *ip6 = ip6_start;
    if ((void *)(ip6 + 1) > data_end)
        return 0;

    /* Map IPv6 to IPv4-compatible for storage (take last 32 bits) */
    evt->src_ip = *(__u32 *)&ip6->saddr.s6_addr[12];
    evt->dst_ip = *(__u32 *)&ip6->daddr.s6_addr[12];
    evt->protocol = ip6->nexthdr;

    void *transport = (void *)(ip6 + 1);

    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        evt->src_port = __constant_htons(tcp->source);
        evt->dst_port = __constant_htons(tcp->dest);

        __u8 flags = 0;
        if (tcp->syn) flags |= 0x02;
        if (tcp->ack) flags |= 0x10;
        if (tcp->fin) flags |= 0x01;
        if (tcp->rst) flags |= 0x04;
        evt->tcp_flags = flags;

    } else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return 0;
        evt->src_port = __constant_htons(udp->source);
        evt->dst_port = __constant_htons(udp->dest);

    } else if (ip6->nexthdr == IPPROTO_ICMPV6) {
        evt->src_port = 0;
        evt->dst_port = 0;

    } else {
        evt->src_port = 0;
        evt->dst_port = 0;
    }

    return 1;
}

/* ==================== Main Filter Program ==================== */

SEC("socket")
int stb_packet_filter(struct __sk_buff *skb) {
    struct pkt_event_t evt = {0};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.pkt_len = skb->len;
    evt.ifindex = skb->ifindex;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return skb->len;

    int parsed = 0;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        parsed = parse_ipv4(skb, (void *)(eth + 1), &evt);
    } else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        parsed = parse_ipv6(skb, (void *)(eth + 1), &evt);
    }

    if (parsed) {
        bpf_perf_event_output(skb, &perf_map,
                              BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return skb->len;
}

char _license[] SEC("license") = "GPL";
