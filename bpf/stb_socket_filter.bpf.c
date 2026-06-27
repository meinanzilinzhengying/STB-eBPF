/**
 * stb_socket_filter.bpf.c - BPF socket filter for packet capture
 *
 * Attached to AF_PACKET raw socket via SO_ATTACH_FILTER.
 * Captures all IPv4 packets, extracts flow metadata, pushes to perf_buffer.
 *
 * Does NOT require CONFIG_BPF_EVENTS (works on STB kernel 5.4).
 * Uses BPF_PROG_TYPE_SOCKET_FILTER which only needs BPF syscall support.
 *
 * Flow: ETH → IP → TCP/UDP → extract tuple → perf_event_output → userspace
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Ethernet protocol IDs */
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD
#endif

/* ==================== Event Structure ==================== */

/**
 * struct pkt_event_t - Packet metadata event
 *
 * Pushed to userspace via perf_buffer after BPF parsing.
 * Lightweight: only essential flow info, no packet payload.
 */
struct pkt_event_t {
    __u64 timestamp_ns;     /* bpf_ktime_get_ns() */
    __u32 src_ip;           /* Source IPv4 (network byte order) */
    __u32 dst_ip;           /* Destination IPv4 (network byte order) */
    __u16 src_port;         /* Source port (host byte order) */
    __u16 dst_port;         /* Destination port (host byte order) */
    __u8  protocol;         /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
    __u8  _pad[1];
    __u16 pkt_len;          /* Original packet length */
    __u32 ifindex;          /* Network interface index */
} __attribute__((packed));

/* ==================== BPF Maps ==================== */

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} perf_map SEC(".maps");

/* ==================== Packet Parsing ==================== */

/**
 * parse_packet - Parse Ethernet/IP/TCP/UDP headers
 *
 * @skb: Socket buffer context
 * @evt: Output event (zero-initialized)
 *
 * Returns: 1 on success (valid IPv4 packet), 0 to skip
 */
static __always_inline int parse_packet(struct __sk_buff *skb,
                                         struct pkt_event_t *evt) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    /* 1. Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    /* Only process IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    /* 2. Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    /* Skip fragmented packets (no transport header) */
    if (ip->frag_off & __constant_htons(0x1FFF))
        return 0;

    evt->src_ip = ip->saddr;
    evt->dst_ip = ip->daddr;
    evt->protocol = ip->protocol;
    evt->pkt_len = __constant_htons(skb->len);
    evt->ifindex = skb->ifindex;

    /* 3. Parse transport header */
    void *transport = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        evt->src_port = __constant_htons(tcp->source);
        evt->dst_port = __constant_htons(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return 0;
        evt->src_port = __constant_htons(udp->source);
        evt->dst_port = __constant_htons(udp->dest);
    } else {
        /* ICMP or other: no ports */
        evt->src_port = 0;
        evt->dst_port = 0;
    }

    return 1;
}

/* ==================== Socket Filter Program ==================== */

/**
 * stb_packet_filter - BPF socket filter entry point
 *
 * Attached to AF_PACKET raw socket. Parses each packet and
 * pushes metadata to perf_buffer for userspace processing.
 *
 * Returns: skb->len (pass packet through) or 0 (drop, but we pass all)
 *
 * Note: For BPF_PROG_TYPE_SOCKET_FILTER, the return value determines
 * how many bytes of the packet to capture. We return the full length.
 */
SEC("socket")
int stb_packet_filter(struct __sk_buff *skb) {
    struct pkt_event_t evt = {0};

    evt.timestamp_ns = bpf_ktime_get_ns();

    if (parse_packet(skb, &evt)) {
        /* Push event to userspace via perf_buffer */
        bpf_perf_event_output(skb, &perf_map,
                              BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    /* Pass entire packet through (return full length) */
    return skb->len;
}

char _license[] SEC("license") = "GPL";
