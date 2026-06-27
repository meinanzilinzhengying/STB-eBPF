#include "packet_parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

/* Undefine TCP flags from common.h to avoid conflict with linux/tcp.h enum */
#undef TCP_FLAG_SYN
#undef TCP_FLAG_ACK
#undef TCP_FLAG_FIN
#undef TCP_FLAG_RST
#undef TCP_FLAG_PSH
#undef TCP_FLAG_URG

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <time.h>

/* Android NDK uses __kernel_udphdr, define udphdr as alias */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

/* Redefine our simple TCP flags */
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_URG  0x20

int packet_parse_raw(const void *data, int len, struct pkt_event_t *evt) {
    if (!data || !evt || len < 14) return 0;

    const unsigned char *p = (const unsigned char *)data;

    /* Parse Ethernet header */
    __u16 eth_proto = (p[12] << 8) | p[13];

    if (eth_proto == ETH_P_IP) {
        /* ===== IPv4 ===== */
        if (len < 14 + 20) return 0;
        const struct iphdr *ip = (const struct iphdr *)(p + 14);

        if (ntohs(ip->frag_off) & 0x1FFF) return 0;

        evt->src_ip = ip->saddr;
        evt->dst_ip = ip->daddr;
        evt->protocol = ip->protocol;
        evt->ip_version = 4;

        int ip_hdr_len = ip->ihl * 4;
        int transport_offset = 14 + ip_hdr_len;

        if (ip->protocol == IPPROTO_TCP) {
            if (len < transport_offset + 20) return 0;
            const struct tcphdr *tcp = (const struct tcphdr *)(p + transport_offset);
            evt->src_port = ntohs(tcp->source);
            evt->dst_port = ntohs(tcp->dest);

            __u8 flags = 0;
            if (tcp->syn) flags |= TCP_FLAG_SYN;
            if (tcp->ack) flags |= TCP_FLAG_ACK;
            if (tcp->fin) flags |= TCP_FLAG_FIN;
            if (tcp->rst) flags |= TCP_FLAG_RST;
            if (tcp->psh) flags |= TCP_FLAG_PSH;
            if (tcp->urg) flags |= TCP_FLAG_URG;
            evt->tcp_flags = flags;

        } else if (ip->protocol == IPPROTO_UDP) {
            if (len < transport_offset + 8) return 0;
            const struct udphdr *udp = (const struct udphdr *)(p + transport_offset);
            evt->src_port = ntohs(udp->source);
            evt->dst_port = ntohs(udp->dest);

        } else if (ip->protocol == IPPROTO_ICMP) {
            if (len < transport_offset + 8) return 0;
            const struct icmphdr *icmp = (const struct icmphdr *)(p + transport_offset);
            evt->src_port = 0;
            evt->dst_port = (__u16)icmp->type;

        } else {
            evt->src_port = 0;
            evt->dst_port = 0;
        }

        return 1;

    } else if (eth_proto == ETH_P_IPV6) {
        /* ===== IPv6 ===== */
        if (len < 14 + 40) return 0;
        const struct ipv6hdr *ip6 = (const struct ipv6hdr *)(p + 14);

        /* Map to IPv4-compatible (last 32 bits) */
        evt->src_ip = *((const __u32 *)&ip6->saddr.s6_addr[12]);
        evt->dst_ip = *((const __u32 *)&ip6->daddr.s6_addr[12]);
        evt->protocol = ip6->nexthdr;
        evt->ip_version = 6;

        int transport_offset = 14 + 40;

        if (ip6->nexthdr == IPPROTO_TCP) {
            if (len < transport_offset + 20) return 0;
            const struct tcphdr *tcp = (const struct tcphdr *)(p + transport_offset);
            evt->src_port = ntohs(tcp->source);
            evt->dst_port = ntohs(tcp->dest);

            __u8 flags = 0;
            if (tcp->syn) flags |= TCP_FLAG_SYN;
            if (tcp->ack) flags |= TCP_FLAG_ACK;
            if (tcp->fin) flags |= TCP_FLAG_FIN;
            if (tcp->rst) flags |= TCP_FLAG_RST;
            evt->tcp_flags = flags;

        } else if (ip6->nexthdr == IPPROTO_UDP) {
            if (len < transport_offset + 8) return 0;
            const struct udphdr *udp = (const struct udphdr *)(p + transport_offset);
            evt->src_port = ntohs(udp->source);
            evt->dst_port = ntohs(udp->dest);

        } else if (ip6->nexthdr == IPPROTO_ICMPV6) {
            evt->src_port = 0;
            evt->dst_port = 0;

        } else {
            evt->src_port = 0;
            evt->dst_port = 0;
        }

        return 1;
    }

    return 0;
}

void packet_to_flow_event(const struct pkt_event_t *pkt,
                          const char *probe_id,
                          struct flow_event_t *flow) {
    memset(flow, 0, sizeof(*flow));

    flow->timestamp_ns = pkt->timestamp_ns;
    strncpy(flow->probe_id, probe_id, sizeof(flow->probe_id) - 1);
    flow->src_ip = pkt->src_ip;
    flow->dst_ip = pkt->dst_ip;
    flow->src_port = pkt->src_port;
    flow->dst_port = pkt->dst_port;
    flow->tcp_flags = pkt->tcp_flags;
    flow->pkt_len = pkt->pkt_len;
    flow->bytes = pkt->pkt_len;
    flow->packets = 1;
    flow->pid = pkt->pid;
    flow->ip_version = pkt->ip_version;
    flow->payload_type = pkt->payload_type;
    flow->latency_us = pkt->latency_us;

    /* Protocol string */
    if (pkt->protocol == IPPROTO_TCP)
        strncpy(flow->protocol, PROTO_TCP, sizeof(flow->protocol) - 1);
    else if (pkt->protocol == IPPROTO_UDP)
        strncpy(flow->protocol, PROTO_UDP, sizeof(flow->protocol) - 1);
    else if (pkt->protocol == IPPROTO_ICMP)
        strncpy(flow->protocol, PROTO_ICMP, sizeof(flow->protocol) - 1);
    else
        snprintf(flow->protocol, sizeof(flow->protocol), "%d", pkt->protocol);

    /* Detect DNS (UDP port 53) */
    if (pkt->protocol == IPPROTO_UDP &&
        (pkt->src_port == PORT_DNS || pkt->dst_port == PORT_DNS)) {
        strncpy(flow->category, CAT_DNS, sizeof(flow->category) - 1);
        if (pkt->dst_port == PORT_DNS)
            strncpy(flow->event_type, EVT_DNS_QUERY, sizeof(flow->event_type) - 1);
        else
            strncpy(flow->event_type, EVT_DNS_REPLY, sizeof(flow->event_type) - 1);
        strncpy(flow->tags, "dns", sizeof(flow->tags) - 1);
        return;
    }

    /* Detect ICMP */
    if (pkt->protocol == IPPROTO_ICMP) {
        strncpy(flow->category, CAT_ICMP, sizeof(flow->category) - 1);
        if (pkt->dst_port == 8) {
            strncpy(flow->event_type, EVT_ICMP_ECHO, sizeof(flow->event_type) - 1);
            strncpy(flow->service, "ping", sizeof(flow->service) - 1);
        }
        strncpy(flow->tags, "icmp", sizeof(flow->tags) - 1);
        return;
    }

    /* Detect IPTV multicast */
    if (IS_MULTICAST(pkt->dst_ip)) {
        strncpy(flow->tags, "iptv,multicast", sizeof(flow->tags) - 1);
        strncpy(flow->service, "IPTV", sizeof(flow->service) - 1);
        strncpy(flow->category, CAT_IPTV, sizeof(flow->category) - 1);
        return;
    }

    /* Detect HTTP from payload type */
    if (pkt->payload_type == PAYLOAD_HTTP_REQ) {
        strncpy(flow->service, "HTTP", sizeof(flow->service) - 1);
        strncpy(flow->tags, "http,request", sizeof(flow->tags) - 1);
    } else if (pkt->payload_type == PAYLOAD_HTTP_RESP) {
        strncpy(flow->service, "HTTP", sizeof(flow->service) - 1);
        strncpy(flow->tags, "http,response", sizeof(flow->tags) - 1);
    } else if (pkt->protocol == IPPROTO_TCP &&
               (pkt->src_port == PORT_HTTP || pkt->dst_port == PORT_HTTP ||
                pkt->src_port == PORT_HTTPS || pkt->dst_port == PORT_HTTPS)) {
        strncpy(flow->service, "HTTP", sizeof(flow->service) - 1);
    }

    /* TCP connection lifecycle events */
    if (pkt->tcp_flags & TCP_FLAG_SYN) {
        strncpy(flow->event_type, EVT_CONNECT, sizeof(flow->event_type) - 1);
        return;
    }
    if (pkt->tcp_flags & TCP_FLAG_FIN || pkt->tcp_flags & TCP_FLAG_RST) {
        strncpy(flow->event_type, EVT_DISCONNECT, sizeof(flow->event_type) - 1);
        return;
    }

    /* Default: network flow */
    strncpy(flow->category, CAT_NETWORK, sizeof(flow->category) - 1);
    strncpy(flow->event_type, EVT_FLOW, sizeof(flow->event_type) - 1);
}
