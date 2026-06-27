#include "packet_parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>

int packet_parse_raw(const void *data, int len, struct pkt_event_t *evt) {
    if (!data || !evt || len < 14) return 0;

    const unsigned char *p = (const unsigned char *)data;

    /* Parse Ethernet header */
    __u16 eth_proto = (p[12] << 8) | p[13];
    if (eth_proto != ETH_P_IP) return 0;

    /* Parse IP header */
    if (len < 14 + 20) return 0;
    const struct iphdr *ip = (const struct iphdr *)(p + 14);

    /* Skip fragments */
    if (ntohs(ip->frag_off) & 0x1FFF) return 0;

    evt->src_ip = ip->saddr;
    evt->dst_ip = ip->daddr;
    evt->protocol = ip->protocol;
    evt->pkt_len = (__u16)len;

    int ip_hdr_len = ip->ihl * 4;
    int transport_offset = 14 + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (len < transport_offset + 20) return 0;
        const struct tcphdr *tcp = (const struct tcphdr *)(p + transport_offset);
        evt->src_port = ntohs(tcp->source);
        evt->dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (len < transport_offset + 8) return 0;
        const struct udphdr *udp = (const struct udphdr *)(p + transport_offset);
        evt->src_port = ntohs(udp->source);
        evt->dst_port = ntohs(udp->dest);
    } else {
        evt->src_port = 0;
        evt->dst_port = 0;
    }

    return 1;
}

void packet_to_flow_event(const struct pkt_event_t *pkt,
                          const char *probe_id,
                          struct flow_event_t *flow) {
    memset(flow, 0, sizeof(*flow));

    flow->timestamp_ns = pkt->timestamp_ns;
    strncpy(flow->probe_id, probe_id, sizeof(flow->probe_id) - 1);
    strncpy(flow->category, CAT_NETWORK, sizeof(flow->category) - 1);
    strncpy(flow->event_type, EVT_FLOW, sizeof(flow->event_type) - 1);
    flow->src_ip = pkt->src_ip;
    flow->dst_ip = pkt->dst_ip;
    flow->src_port = pkt->src_port;
    flow->dst_port = pkt->dst_port;
    flow->bytes = pkt->pkt_len;
    flow->packets = 1;

    if (pkt->protocol == IPPROTO_TCP)
        strncpy(flow->protocol, "TCP", sizeof(flow->protocol) - 1);
    else if (pkt->protocol == IPPROTO_UDP)
        strncpy(flow->protocol, "UDP", sizeof(flow->protocol) - 1);
    else
        strncpy(flow->protocol, "OTHER", sizeof(flow->protocol) - 1);

    /* Detect IPTV multicast */
    if (IS_MULTICAST(pkt->dst_ip)) {
        strncpy(flow->tags, "iptv,multicast", sizeof(flow->tags) - 1);
        strncpy(flow->service, "IPTV", sizeof(flow->service) - 1);
    }
}
