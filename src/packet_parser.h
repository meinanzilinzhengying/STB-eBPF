#ifndef _STB_PACKET_PARSER_H
#define _STB_PACKET_PARSER_H

#include "../include/common.h"

/**
 * pkt_event_t - Packet metadata from BPF or userspace parsing
 *
 * Identical to the BPF-side struct pkt_event_t.
 */
struct pkt_event_t {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[1];
    __u16 pkt_len;
    __u32 ifindex;
};

/**
 * packet_parse_raw - Parse raw Ethernet frame in userspace
 *
 * @data: Raw packet data (Ethernet frame)
 * @len: Packet length
 * @evt: Output event (zero-initialized)
 *
 * Returns: 1 if valid IPv4 packet parsed, 0 otherwise
 */
int packet_parse_raw(const void *data, int len, struct pkt_event_t *evt);

/**
 * packet_to_flow_event - Convert packet event to flow event
 *
 * @pkt: Packet event
 * @probe_id: Probe identifier
 * @flow: Output flow event
 */
void packet_to_flow_event(const struct pkt_event_t *pkt,
                          const char *probe_id,
                          struct flow_event_t *flow);

#endif
