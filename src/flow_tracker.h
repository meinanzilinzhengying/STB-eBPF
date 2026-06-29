#ifndef _STB_FLOW_TRACKER_H
#define _STB_FLOW_TRACKER_H

#include "../include/common.h"

struct flow_tracker;

struct flow_tracker *flow_tracker_create(int max_flows);
void flow_tracker_destroy(struct flow_tracker *ft);
int flow_tracker_update(struct flow_tracker *ft,
                        struct proc_net_entry *entries, int count);
void flow_tracker_update_single(struct flow_tracker *ft,
                                const struct flow_key_t *key,
                                __u64 bytes, const char *probe_id);
int flow_tracker_get_events(struct flow_tracker *ft,
                            struct flow_event_t *events, int max_events);
void flow_tracker_flush(struct flow_tracker *ft);
void flow_tracker_cleanup(struct flow_tracker *ft, __u64 max_age_ns);
void flow_tracker_get_stats(struct flow_tracker *ft,
                            int *active_flows, int *total_events);

/**
 * flow_tracker_check_tcp_retransmit - Check for TCP retransmission
 *
 * @ft: Flow tracker
 * @key: Flow key (5-tuple)
 * @seq_num: TCP sequence number from packet
 * @pkt_len: Packet payload length
 * @tcp_flags: TCP flags (SYN/ACK/FIN/RST)
 * @is_retransmit: Output: 1 if retransmission detected
 * @is_dup_ack: Output: 1 if duplicate ACK detected
 *
 * Returns: 0 on success
 */
int flow_tracker_check_tcp_retransmit(struct flow_tracker *ft,
                                       const struct flow_key_t *key,
                                       __u32 seq_num, __u16 pkt_len,
                                       __u8 tcp_flags,
                                       int *is_retransmit, int *is_dup_ack);

#endif
