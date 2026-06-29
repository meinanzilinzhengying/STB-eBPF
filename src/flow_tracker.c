#include "flow_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct flow_record {
    struct flow_key_t key;
    struct flow_value_t value;
    __u64 prev_rx_queue;
    __u64 prev_tx_queue;
    int active;
};

struct flow_tracker {
    struct flow_record *records;
    int max_flows;
    struct flow_event_t *events;
    int event_count;
    int max_events;
    int active_count;
};

static __u64 now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

struct flow_tracker *flow_tracker_create(int max_flows) {
    struct flow_tracker *ft = calloc(1, sizeof(*ft));
    if (!ft) return NULL;
    ft->records = calloc(max_flows, sizeof(struct flow_record));
    ft->events = calloc(max_flows * 2, sizeof(struct flow_event_t));
    if (!ft->records || !ft->events) {
        free(ft->records); free(ft->events); free(ft);
        return NULL;
    }
    ft->max_flows = max_flows;
    ft->max_events = max_flows * 2;
    return ft;
}

void flow_tracker_destroy(struct flow_tracker *ft) {
    if (!ft) return;
    free(ft->records);
    free(ft->events);
    free(ft);
}

static struct flow_record *find_record(struct flow_tracker *ft,
                                       const struct flow_key_t *key) {
    for (int i = 0; i < ft->max_flows; i++) {
        if (ft->records[i].active &&
            memcmp(&ft->records[i].key, key, sizeof(*key)) == 0) {
            return &ft->records[i];
        }
    }
    for (int i = 0; i < ft->max_flows; i++) {
        if (!ft->records[i].active) {
            ft->records[i].key = *key;
            ft->records[i].active = 1;
            ft->records[i].value.first_seen_ns = now_ns();
            ft->active_count++;
            return &ft->records[i];
        }
    }
    return NULL;
}

static void add_event(struct flow_tracker *ft, const struct flow_event_t *ev) {
    if (ft->event_count < ft->max_events) {
        ft->events[ft->event_count++] = *ev;
    }
}

int flow_tracker_update(struct flow_tracker *ft,
                        struct proc_net_entry *entries, int count) {
    __u64 ts = now_ns();

    for (int i = 0; i < count; i++) {
        struct flow_key_t key = {
            .src_ip = entries[i].local_ip,
            .dst_ip = entries[i].remote_ip,
            .src_port = entries[i].local_port,
            .dst_port = entries[i].remote_port,
            .protocol = entries[i].protocol,
        };

        struct flow_record *rec = find_record(ft, &key);
        if (!rec) continue;

        __u64 rx_delta = 0, tx_delta = 0;
        if (entries[i].rx_queue >= rec->prev_rx_queue)
            rx_delta = entries[i].rx_queue - rec->prev_rx_queue;
        if (entries[i].tx_queue >= rec->prev_tx_queue)
            tx_delta = entries[i].tx_queue - rec->prev_tx_queue;
        __u64 delta_bytes = rx_delta + tx_delta;

        rec->prev_rx_queue = entries[i].rx_queue;
        rec->prev_tx_queue = entries[i].tx_queue;
        rec->value.bytes += delta_bytes;
        rec->value.packets += (delta_bytes > 0) ? 1 : 0;
        rec->value.last_seen_ns = ts;

        if (delta_bytes > 0) {
            struct flow_event_t ev = {0};
            ev.timestamp_ns = ts;
            strncpy(ev.category, CAT_NETWORK, sizeof(ev.category) - 1);
            strncpy(ev.event_type, EVT_FLOW, sizeof(ev.event_type) - 1);
            ev.src_ip = key.src_ip;
            ev.dst_ip = key.dst_ip;
            ev.src_port = key.src_port;
            ev.dst_port = key.dst_port;
            ev.bytes = delta_bytes;
            ev.packets = 1;

            /* Protocol string mapping */
            switch (entries[i].protocol) {
                case 6:  strncpy(ev.protocol, PROTO_TCP, sizeof(ev.protocol) - 1); break;
                case 17: strncpy(ev.protocol, PROTO_UDP, sizeof(ev.protocol) - 1); break;
                case 1:  strncpy(ev.protocol, PROTO_ICMP, sizeof(ev.protocol) - 1); break;
                default: snprintf(ev.protocol, sizeof(ev.protocol), "%d", entries[i].protocol); break;
            }

            if (IS_MULTICAST(key.dst_ip)) {
                strncpy(ev.tags, "iptv,multicast", sizeof(ev.tags) - 1);
                strncpy(ev.service, "IPTV", sizeof(ev.service) - 1);
            }

            add_event(ft, &ev);
        }
    }
    return 0;
}

void flow_tracker_update_single(struct flow_tracker *ft,
                                const struct flow_key_t *key,
                                __u64 bytes, const char *probe_id) {
    __u64 ts = now_ns();
    struct flow_record *rec = find_record(ft, key);
    if (!rec) return;

    rec->value.bytes += bytes;
    rec->value.packets += 1;
    rec->value.last_seen_ns = ts;

    struct flow_event_t ev = {0};
    ev.timestamp_ns = ts;
    strncpy(ev.probe_id, probe_id, sizeof(ev.probe_id) - 1);
    strncpy(ev.category, CAT_NETWORK, sizeof(ev.category) - 1);
    strncpy(ev.event_type, EVT_FLOW, sizeof(ev.event_type) - 1);
    ev.src_ip = key->src_ip;
    ev.dst_ip = key->dst_ip;
    ev.src_port = key->src_port;
    ev.dst_port = key->dst_port;
    ev.bytes = bytes;
    ev.packets = 1;

    /* Protocol string mapping */
    switch (key->protocol) {
        case 6:  strncpy(ev.protocol, PROTO_TCP, sizeof(ev.protocol) - 1); break;
        case 17: strncpy(ev.protocol, PROTO_UDP, sizeof(ev.protocol) - 1); break;
        case 1:  strncpy(ev.protocol, PROTO_ICMP, sizeof(ev.protocol) - 1); break;
        default: snprintf(ev.protocol, sizeof(ev.protocol), "%d", key->protocol); break;
    }

    if (IS_MULTICAST(key->dst_ip)) {
        strncpy(ev.tags, "iptv,multicast", sizeof(ev.tags) - 1);
        strncpy(ev.service, "IPTV", sizeof(ev.service) - 1);
    }

    add_event(ft, &ev);
}

int flow_tracker_get_events(struct flow_tracker *ft,
                            struct flow_event_t *events, int max_events) {
    int n = ft->event_count < max_events ? ft->event_count : max_events;
    memcpy(events, ft->events, n * sizeof(struct flow_event_t));
    return n;
}

void flow_tracker_flush(struct flow_tracker *ft) {
    ft->event_count = 0;
}

void flow_tracker_cleanup(struct flow_tracker *ft, __u64 max_age_ns) {
    if (!ft) return;
    __u64 ts = now_ns();
    int cleaned = 0;

    for (int i = 0; i < ft->max_flows; i++) {
        if (ft->records[i].active &&
            ft->records[i].value.last_seen_ns > 0 &&
            (ts - ft->records[i].value.last_seen_ns) > max_age_ns) {
            ft->records[i].active = 0;
            ft->active_count--;
            cleaned++;
        }
    }

    if (cleaned > 0) {
        printf("[FLOW] Cleaned %d stale flows (active: %d)\n",
               cleaned, ft->active_count);
    }
}

void flow_tracker_get_stats(struct flow_tracker *ft,
                            int *active_flows, int *total_events) {
    if (active_flows) *active_flows = ft->active_count;
    if (total_events) *total_events = ft->event_count;
}

/**
 * flow_tracker_check_tcp_retransmit - Detect TCP retransmissions and duplicate ACKs
 *
 * Algorithm:
 * 1. For data packets (ACK not set or has payload): compare seq with expected
 *    - seq < expected → retransmission
 *    - seq > expected → out-of-order (future improvement)
 *    - seq == expected → normal, update expected = seq + payload_len
 * 2. For pure ACK packets (ACK set, no payload):
 *    - If same ACK as previous → duplicate ACK (possible loss indication)
 * 3. SYN/FIN consume one sequence number
 */
int flow_tracker_check_tcp_retransmit(struct flow_tracker *ft,
                                       const struct flow_key_t *key,
                                       __u32 seq_num, __u16 pkt_len,
                                       __u8 tcp_flags,
                                       int *is_retransmit, int *is_dup_ack) {
    if (!ft || !key || !is_retransmit || !is_dup_ack) return -1;
    *is_retransmit = 0;
    *is_dup_ack = 0;

    struct flow_record *rec = find_record(ft, key);
    if (!rec) return -1;

    /* SYN and FIN consume one sequence number */
    int consumes_seq = (tcp_flags & TCP_FLAG_SYN) || (tcp_flags & TCP_FLAG_FIN);
    int has_ack = (tcp_flags & TCP_FLAG_ACK);
    int has_data = (pkt_len > 0 && !has_ack) || (pkt_len > 0 && has_ack);

    /* Track last ACK for duplicate detection */
    static __u32 last_ack_per_flow[4096];
    static int flow_idx = 0;

    if (consumes_seq) {
        /* SYN/FIN: just advance expected sequence */
        if (rec->value.seq_expected == 0) {
            /* First SYN: initialize expected sequence */
            rec->value.seq_expected = seq_num + 1;
        } else {
            rec->value.seq_expected = seq_num + 1;
        }
        return 0;
    }

    if (has_data || (!has_ack && pkt_len > 0)) {
        /* Data packet: check for retransmission */
        if (rec->value.seq_expected != 0 && seq_num < rec->value.seq_expected) {
            /* Retransmission: sequence number is behind expected */
            *is_retransmit = 1;
            rec->value.retransmits++;
            return 0;
        }
        /* Normal packet: update expected sequence */
        if (pkt_len > 0) {
            rec->value.seq_expected = seq_num + pkt_len;
        }
    }

    if (has_ack && pkt_len == 0) {
        /* Pure ACK: check for duplicate */
        int idx = flow_idx % 4096;
        if (last_ack_per_flow[idx] == seq_num && seq_num != 0) {
            *is_dup_ack = 1;
            rec->value.dup_acks++;
        }
        last_ack_per_flow[idx] = seq_num;
        flow_idx++;
    }

    return 0;
}
