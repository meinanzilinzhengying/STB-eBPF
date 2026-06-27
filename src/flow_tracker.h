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
void flow_tracker_get_stats(struct flow_tracker *ft,
                            int *active_flows, int *total_events);

#endif
