#ifndef _STB_SERIALIZER_H
#define _STB_SERIALIZER_H

#include "../include/common.h"

int serialize_flow_event(const struct flow_event_t *event,
                         const char *probe_id,
                         char *output, int output_size);

int serialize_host_metric(const struct host_metric_t *metric,
                          const char *probe_id,
                          char *output, int output_size);

int serialize_batch(const struct flow_event_t *flow_events, int flow_count,
                    const struct host_metric_t *metric,
                    const char *probe_id,
                    char *output, int output_size);

#endif
