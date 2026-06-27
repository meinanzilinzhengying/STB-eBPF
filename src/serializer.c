#include "serializer.h"
#include <stdio.h>
#include <string.h>

int serialize_flow_event(const struct flow_event_t *event,
                         const char *probe_id,
                         char *output, int output_size) {
    char src[16], dst[16];
    ip_to_str(event->src_ip, src, sizeof(src));
    ip_to_str(event->dst_ip, dst, sizeof(dst));

    return snprintf(output, output_size,
        "{\"timestamp\":%llu,\"probe_id\":\"%s\","
        "\"category\":\"%s\",\"event_type\":\"%s\","
        "\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
        "\"src_port\":%u,\"dst_port\":%u,"
        "\"protocol\":\"%s\",\"ip_version\":%u,"
        "\"tcp_flags\":%u,\"pkt_len\":%u,"
        "\"bytes\":%llu,\"packets\":%llu,"
        "\"latency_us\":%llu,\"bandwidth_bps\":%llu,"
        "\"retransmits\":%u,\"dup_acks\":%u,"
        "\"anomaly\":%u,\"payload_type\":%u,\"pid\":%u,"
        "\"service\":\"%s\",\"details\":\"%s\",\"tags\":\"%s\"}",
        (unsigned long long)event->timestamp_ns, probe_id,
        event->category, event->event_type,
        src, dst,
        event->src_port, event->dst_port,
        event->protocol, event->ip_version,
        event->tcp_flags, event->pkt_len,
        (unsigned long long)event->bytes,
        (unsigned long long)event->packets,
        (unsigned long long)event->latency_us,
        (unsigned long long)event->bandwidth_bps,
        event->retransmits, event->dup_acks,
        event->anomaly, event->payload_type, event->pid,
        event->service, event->details, event->tags);
}

int serialize_host_metric(const struct host_metric_t *metric,
                          const char *probe_id,
                          char *output, int output_size) {
    return snprintf(output, output_size,
        "{\"timestamp\":%llu,\"probe_id\":\"%s\","
        "\"category\":\"metrics\",\"event_type\":\"host_metrics\","
        "\"cpu\":%.1f,\"mem\":%.1f,\"disk\":%.1f,"
        "\"net_rx\":%llu,\"net_tx\":%llu}",
        (unsigned long long)metric->timestamp_ns, probe_id,
        metric->cpu_percent, metric->memory_percent, metric->disk_percent,
        (unsigned long long)metric->net_rx_bytes,
        (unsigned long long)metric->net_tx_bytes);
}

int serialize_batch(const struct flow_event_t *flow_events, int flow_count,
                    const struct host_metric_t *metric,
                    const char *probe_id,
                    char *output, int output_size) {
    int written = 0;

    output[written++] = '[';
    int first = 1;

    for (int i = 0; i < flow_count && written < output_size - 2; i++) {
        if (!first) {
            output[written++] = ',';
        }
        int ret = serialize_flow_event(&flow_events[i], probe_id,
                                       output + written, output_size - written);
        if (ret < 0) break;
        written += ret;
        first = 0;
    }

    if (metric && written < output_size - 2) {
        if (!first) {
            output[written++] = ',';
        }
        int ret = serialize_host_metric(metric, probe_id,
                                        output + written, output_size - written);
        if (ret > 0) {
            written += ret;
            first = 0;
        }
    }

    output[written++] = ']';
    output[written] = '\0';

    return written;
}
