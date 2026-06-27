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
        "\"protocol\":\"%s\","
        "\"bytes\":%llu,\"packets\":%llu,"
        "\"latency_ms\":%llu,"
        "\"service\":\"%s\",\"details\":\"%s\",\"tags\":\"%s\"}\n",
        (unsigned long long)event->timestamp_ns, probe_id,
        event->category, event->event_type,
        src, dst,
        event->src_port, event->dst_port,
        event->protocol,
        (unsigned long long)event->bytes,
        (unsigned long long)event->packets,
        (unsigned long long)event->latency_ms,
        event->service, event->details, event->tags);
}

int serialize_host_metric(const struct host_metric_t *metric,
                          const char *probe_id,
                          char *output, int output_size) {
    return snprintf(output, output_size,
        "{\"timestamp\":%llu,\"probe_id\":\"%s\","
        "\"category\":\"metrics\",\"event_type\":\"host_metrics\","
        "\"cpu\":%.1f,\"mem\":%.1f,\"disk\":%.1f,"
        "\"net_rx\":%llu,\"net_tx\":%llu}\n",
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

    for (int i = 0; i < flow_count && written < output_size - 1; i++) {
        int ret = serialize_flow_event(&flow_events[i], probe_id,
                                       output + written, output_size - written);
        if (ret < 0) break;
        written += ret;
    }

    if (metric && written < output_size - 1) {
        int ret = serialize_host_metric(metric, probe_id,
                                        output + written, output_size - written);
        if (ret > 0) written += ret;
    }

    return written;
}
