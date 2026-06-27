#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "config.h"
#include "runtime_config.h"
#include "proc_net.h"
#include "flow_tracker.h"
#include "host_metrics.h"
#include "serializer.h"
#include "tcp_client.h"
#include "../include/common.h"

static volatile int g_stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

int main(int argc, char *argv[]) {
    struct stb_config cfg;
    config_load_from_env(&cfg);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("STB eBPF Probe v3.0 - Network Monitor\n");
            printf("Usage: %s [-v] [-h]\n", argv[0]);
            printf("Env: STB_RELAY_IP, STB_RELAY_PORT, STB_PROBE_ID\n");
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0) {
            printf("STB eBPF Probe v3.0\n");
            return 0;
        }
    }

    printf("========================================\n");
    printf("STB eBPF Probe v3.0 - Network Monitor\n");
    printf("Relay: %s:%d\n", cfg.relay_server_ip, cfg.relay_server_port);
    printf("Probe ID: %s\n", cfg.probe_id);
    printf("Poll interval: %dms\n", POLL_INTERVAL_MS);
    printf("========================================\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    struct flow_tracker *tracker = flow_tracker_create(MAX_FLOWS);
    if (!tracker) { fprintf(stderr, "Failed to create flow tracker\n"); return 1; }

    struct tcp_client *tcp = tcp_client_init(cfg.relay_server_ip,
                                              cfg.relay_server_port, 1);
    if (!tcp) { fprintf(stderr, "Failed to create TCP client\n"); return 1; }
    tcp_client_connect(tcp);

    struct proc_net_entry entries[MAX_FLOWS];
    struct flow_event_t events[MAX_FLOWS * 2];
    struct host_metric_t metric;
    char json_buf[MAX_JSON_LEN * 16];

    __u64 last_metric_ns = 0;
    __u64 total_events = 0;

    printf("[INFO] Starting main loop...\n");

    while (!g_stop) {
        int tcp_count = proc_net_read_tcp(entries, MAX_FLOWS);
        int udp_count = proc_net_read_udp(entries + tcp_count, MAX_FLOWS - tcp_count);
        int total_count = tcp_count + udp_count;

        flow_tracker_update(tracker, entries, total_count);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        __u64 now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;

        struct host_metric_t *mp = NULL;
        if (now_ns - last_metric_ns >= 30000000000ULL) {
            host_metrics_collect(&metric, cfg.probe_id);
            mp = &metric;
            last_metric_ns = now_ns;
        }

        int event_count = flow_tracker_get_events(tracker, events, MAX_FLOWS * 2);
        if (event_count > 0 || mp) {
            int json_len = serialize_batch(events, event_count, mp,
                                           cfg.probe_id, json_buf, sizeof(json_buf));
            flow_tracker_flush(tracker);

            if (json_len > 0) {
                if (!tcp_client_is_connected(tcp)) {
                    tcp_client_reconnect(tcp);
                }
                if (tcp_client_is_connected(tcp)) {
                    tcp_client_send(tcp, json_buf, json_len);
                    total_events += event_count;
                }
            }
        }

        if (total_events > 0 && total_events % 100 == 0) {
            int active = 0, pending = 0;
            flow_tracker_get_stats(tracker, &active, &pending);
            printf("[STATS] active_flows=%d total_events=%llu\n", active, total_events);
        }

        usleep(POLL_INTERVAL_MS * 1000);
    }

    printf("[INFO] Shutting down (total_events=%llu)\n", total_events);

    flow_tracker_destroy(tracker);
    tcp_client_cleanup(tcp);
    return 0;
}
