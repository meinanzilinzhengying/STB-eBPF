/**
 * main.c - STB eBPF Probe v4.2 Entry Point
 *
 * Architecture:
 *   Primary: BPF socket filter → packet capture → flow aggregation
 *   Fallback: /proc/net polling → connection tracking
 *
 * eBPF captures ALL IPv4+IPv6 packets via AF_PACKET raw socket.
 * Includes: HTTP detection, DNS, ICMP, TCP state, latency, anomaly detection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <net/ethernet.h>
#include <sys/resource.h>

#include "config.h"
#include "runtime_config.h"
#include "bpf_loader.h"
#include "packet_parser.h"
#include "proc_net.h"
#include "flow_tracker.h"
#include "host_metrics.h"
#include "anomaly.h"
#include "serializer.h"
#include "tcp_client.h"
#include "../include/common.h"

/**
 * parse_dns_payload - Parse DNS query/reply from raw UDP payload
 *
 * @payload: Pointer to DNS payload (after UDP header)
 * @len: Payload length
 * @flow: Flow event to enrich with DNS info
 * @is_reply: 1 if this is a DNS reply (src_port == 53)
 *
 * Extracts: query name, query type, response code
 */
static void parse_dns_payload(const unsigned char *payload, int len,
                              struct flow_event_t *flow, int is_reply) {
    if (!payload || len < 12 || !flow) return;

    /* DNS header */
    unsigned short id = (payload[0] << 8) | payload[1];
    unsigned short flags = (payload[2] << 8) | payload[3];
    unsigned short qdcount = (payload[4] << 8) | payload[5];
    unsigned short ancount = (payload[6] << 8) | payload[7];

    (void)id;

    if (is_reply) {
        /* Response code: RCODE (bits 0-3 of flags) */
        int rcode = flags & 0x0F;
        snprintf(flow->details, sizeof(flow->details),
                 "dns_reply:rcode=%d,ancount=%d", rcode, ancount);
    } else if (qdcount > 0) {
        /* Parse query name */
        int offset = 12;
        char name[256] = {0};
        int name_len = 0;
        int jumped = 0;

        while (offset < len && payload[offset] != 0 && !jumped) {
            int label_len = payload[offset];
            if (label_len >= 0xC0) {
                /* Compression pointer */
                jumped = 1;
                break;
            }
            offset++;
            if (offset + label_len > len) break;
            if (name_len > 0 && name_len < 255) {
                name[name_len++] = '.';
            }
            for (int i = 0; i < label_len && name_len < 255; i++) {
                name[name_len++] = payload[offset + i];
            }
            offset += label_len;
        }
        name[name_len] = '\0';

        /* Query type (after name + null byte + 2 bytes compression) */
        int type_offset = offset + 1;
        if (!jumped && type_offset + 1 < len) {
            unsigned short qtype = (payload[type_offset] << 8) | payload[type_offset + 1];
            const char *type_str = "UNKNOWN";
            switch (qtype) {
                case 1: type_str = "A"; break;
                case 28: type_str = "AAAA"; break;
                case 5: type_str = "CNAME"; break;
                case 12: type_str = "PTR"; break;
                case 15: type_str = "MX"; break;
                case 16: type_str = "TXT"; break;
                case 33: type_str = "SRV"; break;
            }
            snprintf(flow->details, sizeof(flow->details),
                     "dns_query:name=%s,type=%s", name, type_str);
        } else {
            snprintf(flow->details, sizeof(flow->details),
                     "dns_query:name=%s", name);
        }
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <net/ethernet.h>
#include <sys/resource.h>

#include "config.h"
#include "runtime_config.h"
#include "bpf_loader.h"
#include "packet_parser.h"
#include "proc_net.h"
#include "flow_tracker.h"
#include "host_metrics.h"
#include "anomaly.h"
#include "serializer.h"
#include "tcp_client.h"
#include "../include/common.h"

static volatile int g_stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

/* Read BPF perf_buffer events */
static int read_bpf_events(struct bpf_loader_status *bpf_status,
                           struct flow_tracker *tracker,
                           const char *probe_id) {
    if (!bpf_status || bpf_status->perf_map_fd < 0) return 0;

    unsigned char perf_buf[32 * 1024];
    int nr_events = 0;

    int ret = bpf_loader_read_perf_events(bpf_status, perf_buf,
                                           sizeof(perf_buf), &nr_events);
    if (ret <= 0 || nr_events == 0) return 0;

    int event_size = sizeof(struct pkt_event_t);
    int count = 0;

    for (int i = 0; i < nr_events; i++) {
        struct pkt_event_t *pkt = (struct pkt_event_t *)(perf_buf + i * event_size);

        if (pkt->timestamp_ns == 0) continue;

        struct flow_event_t flow;
        packet_to_flow_event(pkt, probe_id, &flow);

        struct flow_key_t key = {
            .src_ip = pkt->src_ip,
            .dst_ip = pkt->dst_ip,
            .src_port = pkt->src_port,
            .dst_port = pkt->dst_port,
            .protocol = pkt->protocol,
            .ip_version = pkt->ip_version,
        };
        flow_tracker_update_single(tracker, &key, pkt->pkt_len, probe_id);
        count++;
    }

    return count;
}

/* Read raw packets from AF_PACKET socket and parse */
static int read_raw_packets(int sock_fd,
                            struct flow_tracker *tracker,
                            const char *probe_id) {
    unsigned char pkt_buf[2048];
    int pkt_count = 0;

    while (!g_stop) {
        int len = recvfrom(sock_fd, pkt_buf, sizeof(pkt_buf),
                           MSG_DONTWAIT, NULL, NULL);
        if (len <= 0) break;

        struct pkt_event_t pkt = {0};
        pkt.timestamp_ns = 0;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        pkt.timestamp_ns = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        if (packet_parse_raw(pkt_buf, len, &pkt)) {
            struct flow_event_t flow;
            packet_to_flow_event(&pkt, probe_id, &flow);

            /* Directly add to tracker's event buffer */
            struct flow_key_t key = {
                .src_ip = pkt.src_ip,
                .dst_ip = pkt.dst_ip,
                .src_port = pkt.src_port,
                .dst_port = pkt.dst_port,
                .protocol = pkt.protocol,
            };
            /* Update flow tracker (simplified: just emit event) */
            flow_tracker_update_single(tracker, &key, pkt.pkt_len, probe_id);
            pkt_count++;
        }
    }

    return pkt_count;
}

int main(int argc, char *argv[]) {
    struct stb_config cfg;
    config_load_from_env(&cfg);

    const char *ifname = "eth0";
    const char *bpf_path = "./bpf/stb_socket_filter.bpf.o";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("STB eBPF Probe v4.2 - eBPF Network Monitor\n");
            printf("Usage: %s [-i interface] [-b bpf_obj] [-v] [-h]\n", argv[0]);
            printf("Env: STB_RELAY_IP, STB_RELAY_PORT, STB_PROBE_ID, STB_IFACE\n");
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0) {
            printf("STB eBPF Probe v4.2 (eBPF primary, IPv4+IPv6, anomaly detection)\n");
            return 0;
        }
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            ifname = argv[++i];
        }
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bpf_path = argv[++i];
        }
    }

    /* Allow env override for interface */
    const char *env_iface = getenv("STB_IFACE");
    if (env_iface && env_iface[0]) ifname = env_iface;

    printf("=============================================\n");
    printf("STB eBPF Probe v4.2 - eBPF Network Monitor\n");
    printf("Relay: %s:%d\n", cfg.relay_server_ip, cfg.relay_server_port);
    printf("Probe ID: %s\n", cfg.probe_id);
    printf("Interface: %s\n", ifname);
    printf("Protocols: IPv4+IPv6, TCP+UDP+ICMP+DNS+HTTP\n");
    printf("Features: latency, bandwidth, anomaly detection\n");
    printf("Mode: eBPF socket filter + /proc/net fallback\n");
    printf("=============================================\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Initialize modules */
    struct flow_tracker *tracker = flow_tracker_create(MAX_FLOWS);
    if (!tracker) { fprintf(stderr, "Failed to create flow tracker\n"); return 1; }

    struct tcp_client *tcp = tcp_client_init(cfg.relay_server_ip,
                                              cfg.relay_server_port, 1);
    if (!tcp) { fprintf(stderr, "Failed to create TCP client\n"); return 1; }
    tcp_client_connect(tcp);

    struct anomaly_detector *anomaly = anomaly_detector_create();
    if (!anomaly) { fprintf(stderr, "Failed to create anomaly detector\n"); return 1; }

    /* Try to load BPF socket filter */
    struct bpf_loader_status bpf_status;
    int use_bpf = 0;

    if (bpf_loader_init(ifname, bpf_path, &bpf_status) == 0) {
        use_bpf = 1;
        printf("[INFO] eBPF socket filter active on %s\n", ifname);
    } else {
        printf("[WARN] eBPF not available: %s\n", bpf_status.error);
        printf("[INFO] Falling back to /proc/net polling\n");
    }

    /* /proc/net buffers (used in both modes) */
    struct proc_net_entry entries[MAX_FLOWS];
    struct flow_event_t events[MAX_FLOWS * 2];
    struct host_metric_t metric;
    char json_buf[MAX_JSON_LEN * 16];

    __u64 last_metric_ns = 0;
    __u64 total_events = 0;
    __u64 total_packets = 0;

    printf("[INFO] Starting main loop...\n");

    while (!g_stop) {
        if (use_bpf) {
            /* ===== eBPF Mode ===== */
            int pkt_this_round = 0;

            /* Primary: read from perf buffer (BPF-enriched events) */
            if (bpf_status.perf_map_fd >= 0) {
                pkt_this_round += read_bpf_events(&bpf_status, tracker, cfg.probe_id);
                total_packets += pkt_this_round;
            }

            /* Fallback: read raw packets from AF_PACKET socket */
            if (pkt_this_round == 0) {
                unsigned char pkt_buf[2048];
                while (!g_stop && pkt_this_round < 1000) {
                    int len = recvfrom(bpf_status.socket_fd, pkt_buf, sizeof(pkt_buf),
                                       MSG_DONTWAIT, NULL, NULL);
                    if (len <= 0) break;

                    struct pkt_event_t pkt = {0};
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    pkt.timestamp_ns = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

                    if (packet_parse_raw(pkt_buf, len, &pkt)) {
                        struct flow_event_t flow;
                        packet_to_flow_event(&pkt, cfg.probe_id, &flow);

                        /* DNS payload parsing (UDP port 53) */
                        if (pkt.protocol == IPPROTO_UDP &&
                            (pkt.src_port == PORT_DNS || pkt.dst_port == PORT_DNS) &&
                            len > 42) {
                            /* Calculate DNS payload offset based on Ethernet header size.
                             * Standard: ETH(14) + IP(20) + UDP(8) = 42
                             * VLAN: ETH(14) + VLAN(4) + IP(20) + UDP(8) = 46
                             * We detect VLAN by checking if eth_proto at offset 12 is 0x8100 */
                            const unsigned char *eth = pkt_buf;
                            int eth_hdr_len = 14;
                            if (len >= 16 && eth[12] == 0x81 && eth[13] == 0x00) {
                                eth_hdr_len = 18; /* VLAN tagged */
                            }
                            int dns_offset = eth_hdr_len + 20 + 8; /* ETH + IP + UDP */
                            if (len > dns_offset) {
                                const unsigned char *dns_payload = pkt_buf + dns_offset;
                                int dns_len = len - dns_offset;
                                int is_reply = (pkt.src_port == PORT_DNS);
                                parse_dns_payload(dns_payload, dns_len, &flow, is_reply);
                            }
                        }

                        struct flow_key_t key = {
                            .src_ip = pkt.src_ip, .dst_ip = pkt.dst_ip,
                            .src_port = pkt.src_port, .dst_port = pkt.dst_port,
                            .protocol = pkt.protocol,
                            .ip_version = pkt.ip_version,
                        };
                        flow_tracker_update_single(tracker, &key, pkt.pkt_len, cfg.probe_id);

                        struct flow_event_t flow_check;
                        packet_to_flow_event(&pkt, cfg.probe_id, &flow_check);
                        anomaly_check_flow(anomaly, &flow_check);

                        pkt_this_round++;
                        total_packets++;
                    }
                }
            }

            /* Also poll /proc/net for connection state enrichment (IPv4 + IPv6) */
            int tcp4 = proc_net_read_tcp(entries, MAX_FLOWS / 4);
            int udp4 = proc_net_read_udp(entries + tcp4, MAX_FLOWS / 4 - tcp4);
            int tcp6 = proc_net_read_tcp6(entries + tcp4 + udp4, MAX_FLOWS / 4);
            int udp6 = proc_net_read_udp6(entries + tcp4 + udp4 + tcp6, MAX_FLOWS / 4 - tcp6);
            flow_tracker_update(tracker, entries, tcp4 + udp4 + tcp6 + udp6);

        } else {
            /* ===== /proc/net Fallback Mode (IPv4 + IPv6) ===== */
            int tcp4 = proc_net_read_tcp(entries, MAX_FLOWS / 4);
            int udp4 = proc_net_read_udp(entries + tcp4, MAX_FLOWS / 4 - tcp4);
            int tcp6 = proc_net_read_tcp6(entries + tcp4 + udp4, MAX_FLOWS / 4);
            int udp6 = proc_net_read_udp6(entries + tcp4 + udp4 + tcp6, MAX_FLOWS / 4 - tcp6);
            flow_tracker_update(tracker, entries, tcp4 + udp4 + tcp6 + udp6);
        }

        /* Host metrics every 30s */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        __u64 now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;

        struct host_metric_t *mp = NULL;
        if (now_ns - last_metric_ns >= 30000000000ULL) {
            host_metrics_collect(&metric, cfg.probe_id);
            mp = &metric;
            last_metric_ns = now_ns;

            /* Cleanup stale flows every 60s (alongside metrics) */
            flow_tracker_cleanup(tracker, FLOW_CLEANUP_INTERVAL_S * 1000000000ULL);
        }

        /* Serialize and send */
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

        /* Stats every 500 events */
        if (total_events > 0 && total_events % 500 == 0) {
            int active = 0, pending = 0;
            flow_tracker_get_stats(tracker, &active, &pending);
            printf("[STATS] mode=%s active_flows=%d events=%llu pkts=%llu\n",
                   use_bpf ? "eBPF" : "proc.net", active, total_events, total_packets);
            anomaly_detector_print_stats(anomaly);
        }

        usleep(POLL_INTERVAL_MS * 1000);
    }

    printf("[INFO] Shutting down (events=%llu packets=%llu)\n", total_events, total_packets);

    if (use_bpf) bpf_loader_cleanup(&bpf_status);
    anomaly_detector_destroy(anomaly);
    flow_tracker_destroy(tracker);
    tcp_client_cleanup(tcp);
    return 0;
}
