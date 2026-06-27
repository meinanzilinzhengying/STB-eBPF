#include "anomaly.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Per-source tracking for port scan detection */
struct src_stats {
    __u32 src_ip;
    __u16 unique_ports[256];
    int port_count;
    __u64 last_seen_ns;
    __u64 total_bytes;
    int active;
};

/* Per-flow bandwidth tracking */
struct bw_record {
    struct flow_key_t key;
    __u64 last_bytes;
    __u64 last_time_ns;
    __u64 prev_bytes;
    __u64 prev_time_ns;
    int active;
};

struct anomaly_detector {
    struct src_stats sources[1024];
    struct bw_record bw_records[2048];
    int src_count;
    int bw_count;
    /* Thresholds */
    __u64 spike_threshold_bps;   /* bits per second */
    int scan_port_threshold;     /* unique ports to trigger */
    /* Stats */
    int spike_count;
    int scan_count;
    int drop_count;
};

static __u64 now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

struct anomaly_detector *anomaly_detector_create(void) {
    struct anomaly_detector *ad = calloc(1, sizeof(*ad));
    if (!ad) return NULL;
    ad->spike_threshold_bps = 100000000ULL;  /* 100 Mbps */
    ad->scan_port_threshold = 20;
    return ad;
}

void anomaly_detector_destroy(struct anomaly_detector *ad) {
    free(ad);
}

/* Find or create source stats */
static struct src_stats *find_src(struct anomaly_detector *ad, __u32 src_ip) {
    for (int i = 0; i < ad->src_count; i++) {
        if (ad->sources[i].active && ad->sources[i].src_ip == src_ip)
            return &ad->sources[i];
    }
    if (ad->src_count < 1024) {
        ad->sources[ad->src_count].src_ip = src_ip;
        ad->sources[ad->src_count].active = 1;
        return &ad->sources[ad->src_count++];
    }
    return NULL;
}

/* Check if port was already seen for this source */
static int port_seen(struct src_stats *src, __u16 port) {
    for (int i = 0; i < src->port_count && i < 256; i++) {
        if (src->unique_ports[i] == port) return 1;
    }
    return 0;
}

/* Find bandwidth record */
static struct bw_record *find_bw(struct anomaly_detector *ad,
                                  const struct flow_key_t *key) {
    for (int i = 0; i < ad->bw_count; i++) {
        if (ad->bw_records[i].active &&
            memcmp(&ad->bw_records[i].key, key, sizeof(*key)) == 0)
            return &ad->bw_records[i];
    }
    if (ad->bw_count < 2048) {
        ad->bw_records[ad->bw_count].key = *key;
        ad->bw_records[ad->bw_count].active = 1;
        return &ad->bw_records[ad->bw_count++];
    }
    return NULL;
}

int anomaly_check_flow(struct anomaly_detector *ad, struct flow_event_t *flow) {
    if (!ad || !flow) return ANOMALY_NONE;

    __u64 ts = now_ns();

    /* 1. Port scan detection */
    struct src_stats *src = find_src(ad, flow->src_ip);
    if (src && !port_seen(src, flow->dst_port) && flow->dst_port > 0) {
        if (src->port_count < 256)
            src->unique_ports[src->port_count++] = flow->dst_port;
        src->last_seen_ns = ts;

        if (src->port_count >= ad->scan_port_threshold) {
            flow->anomaly = ANOMALY_SCAN;
            strncpy(flow->tags, "anomaly,port_scan", sizeof(flow->tags) - 1);
            ad->scan_count++;
            return ANOMALY_SCAN;
        }
    }

    /* 2. Traffic spike detection */
    struct flow_key_t key = {
        .src_ip = flow->src_ip, .dst_ip = flow->dst_ip,
        .src_port = flow->src_port, .dst_port = flow->dst_port,
    };
    struct bw_record *bw = find_bw(ad, &key);
    if (bw) {
        __u64 dt_ns = ts - bw->last_time_ns;
        if (dt_ns > 0 && bw->last_time_ns > 0) {
            __u64 delta_bytes = flow->bytes; /* This packet's bytes */
            __u64 bps = (delta_bytes * 8 * 1000000000ULL) / dt_ns;

            flow->bandwidth_bps = bps;

            if (bps > ad->spike_threshold_bps) {
                flow->anomaly = ANOMALY_SPIKE;
                snprintf(flow->details, sizeof(flow->details),
                         "bandwidth spike: %llu bps", bps);
                strncpy(flow->tags, "anomaly,spike", sizeof(flow->tags) - 1);
                ad->spike_count++;
                return ANOMALY_SPIKE;
            }
        }
        bw->last_bytes += flow->bytes;
        bw->last_time_ns = ts;
    }

    /* 3. RST storm detection */
    if (flow->tcp_flags & TCP_FLAG_RST) {
        flow->anomaly = ANOMALY_DROP;
        strncpy(flow->tags, "anomaly,rst", sizeof(flow->tags) - 1);
        ad->drop_count++;
        return ANOMALY_DROP;
    }

    return ANOMALY_NONE;
}

void anomaly_detector_print_stats(struct anomaly_detector *ad) {
    if (!ad) return;
    printf("[ANOMALY] spikes=%d scans=%d drops=%d tracked_sources=%d tracked_flows=%d\n",
           ad->spike_count, ad->scan_count, ad->drop_count,
           ad->src_count, ad->bw_count);
}
