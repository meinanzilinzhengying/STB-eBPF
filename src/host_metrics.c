#include "host_metrics.h"
#include "proc_net.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static double read_cpu_percent(void) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;
    char line[256];
    fgets(line, sizeof(line), f);
    unsigned long long user, nice, system, idle, iowait, irq, softirq;
    if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq) < 4) {
        fclose(f); return 0;
    }
    fclose(f);
    unsigned long long total = user + nice + system + idle + iowait + irq + softirq;
    unsigned long long busy = total - idle - iowait;
    return (total > 0) ? (double)busy * 100.0 / (double)total : 0;
}

static double read_memory_percent(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    __u64 total = 0, available = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %llu kB", &total) == 1) continue;
        if (sscanf(line, "MemAvailable: %llu kB", &available) == 1) break;
    }
    fclose(f);
    if (total == 0) return 0;
    return (double)(total - available) * 100.0 / (double)total;
}

static double read_disk_percent(void) {
    FILE *f = popen("df / 2>/dev/null | tail -1 | awk '{print $5}'", "r");
    if (!f) return 0;
    char buf[32];
    double pct = 0;
    if (fgets(buf, sizeof(buf), f)) {
        sscanf(buf, "%lf%%", &pct);
    }
    pclose(f);
    return pct;
}

int host_metrics_collect(struct host_metric_t *metric, const char *probe_id) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    metric->timestamp_ns = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    strncpy(metric->probe_id, probe_id, sizeof(metric->probe_id) - 1);

    metric->cpu_percent = read_cpu_percent();
    metric->memory_percent = read_memory_percent();
    metric->disk_percent = read_disk_percent();
    proc_net_read_dev(&metric->net_rx_bytes, &metric->net_tx_bytes);
    metric->disk_read_bytes = 0;
    metric->disk_write_bytes = 0;

    return 0;
}
