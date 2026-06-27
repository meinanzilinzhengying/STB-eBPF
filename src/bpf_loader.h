#ifndef _STB_BPF_LOADER_H
#define _STB_BPF_LOADER_H

#include "../include/common.h"

#define PERF_MAX_CPUS  16
#define PERF_PAGE_CNT  64

/**
 * bpf_loader_status - Result of BPF loader initialization
 */
struct bpf_loader_status {
    int socket_fd;          /* Raw socket fd (for packet reading) */
    int perf_map_fd;        /* perf_event_array map fd from BPF */
    int bpf_prog_fd;        /* BPF program fd */
    int use_bpf;            /* 1 if BPF loaded successfully */
    int nr_cpus;            /* Number of CPUs for perf buffer */
    int perf_fds[PERF_MAX_CPUS];    /* perf event fds per CPU */
    void *perf_mmap[PERF_MAX_CPUS]; /* mmap'd ring buffers per CPU */
    int perf_page_cnt;      /* pages per CPU ring buffer */
    char error[256];        /* Error message if failed */
};

/**
 * bpf_loader_init - Load BPF socket filter and attach to interface
 */
int bpf_loader_init(const char *ifname, const char *bpf_obj_path,
                    struct bpf_loader_status *status);

/**
 * bpf_loader_read_packet - Read next packet from raw socket
 */
int bpf_loader_read_packet(int fd, void *buf, int bufsize);

/**
 * bpf_loader_read_perf_events - Read events from perf buffer
 *
 * @status: BPF loader status (contains perf fds and mmaps)
 * @buf: Output buffer for pkt_event_t events
 * @bufsize: Size of output buffer
 * @nr_events: Output: number of events read
 *
 * Returns: 0 on success, -1 on error
 */
int bpf_loader_read_perf_events(struct bpf_loader_status *status,
                                 void *buf, int bufsize, int *nr_events);

/**
 * bpf_loader_cleanup - Close socket and detach BPF
 */
void bpf_loader_cleanup(struct bpf_loader_status *status);

/**
 * bpf_loader_is_available - Quick check if BPF works on this system
 */
int bpf_loader_is_available(void);

#endif
