#ifndef _STB_BPF_LOADER_H
#define _STB_BPF_LOADER_H

#include "../include/common.h"

/**
 * bpf_loader_status - Result of BPF loader initialization
 */
struct bpf_loader_status {
    int socket_fd;          /* Raw socket fd (for packet reading) */
    int perf_map_fd;        /* perf_buffer fd (for BPF events) */
    int bpf_prog_fd;        /* BPF program fd */
    int use_bpf;            /* 1 if BPF loaded successfully */
    char error[256];        /* Error message if failed */
};

/**
 * bpf_loader_init - Load BPF socket filter and attach to interface
 *
 * @ifname: Network interface name (e.g., "eth0")
 * @bpf_obj_path: Path to compiled BPF object file
 * @status: Output status
 *
 * Returns: 0 on success, -1 on failure (check status->error)
 */
int bpf_loader_init(const char *ifname, const char *bpf_obj_path,
                    struct bpf_loader_status *status);

/**
 * bpf_loader_read_packet - Read next packet from raw socket
 *
 * @fd: Raw socket fd
 * @buf: Output buffer
 * @bufsize: Buffer size
 *
 * Returns: Packet length, 0 on timeout, -1 on error
 */
int bpf_loader_read_packet(int fd, void *buf, int bufsize);

/**
 * bpf_loader_cleanup - Close socket and detach BPF
 */
void bpf_loader_cleanup(struct bpf_loader_status *status);

/**
 * bpf_loader_is_available - Quick check if BPF works on this system
 *
 * Returns: 1 if BPF socket filter likely works, 0 if not
 */
int bpf_loader_is_available(void);

#endif
