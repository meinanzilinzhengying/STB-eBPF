/**
 * loader.h - libbpf loader header for STB eBPF Probe
 * 
 * This module handles loading, verifying, and attaching BPF programs
 * using legacy libbpf mode (no BTF/CO-RE).
 */

#ifndef _STB_LOADER_H
#define _STB_LOADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Include configuration */
#include "config.h"
#include "../include/common.h"

/* ==================== Data Structures ==================== */

/**
 * struct bpf_loader - BPF loader context
 * 
 * Contains all state needed to manage BPF program lifecycle.
 */
struct bpf_loader {
    struct bpf_object *obj;           /* BPF object file */
    struct bpf_program *prog_enter;   /* sys_enter_connect program */
    struct bpf_program *prog_exit;    /* sys_exit_connect program */
    struct bpf_link *link_enter;      /* Link for enter program */
    struct bpf_link *link_exit;       /* Link for exit program */
    struct bpf_map *perf_map;        /* perf_event_array map */
    struct bpf_map *connect_start_map; /* connect_start hash map */
    int perf_map_fd;                  /* perf_map file descriptor */
    int connect_start_map_fd;         /* connect_start map file descriptor */
    int is_loaded;                   /* Whether BPF is loaded */
    int is_attached;                 /* Whether programs are attached */
};

/* ==================== Function Declarations ==================== */

/**
 * loader_init - Initialize BPF loader
 * 
 * Returns: Pointer to bpf_loader struct, or NULL on failure
 */
struct bpf_loader *loader_init(void);

/**
 * loader_load - Load BPF object file
 * 
 * @loader: Loader context
 * @bpf_obj_path: Path to BPF object file (.o)
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_load(struct bpf_loader *loader, const char *bpf_obj_path);

/**
 * loader_attach - Attach BPF programs to tracepoints
 * 
 * @loader: Loader context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_attach(struct bpf_loader *loader);

/**
 * loader_detach - Detach BPF programs from tracepoints
 * 
 * @loader: Loader context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_detach(struct bpf_loader *loader);

/**
 * loader_unload - Unload BPF programs and cleanup
 * 
 * @loader: Loader context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_unload(struct bpf_loader *loader);

/**
 * loader_get_perf_map_fd - Get perf_map file descriptor
 * 
 * @loader: Loader context
 * 
 * Returns: perf_map file descriptor, or -1 on failure
 */
int loader_get_perf_map_fd(struct bpf_loader *loader);

/**
 * loader_get_connect_start_map_fd - Get connect_start map file descriptor
 * 
 * @loader: Loader context
 * 
 * Returns: connect_start map file descriptor, or -1 on failure
 */
int loader_get_connect_start_map_fd(struct bpf_loader *loader);

/**
 * loader_print_bpf_log - Print BPF verifier log
 * 
 * @loader: Loader context
 */
void loader_print_bpf_log(struct bpf_loader *loader);

/**
 * loader_cleanup - Cleanup and free loader resources
 * 
 * @loader: Loader context
 */
void loader_cleanup(struct bpf_loader *loader);

/* ==================== Utility Functions ==================== */

/**
 * is_bpf_supported - Check if BPF is supported on this system
 * 
 * Returns: 1 if supported, 0 if not
 */
int is_bpf_supported(void);

/**
 * check_kernel_version - Check kernel version
 * 
 * @min_major: Minimum major version
 * @min_minor: Minimum minor version
 * 
 * Returns: 1 if kernel version >= min_version, 0 otherwise
 */
int check_kernel_version(int min_major, int min_minor);

/**
 * print_kernel_info - Print kernel version and BPF support info
 */
void print_kernel_info(void);

#endif /* _STB_LOADER_H */
