/**
 * perf_monitor.h - Perf buffer monitor header for STB eBPF Probe
 * 
 * This module handles creating and polling perf_buffer to receive
 * events from BPF program.
 * 
 * Uses two-phase pipeline:
 * - Phase 1 (perf_buffer callback): Push raw events to lock-free ring buffer
 * - Phase 2 (main loop flush): Serialize and send events in batch
 */

#ifndef _STB_PERF_MONITOR_H
#define _STB_PERF_MONITOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Include configuration and shared structures */
#include "config.h"
#include "../include/common.h"

/* ==================== Data Structures ==================== */

/**
 * struct perf_monitor - Perf buffer monitor context
 * 
 * Contains all state needed to manage perf_buffer polling
 * and event processing.
 */
struct perf_monitor {
    struct perf_buffer *pb;        /* perf_buffer instance */
    struct perf_buffer_opts pb_opts; /* perf_buffer options */
    int perf_map_fd;               /* perf_map file descriptor */
    int stop_flag;                 /* Flag to stop polling */
    pthread_t poll_thread;         /* Polling thread */
    int use_thread;                /* Whether to use polling thread */
    
    /* Phase 1 output: lock-free ring buffer */
    struct ring_buffer *ring_buf;  /* Lock-free ring buffer for events */
    
    /* Statistics */
    __u64 events_received;        /* Total events received */
    __u64 events_lost;             /* Events lost (buffer full) */
    __u64 poll_count;              /* Number of poll calls */
};

/* ==================== Function Declarations ==================== */

/**
 * perf_monitor_init - Initialize perf monitor
 * 
 * @perf_map_fd: File descriptor of perf_map
 * @ring_buf: Pointer to lock-free ring buffer (Phase 1 output)
 * @use_thread: Whether to use separate polling thread
 * 
 * Returns: Pointer to perf_monitor struct, or NULL on failure
 */
struct perf_monitor *perf_monitor_init(int perf_map_fd,
                                       struct ring_buffer *ring_buf,
                                       int use_thread);

/**
 * perf_monitor_start - Start perf buffer polling
 * 
 * @monitor: Perf monitor context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int perf_monitor_start(struct perf_monitor *monitor);

/**
 * perf_monitor_stop - Stop perf buffer polling
 * 
 * @monitor: Perf monitor context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int perf_monitor_stop(struct perf_monitor *monitor);

/**
 * perf_monitor_cleanup - Cleanup and free perf monitor resources
 * 
 * @monitor: Perf monitor context
 */
void perf_monitor_cleanup(struct perf_monitor *monitor);

/**
 * perf_monitor_poll_once - Poll perf buffer once (non-threaded mode)
 * 
 * @monitor: Perf monitor context
 * @timeout_ms: Timeout in milliseconds
 * 
 * Returns: Number of events processed, or negative error code
 */
int perf_monitor_poll_once(struct perf_monitor *monitor, int timeout_ms);

/**
 * perf_monitor_get_stats - Get perf monitor statistics
 * 
 * @monitor: Perf monitor context
 * @events_received: Output - events received
 * @events_lost: Output - events lost
 * @poll_count: Output - poll count
 */
void perf_monitor_get_stats(struct perf_monitor *monitor,
                            __u64 *events_received,
                            __u64 *events_lost,
                            __u64 *poll_count);

/**
 * perf_monitor_print_stats - Print perf monitor statistics
 * 
 * @monitor: Perf monitor context
 */
void perf_monitor_print_stats(struct perf_monitor *monitor);

/* ==================== Phase 1: Perf Buffer Callback ==================== */

/**
 * event_handler - Perf buffer event handler (Phase 1)
 * 
 * This function is called by perf_buffer when an event is received.
 * It should ONLY push the raw event to the lock-free ring buffer.
 * NO serialization or I/O in this callback!
 * 
 * @ctx: Context (pointer to ring_buffer)
 * @cpu: CPU ID
 * @data: Pointer to event data
 * @size: Size of event data
 */
void event_handler(void *ctx, int cpu, void *data, unsigned int size);

/**
 * lost_handler - Perf buffer lost events handler
 * 
 * @ctx: Context
 * @cpu: CPU ID
 * @cnt: Number of lost events
 */
void lost_handler(void *ctx, int cpu, __u64 cnt);

/* ==================== Utility Functions ==================== */

/**
 * create_ring_buffer - Create a lock-free ring buffer
 * 
 * Returns: Pointer to ring_buffer struct, or NULL on failure
 */
struct ring_buffer *create_ring_buffer(void);

/**
 * ring_buffer_push - Push an event to ring buffer (Phase 1 output)
 * 
 * @ring_buf: Ring buffer
 * @event: Event to push
 * 
 * Returns: 0 on success, -1 if buffer is full
 */
int ring_buffer_push(struct ring_buffer *ring_buf, 
                     const struct connect_event_t *event);

/**
 * ring_buffer_pop - Pop an event from ring buffer (Phase 2 input)
 * 
 * @ring_buf: Ring buffer
 * @event: Output - popped event
 * 
 * Returns: 0 on success, -1 if buffer is empty
 */
int ring_buffer_pop(struct ring_buffer *ring_buf,
                    struct connect_event_t *event);

/**
 * ring_buffer_size - Get number of events in ring buffer
 * 
 * @ring_buf: Ring buffer
 * 
 * Returns: Number of events
 */
int ring_buffer_size(struct ring_buffer *ring_buf);

/**
 * ring_buffer_empty - Check if ring buffer is empty
 * 
 * @ring_buf: Ring buffer
 * 
 * Returns: 1 if empty, 0 if not
 */
int ring_buffer_empty(struct ring_buffer *ring_buf);

/**
 * ring_buffer_full - Check if ring buffer is full
 * 
 * @ring_buf: Ring buffer
 * 
 * Returns: 1 if full, 0 if not
 */
int ring_buffer_full(struct ring_buffer *ring_buf);

/**
 * destroy_ring_buffer - Destroy ring buffer and free resources
 * 
 * @ring_buf: Ring buffer
 */
void destroy_ring_buffer(struct ring_buffer *ring_buf);

#endif /* _STB_PERF_MONITOR_H */
