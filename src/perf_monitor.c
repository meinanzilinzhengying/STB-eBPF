/**
 * perf_monitor.c - Perf buffer monitor implementation for STB eBPF Probe
 * 
 * This module handles creating and polling perf_buffer to receive
 * events from BPF program.
 * 
 * Uses two-phase pipeline:
 * - Phase 1 (perf_buffer callback): Push raw events to lock-free ring buffer
 * - Phase 2 (main loop flush): Serialize and send events in batch
 * 
 * perf_buffer__new() → perf_buffer__poll()
 * event_handler callback: receive raw event, push to lock-free ring buffer
 */

#include "perf_monitor.h"

/* ==================== Lock-free Ring Buffer Implementation ==================== */

/**
 * create_ring_buffer - Create a lock-free ring buffer
 * 
 * Returns: Pointer to ring_buffer struct, or NULL on failure
 */
struct ring_buffer *create_ring_buffer(void) {
    struct ring_buffer *rb = malloc(sizeof(struct ring_buffer));
    if (!rb) {
        perror("malloc failed for ring_buffer");
        return NULL;
    }
    
    memset(rb, 0, sizeof(struct ring_buffer));
    /* write_idx and read_idx are already 0 */
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Ring buffer created (size=%u)\n", RING_BUF_SIZE);
    }
    
    return rb;
}

/**
 * ring_buffer_push - Push an event to ring buffer (Phase 1 output)
 * 
 * @ring_buf: Ring buffer
 * @event: Event to push
 * 
 * Returns: 0 on success, -1 if buffer is full
 * 
 * Note: This function is called from perf_buffer callback (Phase 1).
 *       It must be fast and non-blocking.
 */
int ring_buffer_push(struct ring_buffer *ring_buf,
                      const struct connect_event_t *event) {
    if (!ring_buf || !event) {
        return -1;
    }

    __u32 cur_write = __atomic_load_n(&ring_buf->write_idx, __ATOMIC_ACQUIRE);
    __u32 cur_read = __atomic_load_n(&ring_buf->read_idx, __ATOMIC_ACQUIRE);
    __u32 next_write = (cur_write + 1) % RING_BUF_SIZE;
    if (next_write == cur_read) {
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] Ring buffer full, dropping event\n");
        }
        return -1;
    }

    memcpy(&ring_buf->events[cur_write], event,
           sizeof(struct connect_event_t));
    __atomic_store_n(&ring_buf->write_idx, next_write, __ATOMIC_RELEASE);

    return 0;
}

/**
 * ring_buffer_pop - Pop an event from ring buffer (Phase 2 input)
 * 
 * @ring_buf: Ring buffer
 * @event: Output - popped event
 * 
 * Returns: 0 on success, -1 if buffer is empty
 * 
 * Note: This function is called from main loop (Phase 2).
 */
int ring_buffer_pop(struct ring_buffer *ring_buf,
                     struct connect_event_t *event) {
    if (!ring_buf || !event) {
        return -1;
    }

    __u32 cur_read = __atomic_load_n(&ring_buf->read_idx, __ATOMIC_ACQUIRE);
    __u32 cur_write = __atomic_load_n(&ring_buf->write_idx, __ATOMIC_ACQUIRE);
    if (cur_read == cur_write) {
        return -1;
    }

    memcpy(event, &ring_buf->events[cur_read],
           sizeof(struct connect_event_t));
    __atomic_store_n(&ring_buf->read_idx,
                     (cur_read + 1) % RING_BUF_SIZE, __ATOMIC_RELEASE);
    return 0;
}

/**
 * ring_buffer_size - Get number of events in ring buffer
 * 
 * @ring_buf: Ring buffer
 * 
 * Returns: Number of events
 */
int ring_buffer_size(struct ring_buffer *ring_buf) {
    if (!ring_buf) {
        return 0;
    }
    __u32 w = __atomic_load_n(&ring_buf->write_idx, __ATOMIC_ACQUIRE);
    __u32 r = __atomic_load_n(&ring_buf->read_idx, __ATOMIC_ACQUIRE);
    if (w >= r) return w - r;
    return RING_BUF_SIZE - r + w;
}

/**
 * ring_buffer_empty - Check if ring buffer is empty
 * 
 * @ring_buf: Ring buffer
 * 
 * Returns: 1 if empty, 0 if not
 */
int ring_buffer_empty(struct ring_buffer *ring_buf) {
    if (!ring_buf) {
        return 1;
    }
    return ring_buf->read_idx == ring_buf->write_idx;
}

/**
 * ring_buffer_full - Check if ring buffer is full
 * 
 * @ring_buf: Ring buffer
 * 
 * Returns: 1 if full, 0 if not
 */
int ring_buffer_full(struct ring_buffer *ring_buf) {
    if (!ring_buf) {
        return 0;
    }
    __u32 w = __atomic_load_n(&ring_buf->write_idx, __ATOMIC_ACQUIRE);
    __u32 r = __atomic_load_n(&ring_buf->read_idx, __ATOMIC_ACQUIRE);
    return ((w + 1) % RING_BUF_SIZE) == r;
}

/**
 * destroy_ring_buffer - Destroy ring buffer and free resources
 * 
 * @ring_buf: Ring buffer
 */
void destroy_ring_buffer(struct ring_buffer *ring_buf) {
    if (!ring_buf) {
        return;
    }
    free(ring_buf);
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Ring buffer destroyed\n");
    }
}

/* ==================== Perf Buffer Callback (Phase 1) ==================== */

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
void event_handler(void *ctx, int cpu, void *data, unsigned int size) {
    if (!ctx || !data) {
        return;
    }
    
    if (size != sizeof(struct connect_event_t)) {
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] Invalid event size: %u (expected %zu)\n",
                    size, sizeof(struct connect_event_t));
        }
        return;
    }
    
    /* Cast data to connect_event_t */
    struct connect_event_t *event = (struct connect_event_t *)data;
    
    /* Push to ring buffer (Phase 1 output) */
    struct ring_buffer *ring_buf = (struct ring_buffer *)ctx;
    if (ring_buffer_push(ring_buf, event) != 0) {
        /* Failed to push (buffer full) - event is dropped */
        if (LOG_LEVEL >= 3) {
            fprintf(stderr, "[DEBUG] Failed to push event to ring buffer\n");
        }
    } else {
        if (LOG_LEVEL >= 3) {
            printf("[DEBUG] Event pushed to ring buffer (pid=%u, type=%u)\n",
                   event->pid, event->event_type);
        }
    }
}

/**
 * lost_handler - Perf buffer lost events handler
 * 
 * @ctx: Context
 * @cpu: CPU ID
 * @cnt: Number of lost events
 */
void lost_handler(void *ctx, int cpu, __u64 cnt) {
    if (LOG_LEVEL >= 1) {
        fprintf(stderr, "[WARN] Lost %llu events on CPU %d\n", cnt, cpu);
    }
    
    /* Update statistics if context is perf_monitor */
    if (ctx) {
        struct perf_monitor *monitor = (struct perf_monitor *)ctx;
        monitor->events_lost += cnt;
    }
}

/* ==================== Perf Monitor Implementation ==================== */

/**
 * polling_thread - Thread function for perf buffer polling
 * 
 * @arg: Pointer to perf_monitor struct
 * 
 * Returns: NULL
 */
static void *polling_thread(void *arg) {
    struct perf_monitor *monitor = (struct perf_monitor *)arg;
    if (!monitor) {
        return NULL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Perf buffer polling thread started\n");
    }
    
    /* Poll perf buffer until stop_flag is set */
    while (!__sync_fetch_and_add(&monitor->stop_flag, 0)) {
        int ret = perf_buffer__poll(monitor->pb, 100);  /* 100ms timeout */
        if (ret < 0) {
            if (ret != -EINTR) {
                fprintf(stderr, "[ERROR] perf_buffer__poll failed: %d\n", ret);
            }
            break;
        }
        monitor->poll_count++;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Perf buffer polling thread stopped\n");
    }
    
    return NULL;
}

/* ==================== Public API Implementation ==================== */

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
                                        int use_thread) {
    if (perf_map_fd < 0) {
        fprintf(stderr, "perf_monitor_init: invalid perf_map_fd\n");
        return NULL;
    }
    
    if (!ring_buf) {
        fprintf(stderr, "perf_monitor_init: ring_buf is NULL\n");
        return NULL;
    }
    
    struct perf_monitor *monitor = malloc(sizeof(struct perf_monitor));
    if (!monitor) {
        perror("malloc failed for perf_monitor");
        return NULL;
    }
    
    /* Initialize all fields */
    memset(monitor, 0, sizeof(struct perf_monitor));
    monitor->perf_map_fd = perf_map_fd;
    monitor->ring_buf = ring_buf;
    monitor->use_thread = use_thread;
    monitor->stop_flag = 0;
    monitor->pb = NULL;
    monitor->events_received = 0;
    monitor->events_lost = 0;
    monitor->poll_count = 0;
    
    /* Setup perf_buffer options */
    monitor->pb_opts.sample_period = 1;
    monitor->pb_opts.wakeup_events = 1;
    
    /* Create perf_buffer */
    monitor->pb = perf_buffer__new(perf_map_fd, 8,  /* 8 = number of pages */
                                     event_handler,
                                     lost_handler,
                                     ring_buf);  /* ctx = ring_buf */
    if (!monitor->pb) {
        fprintf(stderr, "Failed to create perf_buffer: %d\n", -errno);
        free(monitor);
        return NULL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Perf monitor initialized (perf_map_fd=%d, use_thread=%d)\n",
               perf_map_fd, use_thread);
    }
    
    return monitor;
}

/**
 * perf_monitor_start - Start perf buffer polling
 * 
 * @monitor: Perf monitor context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int perf_monitor_start(struct perf_monitor *monitor) {
    if (!monitor) {
        fprintf(stderr, "perf_monitor_start: monitor is NULL\n");
        return -EINVAL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Starting perf buffer polling...\n");
    }
    
    if (monitor->use_thread) {
        /* Start polling thread */
        int ret = pthread_create(&monitor->poll_thread, NULL,
                                 polling_thread, monitor);
        if (ret != 0) {
            fprintf(stderr, "Failed to create polling thread: %d\n", ret);
            return -ret;
        }
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Perf buffer polling started\n");
    }
    
    return 0;
}

/**
 * perf_monitor_stop - Stop perf buffer polling
 * 
 * @monitor: Perf monitor context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int perf_monitor_stop(struct perf_monitor *monitor) {
    if (!monitor) {
        fprintf(stderr, "perf_monitor_stop: monitor is NULL\n");
        return -EINVAL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Stopping perf buffer polling...\n");
    }
    
    /* Set stop flag */
    __sync_fetch_and_or(&monitor->stop_flag, 1);
    
    if (monitor->use_thread && monitor->poll_thread) {
        /* Wait for polling thread to finish */
        pthread_join(monitor->poll_thread, NULL);
        monitor->poll_thread = 0;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Perf buffer polling stopped\n");
    }
    
    return 0;
}

/**
 * perf_monitor_cleanup - Cleanup and free perf monitor resources
 * 
 * @monitor: Perf monitor context
 */
void perf_monitor_cleanup(struct perf_monitor *monitor) {
    if (!monitor) {
        return;
    }
    
    /* Stop first */
    if (monitor->pb) {
        perf_monitor_stop(monitor);
    }
    
    /* Destroy perf_buffer */
    if (monitor->pb) {
        perf_buffer__free(monitor->pb);
        monitor->pb = NULL;
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Perf buffer destroyed\n");
        }
    }
    
    /* Free monitor struct */
    free(monitor);
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Perf monitor cleaned up\n");
    }
}

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
                             __u64 *poll_count) {
    if (!monitor) {
        if (events_received) *events_received = 0;
        if (events_lost) *events_lost = 0;
        if (poll_count) *poll_count = 0;
        return;
    }
    
    if (events_received) *events_received = monitor->events_received;
    if (events_lost) *events_lost = monitor->events_lost;
    if (poll_count) *poll_count = monitor->poll_count;
}

/**
 * perf_monitor_print_stats - Print perf monitor statistics
 * 
 * @monitor: Perf monitor context
 */
void perf_monitor_print_stats(struct perf_monitor *monitor) {
    if (!monitor) {
        printf("Perf Monitor Statistics: N/A (monitor is NULL)\n");
        return;
    }
    
    printf("=== Perf Monitor Statistics ===\n");
    printf("Events received: %llu\n", monitor->events_received);
    printf("Events lost: %llu\n", monitor->events_lost);
    printf("Poll count: %llu\n", monitor->poll_count);
    printf("Ring buffer size: %d\n", ring_buffer_size(monitor->ring_buf));
    printf("================================\n");
}

/* ==================== Phase 2: Main Loop Flush ==================== */

/**
 * perf_monitor_poll_once - Poll perf buffer once (for non-threaded mode)
 * 
 * @monitor: Perf monitor context
 * @timeout_ms: Timeout in milliseconds
 * 
 * Returns: Number of events processed, or negative error code
 */
int perf_monitor_poll_once(struct perf_monitor *monitor, int timeout_ms) {
    if (!monitor || !monitor->pb) {
        return -EINVAL;
    }
    
    int ret = perf_buffer__poll(monitor->pb, timeout_ms);
    if (ret < 0) {
        if (ret != -EINTR) {
            fprintf(stderr, "[ERROR] perf_buffer__poll failed: %d\n", ret);
        }
        return ret;
    }
    
    monitor->poll_count++;
    return ret;
}

/**
 * perf_monitor_read_events - Read events from ring buffer (Phase 2 input)
 * 
 * @monitor: Perf monitor context
 * @events: Output array of events
 * @max_events: Maximum number of events to read
 * 
 * Returns: Number of events read, or negative error code
 */
int perf_monitor_read_events(struct perf_monitor *monitor,
                              struct connect_event_t *events,
                              int max_events) {
    if (!monitor || !events || max_events <= 0) {
        return -EINVAL;
    }
    
    int count = 0;
    while (count < max_events && !ring_buffer_empty(monitor->ring_buf)) {
        if (ring_buffer_pop(monitor->ring_buf, &events[count]) == 0) {
            count++;
            monitor->events_received++;
        } else {
            break;
        }
    }
    
    return count;
}
