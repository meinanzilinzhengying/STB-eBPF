/**
 * serializer.h - JSON serializer header for STB eBPF Probe
 * 
 * This module handles converting connect_event_t to JSON format
 * for sending to Windows relay server.
 * 
 * Uses hand-written JSON serialization (no third-party dependencies).
 * Supports batching: accumulates up to 32 events before flushing.
 * 
 * IP conversion: __u32 → "xxx.xxx.xxx.xxx"
 * Timestamp conversion: ns → ISO 8601 UTC
 */

#ifndef _STB_SERIALIZER_H
#define _STB_SERIALIZER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* Include configuration and shared structures */
#include "config.h"
#include "../include/common.h"

/* ==================== Data Structures ==================== */

/**
 * struct serializer - JSON serializer context
 * 
 * Contains batch buffer and serialization state.
 */
struct serializer {
    struct connect_event_t events[MAX_EVENTS_BATCH];  /* Event batch buffer */
    int event_count;               /* Number of events in batch */
    char json_buffer[MAX_JSON_LEN * MAX_EVENTS_BATCH]; /* JSON output buffer */
    int batch_size;               /* Max events per batch */
    int flush_timeout_ms;         /* Max time before flushing */
    __u64 last_flush_time;       /* Timestamp of last flush */
};

/* ==================== Function Declarations ==================== */

/**
 * serializer_init - Initialize JSON serializer
 * 
 * @batch_size: Maximum number of events per batch
 * @flush_timeout_ms: Maximum time (ms) before flushing
 * 
 * Returns: Pointer to serializer struct, or NULL on failure
 */
struct serializer *serializer_init(int batch_size, int flush_timeout_ms);

/**
 * serializer_add_event - Add an event to batch
 * 
 * @ser: Serializer context
 * @event: Event to add
 * 
 * Returns: 0 on success, -1 if batch is full (call flush first)
 */
int serializer_add_event(struct serializer *ser, 
                         const struct connect_event_t *event);

/**
 * serializer_flush - Flush batch to JSON string
 * 
 * @ser: Serializer context
 * @output: Output buffer for JSON string
 * @output_size: Size of output buffer
 * 
 * Returns: Number of bytes written to output, or -1 on failure
 */
int serializer_flush(struct serializer *ser, char *output, int output_size);

/**
 * serializer_needs_flush - Check if batch needs flushing
 * 
 * @ser: Serializer context
 * 
 * Returns: 1 if needs flush, 0 otherwise
 */
int serializer_needs_flush(struct serializer *ser);

/**
 * serializer_cleanup - Cleanup and free serializer resources
 * 
 * @ser: Serializer context
 */
void serializer_cleanup(struct serializer *ser);

/* ==================== Utility Functions ==================== */

/**
 * ip_to_string - Convert __u32 IP address to string
 * 
 * @ip: IP address in network byte order (__u32)
 * @output: Output buffer (must be at least INET_ADDRSTRLEN bytes)
 * 
 * Returns: Pointer to output string
 */
const char *ip_to_string(__u32 ip, char *output);

/**
 * timestamp_to_iso8601 - Convert nanosecond timestamp to ISO 8601 UTC
 * 
 * @timestamp_ns: Timestamp in nanoseconds
 * @output: Output buffer (must be at least 32 bytes)
 * 
 * Returns: Pointer to output string
 */
const char *timestamp_to_iso8601(__u64 timestamp_ns, char *output);

/**
 * event_type_to_string - Convert event_type to string
 * 
 * @event_type: Event type (EVENT_CONNECT_ENTER/EVENT_CONNECT_EXIT)
 * 
 * Returns: String representation
 */
const char *event_type_to_string(__u8 event_type);

/**
 * serialize_event_to_json - Serialize single event to JSON
 * 
 * @event: Event to serialize
 * @output: Output buffer
 * @output_size: Size of output buffer
 * 
 * Returns: Number of bytes written, or -1 on failure
 */
int serialize_event_to_json(const struct connect_event_t *event,
                             char *output, int output_size);

/**
 * serialize_batch_to_json - Serialize event batch to JSON
 * 
 * @events: Array of events
 * @event_count: Number of events
 * @output: Output buffer
 * @output_size: Size of output buffer
 * 
 * Returns: Number of bytes written, or -1 on failure
 * 
 * Format:
 * {
 *   "probe_id": "stb-tyson-01",
 *   "timestamp": "2026-06-12T10:30:00.123456Z",
 *   "events": [...]
 * }
 */
int serialize_batch_to_json(const struct connect_event_t *events,
                             int event_count,
                             char *output, int output_size);

#endif /* _STB_SERIALIZER_H */
