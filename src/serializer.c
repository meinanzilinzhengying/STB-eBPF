/**
 * serializer.c - JSON serializer implementation for STB eBPF Probe
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

#include "serializer.h"

/* ==================== Utility Functions ==================== */

/**
 * ip_to_string - Convert __u32 IP address to string
 * 
 * @ip: IP address in network byte order (__u32)
 * @output: Output buffer (must be at least INET_ADDRSTRLEN bytes)
 * 
 * Returns: Pointer to output string
 * 
 * Note: __u32 is in network byte order (big endian).
 *       We need to convert to host byte order for inet_ntop,
 *       or manually format the string.
 */
const char *ip_to_string(__u32 ip, char *output) {
    if (!output) {
        return NULL;
    }
    
    /* IP is in network byte order (big endian).
     * Access bytes directly in network order: bytes[0] is the MSB.
     * On a little-endian host, (unsigned char *)&ip gives LSB first,
     * so we read in reverse order.
     */
    unsigned char *bytes = (unsigned char *)&ip;
    snprintf(output, INET_ADDRSTRLEN, "%d.%d.%d.%d",
             bytes[3], bytes[2], bytes[1], bytes[0]);
    return output;
}

/**
 * timestamp_to_iso8601 - Convert nanosecond timestamp to ISO 8601 UTC
 * 
 * @timestamp_ns: Timestamp in nanoseconds
 * @output: Output buffer (must be at least 32 bytes)
 * 
 * Returns: Pointer to output string
 * 
 * Format: "2026-06-12T10:30:00.123456Z"
 * 
 * Note: We use clock_gettime(CLOCK_REALTIME) for wall clock time.
 *       BPF uses bpf_ktime_get_ns() (monotonic), but for reporting
 *       we need wall clock time.
 */
const char *timestamp_to_iso8601(__u64 timestamp_ns, char *output) {
    if (!output) {
        return NULL;
    }

    init_clock_offset();
    __u64 realtime_ns = timestamp_ns + g_mono_to_real_ns;

    /* Convert nanoseconds to seconds + nanoseconds */
    time_t seconds = realtime_ns / 1000000000ULL;
    long nanoseconds = realtime_ns % 1000000000ULL;
    
    /* Convert to UTC struct tm */
    struct tm *tm_utc = gmtime(&seconds);
    if (!tm_utc) {
        snprintf(output, 32, "1970-01-01T00:00:00.000000Z");
        return output;
    }
    
    /* Format: YYYY-MM-DDTHH:MM:SS.NNNNNNZ */
    strftime(output, 32, "%Y-%m-%dT%H:%M:%S", tm_utc);
    
    /* Append microseconds (first 6 digits of nanoseconds) */
    long microseconds = nanoseconds / 1000;
    char usec_buf[8];
    snprintf(usec_buf, 8, ".%06ld", microseconds);
    strcat(output, usec_buf);
    strcat(output, "Z");
    
    return output;
}

/**
 * event_type_to_string - Convert event_type to string
 * 
 * @event_type: Event type (EVENT_CONNECT_ENTER/EVENT_CONNECT_EXIT)
 * 
 * Returns: String representation
 */
const char *event_type_to_string(__u8 event_type) {
    switch (event_type) {
        case EVENT_CONNECT_ENTER:
            return "connect_enter";
        case EVENT_CONNECT_EXIT:
            return "connect_exit";
        default:
            return "unknown";
    }
}

/* Offset between CLOCK_MONOTONIC and CLOCK_REALTIME (ns) */
static __u64 g_mono_to_real_ns = 0;

static void init_clock_offset(void) {
    static int done = 0;
    if (done) return;
    struct timespec mono, real;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &real);
    __u64 m = (__u64)mono.tv_sec * 1000000000ULL + mono.tv_nsec;
    __u64 r = (__u64)real.tv_sec * 1000000000ULL + real.tv_nsec;
    g_mono_to_real_ns = r - m;
    done = 1;
}

/* ==================== JSON Serialization Helpers ==================== */

/**
 * json_escape_string - Escape string for JSON
 * 
 * @input: Input string
 * @output: Output buffer
 * @output_size: Size of output buffer
 * 
 * Returns: Number of bytes written, or -1 on failure
 */
static int json_escape_string(const char *input, char *output, int output_size) {
    if (!input || !output) {
        return -1;
    }
    
    int written = 0;
    const char *p = input;
    
    while (*p && written < output_size - 2) {
        switch (*p) {
            case '\"':
                written += snprintf(output + written, output_size - written, "\\\"");
                break;
            case '\\':
                written += snprintf(output + written, output_size - written, "\\\\");
                break;
            case '\b':
                written += snprintf(output + written, output_size - written, "\\b");
                break;
            case '\f':
                written += snprintf(output + written, output_size - written, "\\f");
                break;
            case '\n':
                written += snprintf(output + written, output_size - written, "\\n");
                break;
            case '\r':
                written += snprintf(output + written, output_size - written, "\\r");
                break;
            case '\t':
                written += snprintf(output + written, output_size - written, "\\t");
                break;
            default:
                if ((unsigned char)*p < 0x20) {
                    /* Control character */
                    written += snprintf(output + written, output_size - written,
                                        "\\u%04x", (unsigned char)*p);
                } else {
                    output[written++] = *p;
                    output[written] = '\0';
                }
                break;
        }
        p++;
    }
    
    return written;
}

/**
 * serialize_event_json_internal - Serialize single event to JSON (internal)
 * 
 * @event: Event to serialize
 * @output: Output buffer
 * @output_size: Size of output buffer
 * @is_first: Whether this is the first event in array
 * 
 * Returns: Number of bytes written, or -1 on failure
 */
static int serialize_event_json_internal(const struct connect_event_t *event,
                                          char *output, int output_size,
                                          int is_first) {
    if (!event || !output || output_size <= 0) {
        return -1;
    }
    
    char src_ip_buf[INET_ADDRSTRLEN];
    char dst_ip_buf[INET_ADDRSTRLEN];
    char ts_buf[32];
    char comm_escaped[32];
    
    /* Convert fields to strings (use separate buffers for src/dst) */
    const char *src_ip = ip_to_string(event->saddr, src_ip_buf);
    const char *dst_ip = ip_to_string(event->daddr, dst_ip_buf);
    const char *timestamp = timestamp_to_iso8601(event->timestamp_ns, ts_buf);
    const char *event_type = event_type_to_string(event->event_type);
    json_escape_string(event->comm, comm_escaped, sizeof(comm_escaped));
    
    /* Build JSON object */
    int written = 0;
    if (!is_first) {
        written += snprintf(output + written, output_size - written, ",");
    }
    
    written += snprintf(output + written, output_size - written,
                        "{\"pid\":%u,\"uid\":%u,\"src_ip\":\"%s\","
                        "\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
                        "\"family\":%u,\"protocol\":%u,\"comm\":\"%s\","
                        "\"event_type\":\"%s\",\"latency_us\":%llu,"
                        "\"retval\":%d}",
                        event->pid, event->uid,
                        src_ip, dst_ip,
                        event->sport, event->dport,
                        event->family, event->protocol,
                        comm_escaped, event_type,
                        event->latency_us, event->retval);
    
    if (written >= output_size) {
        return -1;  /* Buffer overflow */
    }
    
    return written;
}

/* ==================== Public API Implementation ==================== */

/**
 * serializer_init - Initialize JSON serializer
 * 
 * @batch_size: Maximum number of events per batch
 * @flush_timeout_ms: Maximum time (ms) before flushing
 * 
 * Returns: Pointer to serializer struct, or NULL on failure
 */
struct serializer *serializer_init(int batch_size, int flush_timeout_ms) {
    if (batch_size <= 0 || batch_size > MAX_EVENTS_BATCH) {
        fprintf(stderr, "Invalid batch_size: %d (max=%d)\n",
                batch_size, MAX_EVENTS_BATCH);
        return NULL;
    }
    
    struct serializer *ser = malloc(sizeof(struct serializer));
    if (!ser) {
        perror("malloc failed for serializer");
        return NULL;
    }
    
    /* Initialize */
    memset(ser, 0, sizeof(struct serializer));
    ser->event_count = 0;
    ser->batch_size = batch_size;
    ser->flush_timeout_ms = flush_timeout_ms;
    ser->last_flush_time = 0;
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Serializer initialized (batch_size=%d, timeout=%dms)\n",
               batch_size, flush_timeout_ms);
    }
    
    return ser;
}

/**
 * serializer_add_event - Add an event to batch
 * 
 * @ser: Serializer context
 * @event: Event to add
 * 
 * Returns: 0 on success, -1 if batch is full (call flush first)
 */
int serializer_add_event(struct serializer *ser,
                          const struct connect_event_t *event) {
    if (!ser || !event) {
        return -1;
    }
    
    if (ser->event_count >= ser->batch_size) {
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] Batch full (%d events), call flush first\n",
                    ser->batch_size);
        }
        return -1;
    }
    
    /* Copy event to batch buffer */
    memcpy(&ser->events[ser->event_count], event,
           sizeof(struct connect_event_t));
    ser->event_count++;
    
    if (LOG_LEVEL >= 3) {
        printf("[DEBUG] Event added to batch (%d/%d)\n",
               ser->event_count, ser->batch_size);
    }
    
    return 0;
}

/**
 * serializer_flush - Flush batch to JSON string
 * 
 * @ser: Serializer context
 * @output: Output buffer for JSON string
 * @output_size: Size of output buffer
 * 
 * Returns: Number of bytes written to output, or -1 on failure
 */
int serializer_flush(struct serializer *ser, char *output, int output_size) {
    if (!ser || !output || output_size <= 0) {
        return -1;
    }
    
    if (ser->event_count == 0) {
        if (LOG_LEVEL >= 3) {
            printf("[DEBUG] No events to flush\n");
        }
        return 0;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Flushing %d events to JSON...\n", ser->event_count);
    }
    
    /* Build JSON */
    int written = 0;
    
    /* Start JSON object */
    written += snprintf(output + written, output_size - written,
                        "{\"probe_id\":\"%s\",\"timestamp\":\"", PROBE_ID);
    
    /* Use current time for batch timestamp */
    char ts_buf[32];
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    __u64 now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
    timestamp_to_iso8601(now_ns, ts_buf);
    written += snprintf(output + written, output_size - written, "%s", ts_buf);
    
    /* Start events array */
    written += snprintf(output + written, output_size - written,
                        "\",\"events\":[");
    
    /* Serialize each event */
    for (int i = 0; i < ser->event_count; i++) {
        int ret = serialize_event_json_internal(&ser->events[i],
                                                 output + written,
                                                 output_size - written,
                                                 i == 0);
        if (ret < 0) {
            fprintf(stderr, "Failed to serialize event %d\n", i);
            return -1;
        }
        written += ret;
    }
    
    /* End events array and JSON object */
    written += snprintf(output + written, output_size - written, "]}\n");
    
    if (written >= output_size) {
        fprintf(stderr, "JSON buffer overflow (%d bytes written)\n", written);
        return -1;
    }
    
    /* Update last flush time */
    struct timespec now2;
    clock_gettime(CLOCK_MONOTONIC, &now2);
    ser->last_flush_time = (__u64)now2.tv_sec * 1000ULL + now2.tv_nsec / 1000000ULL;
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Flushed %d events (%d bytes JSON)\n",
               ser->event_count, written);
    }
    
    /* Reset batch */
    ser->event_count = 0;
    
    return written;
}

/**
 * serializer_needs_flush - Check if batch needs flushing
 * 
 * @ser: Serializer context
 * 
 * Returns: 1 if needs flush, 0 otherwise
 */
int serializer_needs_flush(struct serializer *ser) {
    if (!ser) {
        return 0;
    }
    
    /* Flush if batch is full */
    if (ser->event_count >= ser->batch_size) {
        return 1;
    }
    
    /* Flush if timeout exceeded */
    if (ser->flush_timeout_ms > 0 && ser->event_count > 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        __u64 now_ms = (__u64)now.tv_sec * 1000ULL + now.tv_nsec / 1000000ULL;
        
        if (now_ms - ser->last_flush_time >= (__u64)ser->flush_timeout_ms) {
            return 1;
        }
    }
    
    return 0;
}

/**
 * serializer_cleanup - Cleanup and free serializer resources
 * 
 * @ser: Serializer context
 */
void serializer_cleanup(struct serializer *ser) {
    if (!ser) {
        return;
    }
    
    /* Flush any remaining events */
    if (ser->event_count > 0) {
        char dummy[4096];
        serializer_flush(ser, dummy, sizeof(dummy));
    }
    
    /* Free serializer struct */
    free(ser);
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Serializer cleaned up\n");
    }
}

/* ==================== Single Event Serialization ==================== */

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
                              char *output, int output_size) {
    if (!event || !output || output_size <= 0) {
        return -1;
    }
    
    struct serializer *ser = serializer_init(1, 0);
    if (!ser) {
        return -1;
    }
    
    int ret = serializer_add_event(ser, event);
    if (ret != 0) {
        serializer_cleanup(ser);
        return -1;
    }
    
    ret = serializer_flush(ser, output, output_size);
    serializer_cleanup(ser);
    
    return ret;
}

/**
 * serialize_batch_to_json - Serialize event batch to JSON
 * 
 * @events: Array of events
 * @event_count: Number of events
 * @output: Output buffer
 * @output_size: Size of output buffer
 * 
 * Returns: Number of bytes written, or -1 on failure
 */
int serialize_batch_to_json(const struct connect_event_t *events,
                              int event_count,
                              char *output, int output_size) {
    if (!events || event_count <= 0 || !output || output_size <= 0) {
        return -1;
    }
    
    struct serializer *ser = serializer_init(event_count, 0);
    if (!ser) {
        return -1;
    }
    
    /* Add all events */
    for (int i = 0; i < event_count; i++) {
        if (serializer_add_event(ser, &events[i]) != 0) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Failed to add event %d to batch\n", i);
            }
            break;
        }
    }
    
    /* Flush */
    int ret = serializer_flush(ser, output, output_size);
    serializer_cleanup(ser);
    
    return ret;
}
