/**
 * main.c - Main entry point for STB eBPF Probe
 * 
 * This is the main entry point that integrates all modules:
 * - loader (BPF loader)
 * - perf_monitor (perf buffer monitor)
 * - serializer (JSON serializer)
 * - tcp_client (TCP client)
 * 
 * Uses two-phase pipeline:
 * - Phase 1 (perf_buffer callback): push raw events to ring buffer
 * - Phase 2 (main loop flush): serialize + TCP send in batch
 * 
 * Handles:
 * - Signal handling (SIGINT, SIGTERM)
 * - Main event loop
 * - Resource cleanup
 * - Statistics reporting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>

/* Include all module headers */
#include "config.h"
#include "loader.h"
#include "perf_monitor.h"
#include "serializer.h"
#include "tcp_client.h"
#include "../include/common.h"

/* ==================== Global Variables ==================== */

/* Global flag for signal handling */
static volatile int g_stop_requested = 0;

/* Module contexts */
static struct bpf_loader *g_loader = NULL;
static struct perf_monitor *g_monitor = NULL;
static struct serializer *g_serializer = NULL;
static struct tcp_client *g_tcp_client = NULL;
static struct ring_buffer *g_ring_buf = NULL;

/* Statistics */
static __u64 g_total_events = 0;
static __u64 g_total_sent = 0;
static __u64 g_total_dropped = 0;
static __u64 g_start_time = 0;

/* ==================== Signal Handlers ==================== */

/**
 * signal_handler - Handle SIGINT and SIGTERM
 * 
 * @sig: Signal number
 */
static void signal_handler(int sig) {
    if (LOG_LEVEL >= 2) {
        printf("\n[INFO] Received signal %d, shutting down...\n", sig);
    }
    g_stop_requested = 1;
}

/**
 * setup_signal_handlers - Setup signal handlers for graceful shutdown
 * 
 * Returns: 0 on success, -1 on failure
 */
static int setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("sigaction(SIGINT) failed");
        return -1;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("sigaction(SIGTERM) failed");
        return -1;
    }
    
    /* Ignore SIGPIPE (we handle EPIPE in tcp_client) */
    signal(SIGPIPE, SIG_IGN);
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Signal handlers set up\n");
    }
    
    return 0;
}

/* ==================== Resource Management ==================== */

/**
 * cleanup_all - Cleanup all resources
 * 
 * This function cleans up all modules in reverse order of initialization.
 */
static void cleanup_all(void) {
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Cleaning up resources...\n");
    }
    
    /* Stop perf monitor */
    if (g_monitor) {
        perf_monitor_stop(g_monitor);
    }
    
    /* Flush serializer */
    if (g_serializer) {
        char json_buf[MAX_JSON_LEN * MAX_EVENTS_BATCH];
        int ret = serializer_flush(g_serializer, json_buf, sizeof(json_buf));
        if (ret > 0 && g_tcp_client) {
            tcp_client_send_line(g_tcp_client, json_buf);
        }
    }
    
    /* Cleanup TCP client */
    if (g_tcp_client) {
        tcp_client_cleanup(g_tcp_client);
        g_tcp_client = NULL;
    }
    
    /* Cleanup serializer */
    if (g_serializer) {
        serializer_cleanup(g_serializer);
        g_serializer = NULL;
    }
    
    /* Cleanup perf monitor */
    if (g_monitor) {
        perf_monitor_cleanup(g_monitor);
        g_monitor = NULL;
    }
    
    /* Cleanup ring buffer */
    if (g_ring_buf) {
        destroy_ring_buffer(g_ring_buf);
        g_ring_buf = NULL;
    }
    
    /* Cleanup BPF loader (detach + unload) */
    if (g_loader) {
        loader_cleanup(g_loader);
        g_loader = NULL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] All resources cleaned up\n");
    }
}

/**
 * set_resource_limits - Set resource limits (CPU, memory)
 * 
 * Returns: 0 on success, -1 on failure
 */
static int set_resource_limits(void) {
    /* Set CPU affinity if configured */
    if (CPU_AFFINITY >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(CPU_AFFINITY, &cpuset);
        
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Failed to set CPU affinity: %s\n",
                        strerror(errno));
            }
        } else {
            if (LOG_LEVEL >= 2) {
                printf("[INFO] CPU affinity set to CPU %d\n", CPU_AFFINITY);
            }
        }
    }
    
    /* Set memory limit */
    if (MAX_MEMORY_LIMIT > 0) {
        struct rlimit mem_limit;
        mem_limit.rlim_cur = MAX_MEMORY_LIMIT;
        mem_limit.rlim_max = MAX_MEMORY_LIMIT;
        
        if (setrlimit(RLIMIT_AS, &mem_limit) != 0) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Failed to set memory limit: %s\n",
                        strerror(errno));
            }
        } else {
            if (LOG_LEVEL >= 2) {
                printf("[INFO] Memory limit set to %d MB\n",
                       MAX_MEMORY_LIMIT / (1024 * 1024));
            }
        }
    }
    
    return 0;
}

/* ==================== Main Loop ==================== */

/**
 * print_runtime_stats - Print runtime statistics
 */
static void print_runtime_stats(void) {
    printf("\n=== STB eBPF Probe Runtime Statistics ===\n");
    printf("Total events received: %llu\n", g_total_events);
    printf("Total events sent: %llu\n", g_total_sent);
    printf("Total events dropped: %llu\n", g_total_dropped);
    
    /* Calculate runtime */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    __u64 now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
    __u64 runtime_sec = (now_ns - g_start_time) / 1000000000ULL;
    
    if (runtime_sec > 0) {
        printf("Runtime: %llu seconds\n", runtime_sec);
        printf("Events/second: %llu\n", g_total_events / runtime_sec);
    }
    
    /* Module-specific stats */
    if (g_monitor) {
        perf_monitor_print_stats(g_monitor);
    }
    
    if (g_tcp_client) {
        tcp_client_print_stats(g_tcp_client);
    }
    
    printf("==========================================\n");
}

/**
 * main_loop - Main event processing loop
 * 
 * Returns: 0 on success, -1 on failure
 * 
 * This loop implements the two-phase pipeline:
 * - Phase 1: perf_buffer__poll() receives events → ring buffer
 * - Phase 2: flush ring buffer → serialize → TCP send
 */
static int main_loop(void) {
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Entering main loop...\n");
    }
    
    /* Event batch buffer */
    struct connect_event_t events[MAX_EVENTS_BATCH];
    
    /* JSON output buffer */
    char json_buf[MAX_JSON_LEN * MAX_EVENTS_BATCH];
    
    /* Main loop */
    while (!g_stop_requested) {
        /* Phase 1: Poll perf buffer (fills ring buffer via callback) */
        int poll_ret = perf_monitor_poll_once(g_monitor, 100);  /* 100ms timeout */
        
        if (poll_ret < 0 && poll_ret != -EINTR) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] perf_monitor_poll_once failed: %d\n",
                        poll_ret);
            }
            /* Short sleep to avoid busy loop */
            usleep(100000);  /* 100ms */
            continue;
        }
        
        /* Phase 2: Read events from ring buffer */
        int event_count = 0;
        while (event_count < MAX_EVENTS_BATCH) {
            struct connect_event_t event;
            int ret = ring_buffer_pop(g_ring_buf, &event);
            if (ret != 0) {
                break;  /* No more events */
            }
            
            /* Add to batch */
            memcpy(&events[event_count], &event, sizeof(event));
            event_count++;
            g_total_events++;
        }
        
        /* Process batch if we have events */
        if (event_count > 0) {
            /* Add events to serializer */
            for (int i = 0; i < event_count; i++) {
                if (serializer_add_event(g_serializer, &events[i]) != 0) {
                    /* Serializer batch full, flush first */
                    int flush_ret = serializer_flush(g_serializer, json_buf, 
                                                      sizeof(json_buf));
                    if (flush_ret > 0) {
                        /* Send JSON to relay server */
                        if (g_tcp_client && tcp_client_is_connected(g_tcp_client)) {
                            int send_ret = tcp_client_send_line(g_tcp_client, 
                                                                json_buf);
                            if (send_ret > 0) {
                                g_total_sent += send_ret;
                            }
                        }
                    }
                    
                    /* Retry adding event */
                    if (serializer_add_event(g_serializer, &events[i]) != 0) {
                        /* Still full, drop event */
                        g_total_dropped++;
                        if (LOG_LEVEL >= 1) {
                            fprintf(stderr, "[WARN] Dropping event (serializer full)\n");
                        }
                    }
                }
            }
            
            /* Check if serializer needs flush */
            if (serializer_needs_flush(g_serializer)) {
                int flush_ret = serializer_flush(g_serializer, json_buf, 
                                                  sizeof(json_buf));
                if (flush_ret > 0) {
                    /* Send JSON to relay server */
                    if (g_tcp_client && tcp_client_is_connected(g_tcp_client)) {
                        int send_ret = tcp_client_send_line(g_tcp_client, 
                                                            json_buf);
                        if (send_ret > 0) {
                            g_total_sent += send_ret;
                        }
                    }
                }
            }
        }
        
        /* Check TCP connection */
        if (g_tcp_client && !tcp_client_is_connected(g_tcp_client)) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] TCP connection lost, reconnecting...\n");
            }
            tcp_client_reconnect(g_tcp_client);
        }
        
        /* Print periodic stats (every 1000 events) */
        if (g_total_events % 1000 == 0 && g_total_events > 0) {
            if (LOG_LEVEL >= 2) {
                print_runtime_stats();
            }
        }
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Main loop exited\n");
    }
    
    return 0;
}

/* ==================== Initialization ==================== */

/**
 * init_all - Initialize all modules
 * 
 * Returns: 0 on success, -1 on failure
 */
static int init_all(void) {
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Initializing all modules...\n");
    }
    
    /* Print kernel info */
    if (LOG_LEVEL >= 2) {
        print_kernel_info();
    }
    
    /* Check BPF support */
    if (!is_bpf_supported()) {
        fprintf(stderr, "BPF not supported on this system\n");
        return -1;
    }
    
    /* 1. Create ring buffer (Phase 1 output) */
    g_ring_buf = create_ring_buffer();
    if (!g_ring_buf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Ring buffer created\n");
    }
    
    /* 2. Initialize BPF loader */
    if (ENABLE_LOADER) {
        g_loader = loader_init();
        if (!g_loader) {
            fprintf(stderr, "Failed to initialize BPF loader\n");
            return -1;
        }
        
        /* Load BPF object */
        char bpf_obj_path[] = "./bpf/stb_connect.bpf.o";
        if (loader_load(g_loader, bpf_obj_path) != 0) {
            fprintf(stderr, "Failed to load BPF object: %s\n", bpf_obj_path);
            return -1;
        }
        
        /* Attach BPF programs */
        if (loader_attach(g_loader) != 0) {
            fprintf(stderr, "Failed to attach BPF programs\n");
            return -1;
        }
        
        if (LOG_LEVEL >= 2) {
            printf("[INFO] BPF loader initialized and attached\n");
        }
    }
    
    /* 3. Initialize perf monitor */
    if (ENABLE_PERF_MONITOR) {
        int perf_map_fd = loader_get_perf_map_fd(g_loader);
        if (perf_map_fd < 0) {
            fprintf(stderr, "Invalid perf_map_fd\n");
            return -1;
        }
        
        g_monitor = perf_monitor_init(perf_map_fd, g_ring_buf, 0);  /* Don't use thread */
        if (!g_monitor) {
            fprintf(stderr, "Failed to initialize perf monitor\n");
            return -1;
        }
        
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Perf monitor initialized\n");
        }
    }
    
    /* 4. Initialize serializer */
    if (ENABLE_SERIALIZER) {
        g_serializer = serializer_init(MAX_EVENTS_PER_BATCH, 
                                       BATCH_FLUSH_TIMEOUT_MS);
        if (!g_serializer) {
            fprintf(stderr, "Failed to initialize serializer\n");
            return -1;
        }
        
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Serializer initialized (batch_size=%d, timeout=%dms)\n",
                   MAX_EVENTS_PER_BATCH, BATCH_FLUSH_TIMEOUT_MS);
        }
    }
    
    /* 5. Initialize TCP client */
    if (ENABLE_TCP_CLIENT) {
        g_tcp_client = tcp_client_init(RELAY_SERVER_IP, 
                                        RELAY_SERVER_PORT, 
                                        1);  /* auto_reconnect */
        if (!g_tcp_client) {
            fprintf(stderr, "Failed to initialize TCP client\n");
            return -1;
        }
        
        /* Connect to relay server */
        if (tcp_client_connect(g_tcp_client) != 0) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Failed to connect to relay server %s:%d\n",
                        RELAY_SERVER_IP, RELAY_SERVER_PORT);
                fprintf(stderr, "Will retry with auto-reconnect\n");
            }
        } else {
            if (LOG_LEVEL >= 2) {
                printf("[INFO] Connected to relay server %s:%d\n",
                       RELAY_SERVER_IP, RELAY_SERVER_PORT);
            }
        }
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] All modules initialized successfully\n");
    }
    
    return 0;
}

/* ==================== Print Usage ==================== */

/**
 * print_usage - Print usage information
 * 
 * @prog_name: Program name
 */
static void print_usage(const char *prog_name) {
    printf("STB eBPF Probe - Network Connection Monitor\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help           Print this help message\n");
    printf("  -v, --version        Print version information\n");
    printf("  -c, --config FILE    Load configuration from FILE\n");
    printf("  -d, --daemon        Run as daemon\n");
    printf("  -l, --log-level N   Set log level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)\n");
    printf("  -t, --test           Test mode (print events to stdout)\n");
    printf("\n");
    printf("Default relay server: %s:%d\n", RELAY_SERVER_IP, RELAY_SERVER_PORT);
    printf("Default probe ID: %s\n", PROBE_ID);
    printf("\n");
}

/**
 * print_version - Print version information
 */
static void print_version(void) {
    printf("STB eBPF Probe version 2.0.0\n");
    printf("Kernel: %s\n", "Linux 5.4.210");
    printf("Architecture: %s\n", "ARMv7l");
    printf("Build date: %s %s\n", __DATE__, __TIME__);
}

/* ==================== Main Function ==================== */

/**
 * main - Program entry point
 * 
 * @argc: Argument count
 * @argv: Argument vector
 * 
 * Returns: 0 on success, non-zero on failure
 */
int main(int argc, char *argv[]) {
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log-level") == 0) {
            if (i + 1 < argc) {
                int level = atoi(argv[i + 1]);
                if (level >= 0 && level <= 3) {
                    /* Note: LOG_LEVEL is compile-time, can't change at runtime */
                    printf("Log level: %d (compile-time: %d)\n", level, LOG_LEVEL);
                }
                i++;
            }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
            printf("Test mode not yet implemented\n");
            return 0;
        }
    }
    
    /* Print banner */
    printf("===============================================\n");
    printf("STB eBPF Probe - Network Connection Monitor\n");
    printf("Version: 2.0.0\n");
    printf("Relay Server: %s:%d\n", RELAY_SERVER_IP, RELAY_SERVER_PORT);
    printf("Probe ID: %s\n", PROBE_ID);
    printf("===============================================\n\n");
    
    /* Setup signal handlers */
    if (setup_signal_handlers() != 0) {
        fprintf(stderr, "Failed to setup signal handlers\n");
        return 1;
    }
    
    /* Set resource limits */
    set_resource_limits();
    
    /* Record start time */
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    g_start_time = (__u64)start.tv_sec * 1000000000ULL + start.tv_nsec;
    
    /* Initialize all modules */
    if (init_all() != 0) {
        fprintf(stderr, "Failed to initialize modules\n");
        cleanup_all();
        return 1;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Initialization complete, entering main loop\n");
    }
    
    /* Enter main loop */
    int ret = main_loop();
    
    /* Print final statistics */
    print_runtime_stats();
    
    /* Cleanup */
    cleanup_all();
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Exiting with code %d\n", ret);
    }
    
    return ret == 0 ? 0 : 1;
}
