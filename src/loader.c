/**
 * loader.c - libbpf loader implementation for STB eBPF Probe
 * 
 * This module handles loading, verifying, and attaching BPF programs
 * using legacy libbpf mode (no BTF/CO-RE).
 * 
 * Uses bpf_object__open_file() + bpf_object__load() (not skeleton).
 * Manually attaches tracepoint programs.
 */

#include "loader.h"

#include <limits.h>
#include <sys/utsname.h>

/* ==================== Internal Helper Functions ==================== */

/**
 * set_legacy_mode - Set libbpf to legacy mode (no BTF/CO-RE)
 * 
 * This function configures libbpf to work without BTF/CO-RE support,
 * which is required for older kernels (5.4.x).
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int set_legacy_mode(void) {
    /* Disable BTF/CO-RE features */
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .btf_file_name = NULL,  /* No BTF file */
        .btf_custom_path = NULL,
        .kernel_log_buf = NULL,
        .kernel_log_size = 0,
        .kernel_log_level = 0,
    };
    
    /* Set environment variables to disable CO-RE */
    setenv("LIBBPF_STRICT", "0", 1);
    
    return 0;
}

/**
 * find_bpf_file - Find BPF object file in common locations
 * 
 * @bpf_obj_name: Name of BPF object file (e.g., "stb_connect.bpf.o")
 * @result_path: Buffer to store the full path (must be at least PATH_MAX)
 * 
 * Returns: 0 if found, -1 if not found
 */
static int find_bpf_file(const char *bpf_obj_name, char *result_path) {
    const char *search_paths[] = {
        "./bpf/",
        "../bpf/",
        "/system/bin/",
        "/system/xbin/",
        "/vendor/bin/",
        NULL
    };
    
    for (int i = 0; search_paths[i] != NULL; i++) {
        snprintf(result_path, PATH_MAX, "%s%s", search_paths[i], bpf_obj_name);
        if (access(result_path, F_OK) == 0) {
            return 0;
        }
    }
    
    /* If not found in common paths, try the given path directly */
    if (access(bpf_obj_name, F_OK) == 0) {
        strncpy(result_path, bpf_obj_name, PATH_MAX - 1);
        result_path[PATH_MAX - 1] = '\0';
        return 0;
    }
    
    return -1;
}

/* ==================== Public API Implementation ==================== */

/**
 * loader_init - Initialize BPF loader
 * 
 * Returns: Pointer to bpf_loader struct, or NULL on failure
 */
struct bpf_loader *loader_init(void) {
    struct bpf_loader *loader = malloc(sizeof(struct bpf_loader));
    if (!loader) {
        perror("malloc failed for bpf_loader");
        return NULL;
    }
    
    /* Initialize all fields to zero/NULL */
    memset(loader, 0, sizeof(struct bpf_loader));
    loader->perf_map_fd = -1;
    loader->connect_start_map_fd = -1;
    loader->is_loaded = 0;
    loader->is_attached = 0;
    
    /* Set legacy mode */
    set_legacy_mode();
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] BPF loader initialized in legacy mode\n");
    }
    
    return loader;
}

/**
 * loader_load - Load BPF object file
 * 
 * @loader: Loader context
 * @bpf_obj_path: Path to BPF object file (.o)
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_load(struct bpf_loader *loader, const char *bpf_obj_path) {
    if (!loader) {
        fprintf(stderr, "loader_load: loader is NULL\n");
        return -EINVAL;
    }
    
    if (!bpf_obj_path) {
        fprintf(stderr, "loader_load: bpf_obj_path is NULL\n");
        return -EINVAL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Loading BPF object: %s\n", bpf_obj_path);
    }
    
    /* Resolve path if needed */
    char resolved_path[PATH_MAX];
    if (find_bpf_file(bpf_obj_path, resolved_path) == 0) {
        bpf_obj_path = resolved_path;
        if (LOG_LEVEL >= 3) {
            printf("[DEBUG] Using BPF object path: %s\n", bpf_obj_path);
        }
    }
    
    /* Open BPF object file (legacy mode, no BTF) */
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .btf_file_name = NULL,  /* No BTF */
    };
    
    loader->obj = bpf_object__open_file(bpf_obj_path, &open_opts);
    if (!loader->obj) {
        fprintf(stderr, "Failed to open BPF object file: %s (err=%d)\n", 
                bpf_obj_path, -errno);
        return -errno;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] BPF object opened successfully\n");
    }
    
    /* Load BPF object into kernel */
    int ret = bpf_object__load(loader->obj);
    if (ret != 0) {
        fprintf(stderr, "Failed to load BPF object: err=%d\n", ret);
        loader_print_bpf_log(loader);
        return ret;
    }
    
    loader->is_loaded = 1;
    if (LOG_LEVEL >= 2) {
        printf("[INFO] BPF object loaded successfully\n");
    }
    
    /* Find programs */
    loader->prog_enter = bpf_object__find_program_by_name(
        loader->obj, "tracepoint__sys_enter_connect");
    if (!loader->prog_enter) {
        fprintf(stderr, "Failed to find program: tracepoint__sys_enter_connect\n");
        return -ENOENT;
    }
    
    loader->prog_exit = bpf_object__find_program_by_name(
        loader->obj, "tracepoint__sys_exit_connect");
    if (!loader->prog_exit) {
        fprintf(stderr, "Failed to find program: tracepoint__sys_exit_connect\n");
        return -ENOENT;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] BPF programs found: enter=%p, exit=%p\n", 
               loader->prog_enter, loader->prog_exit);
    }
    
    /* Find maps */
    loader->perf_map = bpf_object__find_map_by_name(loader->obj, "perf_map");
    if (!loader->perf_map) {
        fprintf(stderr, "Failed to find map: perf_map\n");
        return -ENOENT;
    }
    
    loader->connect_start_map = bpf_object__find_map_by_name(
        loader->obj, "connect_start");
    if (!loader->connect_start_map) {
        fprintf(stderr, "Failed to find map: connect_start\n");
        return -ENOENT;
    }
    
    /* Get map file descriptors */
    loader->perf_map_fd = bpf_map__fd(loader->perf_map);
    loader->connect_start_map_fd = bpf_map__fd(loader->connect_start_map);
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] BPF maps found: perf_map_fd=%d, connect_start_map_fd=%d\n",
               loader->perf_map_fd, loader->connect_start_map_fd);
    }
    
    return 0;
}

/**
 * loader_attach - Attach BPF programs to tracepoints
 * 
 * @loader: Loader context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_attach(struct bpf_loader *loader) {
    if (!loader) {
        fprintf(stderr, "loader_attach: loader is NULL\n");
        return -EINVAL;
    }
    
    if (!loader->is_loaded) {
        fprintf(stderr, "loader_attach: BPF not loaded yet\n");
        return -EINVAL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Attaching BPF programs to tracepoints...\n");
    }
    
    /* Attach sys_enter_connect */
    loader->link_enter = bpf_program__attach_tracepoint(
        loader->prog_enter, "syscalls", "sys_enter_connect");
    if (!loader->link_enter) {
        fprintf(stderr, "Failed to attach tracepoint: sys_enter_connect (err=%d)\n", 
                -errno);
        return -errno;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Attached: sys_enter_connect\n");
    }
    
    /* Attach sys_exit_connect */
    loader->link_exit = bpf_program__attach_tracepoint(
        loader->prog_exit, "syscalls", "sys_exit_connect");
    if (!loader->link_exit) {
        fprintf(stderr, "Failed to attach tracepoint: sys_exit_connect (err=%d)\n", 
                -errno);
        /* Clean up enter link */
        bpf_link__destroy(loader->link_enter);
        loader->link_enter = NULL;
        return -errno;
    }
    
    loader->is_attached = 1;
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Attached: sys_exit_connect\n");
        printf("[INFO] All BPF programs attached successfully\n");
    }
    
    return 0;
}

/**
 * loader_detach - Detach BPF programs from tracepoints
 * 
 * @loader: Loader context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_detach(struct bpf_loader *loader) {
    if (!loader) {
        fprintf(stderr, "loader_detach: loader is NULL\n");
        return -EINVAL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Detaching BPF programs...\n");
    }
    
    /* Destroy links (detaches programs) */
    if (loader->link_enter) {
        bpf_link__destroy(loader->link_enter);
        loader->link_enter = NULL;
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Detached: sys_enter_connect\n");
        }
    }
    
    if (loader->link_exit) {
        bpf_link__destroy(loader->link_exit);
        loader->link_exit = NULL;
        if (LOG_LEVEL >= 2) {
            printf("[INFO] Detached: sys_exit_connect\n");
        }
    }
    
    loader->is_attached = 0;
    return 0;
}

/**
 * loader_unload - Unload BPF programs and cleanup
 * 
 * @loader: Loader context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int loader_unload(struct bpf_loader *loader) {
    if (!loader) {
        fprintf(stderr, "loader_unload: loader is NULL\n");
        return -EINVAL;
    }
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] Unloading BPF programs...\n");
    }
    
    /* Detach first */
    if (loader->is_attached) {
        loader_detach(loader);
    }
    
    /* Close BPF object (unloads programs) */
    if (loader->obj) {
        bpf_object__close(loader->obj);
        loader->obj = NULL;
        if (LOG_LEVEL >= 2) {
            printf("[INFO] BPF object closed\n");
        }
    }
    
    loader->is_loaded = 0;
    loader->perf_map_fd = -1;
    loader->connect_start_map_fd = -1;
    
    return 0;
}

/**
 * loader_get_perf_map_fd - Get perf_map file descriptor
 * 
 * @loader: Loader context
 * 
 * Returns: perf_map file descriptor, or -1 on failure
 */
int loader_get_perf_map_fd(struct bpf_loader *loader) {
    if (!loader) {
        return -1;
    }
    return loader->perf_map_fd;
}

/**
 * loader_get_connect_start_map_fd - Get connect_start map file descriptor
 * 
 * @loader: Loader context
 * 
 * Returns: connect_start map file descriptor, or -1 on failure
 */
int loader_get_connect_start_map_fd(struct bpf_loader *loader) {
    if (!loader) {
        return -1;
    }
    return loader->connect_start_map_fd;
}

/**
 * loader_print_bpf_log - Print BPF verifier log
 * 
 * @loader: Loader context
 */
void loader_print_bpf_log(struct bpf_loader *loader) {
    if (!loader || !loader->obj) {
        return;
    }
    
    /* Note: In legacy mode, we don't have easy access to verifier log.
     * This is a limitation of bpf_object__open_file() without explicit log buffer.
     * For production, use bpf_object__open_mem() with custom log buffer.
     */
    fprintf(stderr, "BPF verifier log not available in legacy mode\n");
    fprintf(stderr, "Suggestion: Use bpf_object__open_mem() with log buffer\n");
}

/**
 * loader_cleanup - Cleanup and free loader resources
 * 
 * @loader: Loader context
 */
void loader_cleanup(struct bpf_loader *loader) {
    if (!loader) {
        return;
    }
    
    /* Unload first */
    if (loader->is_loaded) {
        loader_unload(loader);
    }
    
    /* Free loader struct */
    free(loader);
    
    if (LOG_LEVEL >= 2) {
        printf("[INFO] BPF loader cleaned up\n");
    }
}

/* ==================== Utility Functions ==================== */

/**
 * is_bpf_supported - Check if BPF is supported on this system
 * 
 * Returns: 1 if supported, 0 if not
 */
int is_bpf_supported(void) {
    /* Check for BPF filesystem */
    if (access("/sys/fs/bpf", F_OK) != 0) {
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] BPF filesystem not mounted at /sys/fs/bpf\n");
        }
        return 0;
    }
    
    /* Check kernel version (need 4.1+ for basic BPF, 4.17+ for tracepoint) */
    if (!check_kernel_version(4, 17)) {
        if (LOG_LEVEL >= 1) {
            fprintf(stderr, "[WARN] Kernel version too old for BPF tracepoint\n");
        }
        return 0;
    }
    
    /* Check for tracefs */
    if (access("/sys/kernel/debug/tracing", F_OK) != 0) {
        /* Try alternate location */
        if (access("/sys/kernel/tracing", F_OK) != 0) {
            if (LOG_LEVEL >= 1) {
                fprintf(stderr, "[WARN] Tracefs not mounted\n");
            }
            return 0;
        }
    }
    
    return 1;
}

/**
 * check_kernel_version - Check kernel version
 * 
 * @min_major: Minimum major version
 * @min_minor: Minimum minor version
 * 
 * Returns: 1 if kernel version >= min_version, 0 otherwise
 */
int check_kernel_version(int min_major, int min_minor) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        return 0;
    }
    
    /* Parse kernel version (e.g., "5.4.210" → major=5, minor=4) */
    int major, minor;
    if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
        return 0;
    }
    
    if (major > min_major) {
        return 1;
    } else if (major == min_major) {
        return minor >= min_minor;
    } else {
        return 0;
    }
}

/**
 * print_kernel_info - Print kernel version and BPF support info
 */
void print_kernel_info(void) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        perror("uname failed");
        return;
    }
    
    printf("=== Kernel Information ===\n");
    printf("System: %s %s %s\n", uts.sysname, uts.nodename, uts.release);
    printf("Version: %s\n", uts.version);
    printf("Machine: %s\n", uts.machine);
    
    printf("\n=== BPF Support ===\n");
    printf("BPF filesystem: %s\n", 
           access("/sys/fs/bpf", F_OK) == 0 ? "Available" : "Not available");
    printf("Tracefs: %s\n",
           (access("/sys/kernel/debug/tracing", F_OK) == 0 || 
            access("/sys/kernel/tracing", F_OK) == 0) ? "Available" : "Not available");
    printf("Kernel version >= 4.17: %s\n",
           check_kernel_version(4, 17) ? "Yes" : "No");
    printf("BPF supported: %s\n", is_bpf_supported() ? "Yes" : "No");
    printf("=======================\n");
}
