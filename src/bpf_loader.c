/**
 * bpf_loader.c - BPF socket filter loader
 *
 * Loads compiled BPF program via bpf() syscall and attaches to
 * AF_PACKET raw socket. No libbpf dependency.
 *
 * Flow:
 * 1. Read .o file → extract BPF bytecode
 * 2. bpf(BPF_PROG_LOAD) → get prog fd
 * 3. socket(AF_PACKET, SOCK_RAW) → get socket fd
 * 4. setsockopt(SO_ATTACH_BPF) → attach filter
 */

#include "bpf_loader.h"
#include "config.h"
#include "packet_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <arpa/inet.h>

#ifndef __NR_bpf
#define __NR_bpf 386
#endif

/* Forward declarations */
static int bpf_loader_create_perf_buffer(struct bpf_loader_status *status);
static int bpf_map_update_elem(int map_fd, const void *key,
                               const void *value, __u64 flags);

/* BPF helper syscalls */
static int bpf_map_get_next_id(__u32 id, __u32 *next_id) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.start_id = id;
    return syscall(__NR_bpf, BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr));
}

static int bpf_map_get_fd_by_id(__u32 id) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_id = id;
    return syscall(__NR_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

static int bpf_obj_get_info_by_fd(int fd, void *info, __u32 *info_len) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd;
    attr.info.info_len = *info_len;
    attr.info.info = (uint64_t)(unsigned long)info;
    int ret = syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    *info_len = attr.info.info_len;
    return ret;
}

/* Minimal ELF parser for BPF .o files */
struct elf_bpf_prog {
    const void *insns;
    int insn_cnt;
};

/**
 * parse_bpf_elf - Minimal ELF parser to extract BPF instructions
 *
 * Only handles the simple case of a .o file with a single .text section
 * containing BPF instructions. No external dependencies.
 */
static int parse_bpf_elf(const char *path, struct elf_bpf_prog *prog) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Read ELF header */
    unsigned char e_ident[16];
    if (fread(e_ident, 1, 16, f) != 16) { fclose(f); return -1; }

    /* Verify ELF magic */
    if (e_ident[0] != 0x7f || e_ident[1] != 'E' ||
        e_ident[2] != 'L' || e_ident[3] != 'F') {
        fclose(f); return -1;
    }

    int is_64 = (e_ident[4] == 2);
    int is_le = (e_ident[5] == 1);

    if (!is_64 || !is_le) { fclose(f); return -1; }

    /* Read ELF64 header fields */
    fseek(f, 16, SEEK_SET);
    uint16_t e_type, e_machine;
    uint64_t e_shoff;
    uint16_t e_shentsize, e_shnum, e_shstrndx;

    fread(&e_type, 2, 1, f);
    fread(&e_machine, 2, 1, f);
    fseek(f, 4 + 8 + 8, SEEK_CUR); /* skip e_version(4), e_entry(8), e_phoff(8) */
    fread(&e_shoff, 8, 1, f);
    fseek(f, 4 + 2 + 2 + 2, SEEK_CUR); /* skip e_flags(4), e_ehsize(2), e_phentsize(2), e_phnum(2) */
    fread(&e_shentsize, 2, 1, f);
    fread(&e_shnum, 2, 1, f);
    fread(&e_shstrndx, 2, 1, f);

    /* Read section headers to find .text or socket */
    for (int i = 0; i < e_shnum; i++) {
        fseek(f, e_shoff + i * e_shentsize, SEEK_SET);

        uint32_t sh_name, sh_type;
        uint64_t sh_offset, sh_size;
        fread(&sh_name, 4, 1, f);
        fread(&sh_type, 4, 1, f);
        fseek(f, 8 + 8, SEEK_CUR); /* skip sh_flags(8), sh_addr(8) */
        fread(&sh_offset, 8, 1, f);
        fread(&sh_size, 8, 1, f);

        /* SHT_PROGBITS = 1 */
        if (sh_type == 1 && sh_size > 0) {
            /* Read string table offset from the section header for e_shstrndx */
            uint64_t str_off;
            fseek(f, e_shoff + e_shstrndx * e_shentsize + 24, SEEK_SET);
            fread(&str_off, 8, 1, f);

            fseek(f, str_off + sh_name, SEEK_SET);
            char name[32] = {0};
            fread(name, 1, sizeof(name) - 1, f);

            if (strstr(name, "text") || strstr(name, "socket")) {
                /* Found BPF program section */
                void *insns = malloc(sh_size);
                if (!insns) { fclose(f); return -1; }

                fseek(f, sh_offset, SEEK_SET);
                if (fread(insns, 1, sh_size, f) != sh_size) {
                    free(insns); fclose(f); return -1;
                }

                prog->insns = insns;
                prog->insn_cnt = sh_size / 8; /* Each BPF insn is 8 bytes */
                fclose(f);
                return 0;
            }
        }
    }

    fclose(f);
    return -1;
}

int bpf_loader_init(const char *ifname, const char *bpf_obj_path,
                    struct bpf_loader_status *status) {
    memset(status, 0, sizeof(*status));
    status->socket_fd = -1;
    status->perf_map_fd = -1;
    status->bpf_prog_fd = -1;

    /* 1. Parse BPF ELF */
    struct elf_bpf_prog bpf_prog;
    if (parse_bpf_elf(bpf_obj_path, &bpf_prog) != 0) {
        snprintf(status->error, sizeof(status->error),
                 "Failed to parse BPF ELF: %s", bpf_obj_path);
        return -1;
    }

    /* 2. Load BPF program via bpf() syscall */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insns = (uint64_t)(unsigned long)bpf_prog.insns;
    attr.insn_cnt = bpf_prog.insn_cnt;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_buf = 0;
    attr.log_level = 0;
    attr.log_size = 0;
    attr.kern_version = 0;

    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    free((void *)bpf_prog.insns);

    if (prog_fd < 0) {
        snprintf(status->error, sizeof(status->error),
                 "BPF_PROG_LOAD failed: %s", strerror(errno));
        return -1;
    }
    status->bpf_prog_fd = prog_fd;

    /* 2.5. Find perf_event_array map fd from loaded program */
    status->perf_map_fd = -1;
    {
        __u32 id = 0;
        while (bpf_map_get_next_id(id, &id) == 0) {
            int map_fd = bpf_map_get_fd_by_id(id);
            if (map_fd < 0) continue;

            struct bpf_map_info info;
            __u32 info_len = sizeof(info);
            memset(&info, 0, sizeof(info));
            if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) == 0) {
                if (info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
                    status->perf_map_fd = map_fd;
                    printf("[INFO] Found perf_event_array map (id=%u, fd=%d)\n",
                           id, map_fd);
                    break;
                }
            }
            close(map_fd);
        }
    }

    /* 3. Create AF_PACKET raw socket */
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        snprintf(status->error, sizeof(status->error),
                 "socket(AF_PACKET) failed: %s (need root)", strerror(errno));
        close(prog_fd);
        return -1;
    }

    /* 4. Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        snprintf(status->error, sizeof(status->error),
                 "ioctl(SIOCGIFINDEX) failed: %s", strerror(errno));
        close(sock_fd); close(prog_fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        snprintf(status->error, sizeof(status->error),
                 "bind(AF_PACKET) failed: %s", strerror(errno));
        close(sock_fd); close(prog_fd);
        return -1;
    }

    /* 5. Attach BPF program to socket */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF,
                   &prog_fd, sizeof(prog_fd)) < 0) {
        snprintf(status->error, sizeof(status->error),
                 "SO_ATTACH_BPF failed: %s", strerror(errno));
        close(sock_fd); close(prog_fd);
        return -1;
    }

    status->socket_fd = sock_fd;
    status->use_bpf = 1;

    /* 6. Create perf buffer for BPF events */
    if (status->perf_map_fd >= 0) {
        if (bpf_loader_create_perf_buffer(status) == 0) {
            printf("[INFO] Perf buffer active (%d CPUs)\n", status->nr_cpus);
        } else {
            printf("[WARN] Perf buffer creation failed, using raw packets only\n");
        }
    }

    printf("[INFO] BPF socket filter attached to %s (prog_fd=%d, sock_fd=%d)\n",
           ifname, prog_fd, sock_fd);

    return 0;
}

int bpf_loader_read_packet(int fd, void *buf, int bufsize) {
    if (fd < 0) return -1;
    return recvfrom(fd, buf, bufsize, MSG_DONTWAIT, NULL, NULL);
}

void bpf_loader_cleanup(struct bpf_loader_status *status) {
    if (!status) return;

    /* Cleanup perf buffers */
    for (int i = 0; i < status->nr_cpus; i++) {
        if (status->perf_mmap[i]) {
            munmap(status->perf_mmap[i],
                   (status->perf_page_cnt + 1) * sysconf(_SC_PAGESIZE));
            status->perf_mmap[i] = NULL;
        }
        if (status->perf_fds[i] >= 0) {
            close(status->perf_fds[i]);
            status->perf_fds[i] = -1;
        }
    }

    if (status->socket_fd >= 0) {
        close(status->socket_fd);
        status->socket_fd = -1;
    }
    if (status->bpf_prog_fd >= 0) {
        close(status->bpf_prog_fd);
        status->bpf_prog_fd = -1;
    }
    status->use_bpf = 0;
}

/**
 * bpf_loader_create_perf_buffer - Create perf event fds and mmap ring buffers
 *
 * Uses perf_event_open() + mmap() to create per-CPU ring buffers
 * that receive events from BPF bpf_perf_event_output().
 */
static int bpf_loader_create_perf_buffer(struct bpf_loader_status *status) {
    int page_size = sysconf(_SC_PAGESIZE);
    status->perf_page_cnt = PERF_PAGE_CNT;
    status->nr_cpus = 0;

    /* Get number of CPUs */
    int nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (nr_cpus <= 0) nr_cpus = 1;
    if (nr_cpus > PERF_MAX_CPUS) nr_cpus = PERF_MAX_CPUS;

    /* Find the perf_map fd from the BPF object */
    if (status->perf_map_fd < 0) {
        fprintf(stderr, "[PERF] No perf_map fd available\n");
        return -1;
    }

    for (int cpu = 0; cpu < nr_cpus; cpu++) {
        /* Create perf event fd */
        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_BPF_OUTPUT;
        attr.sample_type = PERF_SAMPLE_RAW;
        attr.sample_period = 1;
        attr.wakeup_events = 1;

        int fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
                         cpu /* cpu */, -1 /* group_fd */,
                         PERF_FLAG_FD_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "[PERF] perf_event_open failed for CPU %d: %s\n",
                    cpu, strerror(errno));
            /* Skip this CPU but continue */
            status->perf_fds[cpu] = -1;
            continue;
        }

        /* Update the perf_event_array map with this fd */
        if (bpf_map_update_elem(status->perf_map_fd, &cpu, &fd, BPF_ANY) < 0) {
            fprintf(stderr, "[PERF] bpf_map_update_elem failed for CPU %d\n", cpu);
            close(fd);
            status->perf_fds[cpu] = -1;
            continue;
        }

        /* mmap the ring buffer */
        int mmap_size = (status->perf_page_cnt + 1) * page_size;
        void *buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
        if (buf == MAP_FAILED) {
            fprintf(stderr, "[PERF] mmap failed for CPU %d: %s\n",
                    cpu, strerror(errno));
            close(fd);
            status->perf_fds[cpu] = -1;
            continue;
        }

        status->perf_fds[cpu] = fd;
        status->perf_mmap[cpu] = buf;
        status->nr_cpus++;
    }

    if (status->nr_cpus == 0) {
        fprintf(stderr, "[PERF] No CPUs could be set up\n");
        return -1;
    }

    printf("[INFO] Perf buffer created: %d CPUs, %d pages/CPU\n",
           status->nr_cpus, status->perf_page_cnt);
    return 0;
}

/* bpf_map_update_elem wrapper using bpf() syscall */
static int bpf_map_update_elem(int map_fd, const void *key,
                               const void *value, __u64 flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uint64_t)(unsigned long)key;
    attr.value = (uint64_t)(unsigned long)value;
    attr.flags = flags;
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/**
 * bpf_loader_read_perf_events - Read events from perf ring buffers
 *
 * Reads pkt_event_t events from all CPU ring buffers.
 */
int bpf_loader_read_perf_events(struct bpf_loader_status *status,
                                 void *buf, int bufsize, int *nr_events) {
    if (!status || !buf || !nr_events) return -1;
    *nr_events = 0;

    int page_size = sysconf(_SC_PAGESIZE);
    int event_size = sizeof(struct pkt_event_t);
    int total = 0;
    char *out = (char *)buf;

    for (int cpu = 0; cpu < status->nr_cpus; cpu++) {
        if (status->perf_fds[cpu] < 0 || !status->perf_mmap[cpu])
            continue;

        /* Read from ring buffer head/tail */
        struct perf_event_mmap_page *hdr = status->perf_mmap[cpu];
        volatile __u64 *tail = &hdr->data_tail;
        __u64 head = hdr->data_head;

        /* Memory barrier */
        __sync_synchronize();

        char *base = (char *)hdr + page_size;
        int ring_size = status->perf_page_cnt * page_size;

        while (*tail < head) {
            /* Read perf event header */
            struct perf_event_header *eph =
                (struct perf_event_header *)(base + (*tail % ring_size));

            if (eph->type == PERF_RECORD_SAMPLE) {
                /* Skip 8-byte perf event header, then 4-byte size, then data */
                int hdr_size = sizeof(struct perf_event_header) + sizeof(__u32);
                int data_offset = *tail % ring_size + hdr_size;
                void *data = base + data_offset;

                if (total + event_size <= bufsize) {
                    memcpy(out + total, data, event_size);
                    total += event_size;
                    (*nr_events)++;
                }
            }

            *tail += eph->size;
            /* Prevent stale tail reads */
            __sync_synchronize();
        }
    }

    return total;
}

int bpf_loader_is_available(void) {
    /* Quick check: can we open BPF syscall? */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    int ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    return (ret < 0 && errno != ENOSYS);
}
