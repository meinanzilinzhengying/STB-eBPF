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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <arpa/inet.h>

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
    fseek(f, 8 + 8 + 8, SEEK_CUR); /* skip e_entry, e_phoff, e_shoff is next */
    fread(&e_shoff, 8, 1, f);
    fseek(f, 4 + 2, SEEK_CUR); /* skip e_flags, e_ehsize */
    fread(&e_shentsize, 2, 1, f);
    fread(&e_shnum, 2, 1, f);
    fread(&e_shstrndx, 2, 1, f);

    /* Read section headers to find .text */
    for (int i = 0; i < e_shnum; i++) {
        fseek(f, e_shoff + i * e_shentsize, SEEK_SET);

        uint32_t sh_name, sh_type;
        uint64_t sh_offset, sh_size;
        fread(&sh_name, 4, 1, f);
        fread(&sh_type, 4, 1, f);
        fseek(f, 4 + 4, SEEK_CUR); /* sh_flags */
        fread(&sh_offset, 8, 1, f);
        fread(&sh_size, 8, 1, f);

        /* SHT_PROGBITS = 1 */
        if (sh_type == 1 && sh_size > 0) {
            /* Read section name from string table */
            fseek(f, e_shoff + e_shstrndx * e_shentsize, SEEK_SET);
            uint64_t str_off;
            fseek(f, 16 + 8 + 8 + 8 + 8 + 4, SEEK_SET);
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

int bpf_loader_is_available(void) {
    /* Quick check: can we open BPF syscall? */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    /* BPF_PROG_LOAD with invalid prog should return EACCES or EINVAL,
     * not ENOSYS (which means BPF not available) */
    int ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    return (ret < 0 && errno != ENOSYS);
}
