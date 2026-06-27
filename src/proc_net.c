#include "proc_net.h"
#include <stdio.h>
#include <string.h>

static int parse_proc_net_file(const char *path, int is_tcp,
                               struct proc_net_entry *entries, int max_entries) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[1024];
    int count = 0;

    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return 0;
    }

    while (count < max_entries && fgets(line, sizeof(line), f)) {
        unsigned int lip, lport, rip, rport;
        unsigned int state, txq, rxq, uid, inode;
        int n;

        /* Parse /proc/net/tcp[6] format:
         * sl  local_address:port rem_address:port st tx_queue:rx_queue ... uid inode */
        n = sscanf(line, " %*d %x:%x %x:%x %x %x:%x %*x:%x %*x %*d %*d %u %u",
                   &lip, &lport, &rip, &rport, &state, &rxq, &txq, &uid, &inode);
        if (n < 5) continue;

        entries[count].local_ip = lip;
        entries[count].local_port = (__u16)lport;
        entries[count].remote_ip = rip;
        entries[count].remote_port = (__u16)rport;
        entries[count].state = (__u8)state;
        entries[count].rx_queue = rxq;
        entries[count].tx_queue = txq;
        entries[count].uid = uid;
        entries[count].inode = inode;
        entries[count].protocol = is_tcp ? 6 : 17;

        count++;
    }

    fclose(f);
    return count;
}

int proc_net_read_tcp(struct proc_net_entry *entries, int max_entries) {
    return parse_proc_net_file("/proc/net/tcp", 1, entries, max_entries);
}

int proc_net_read_udp(struct proc_net_entry *entries, int max_entries) {
    return parse_proc_net_file("/proc/net/udp", 0, entries, max_entries);
}

int proc_net_read_tcp6(struct proc_net_entry *entries, int max_entries) {
    return parse_proc_net_file("/proc/net/tcp6", 1, entries, max_entries);
}

int proc_net_read_udp6(struct proc_net_entry *entries, int max_entries) {
    return parse_proc_net_file("/proc/net/udp6", 0, entries, max_entries);
}

int proc_net_read_dev(__u64 *rx_bytes, __u64 *tx_bytes) {
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return -1;

    char line[512];
    __u64 total_rx = 0, total_tx = 0;

    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        __u64 rx, tx;
        if (sscanf(line, " %63[^:]: %llu %*u %*u %*u %*u %*u %*u %*u %llu",
                   iface, &rx, &tx) == 3) {
            total_rx += rx;
            total_tx += tx;
        }
    }

    fclose(f);
    *rx_bytes = total_rx;
    *tx_bytes = total_tx;
    return 0;
}
