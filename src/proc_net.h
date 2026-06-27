#ifndef _STB_PROC_NET_H
#define _STB_PROC_NET_H

#include "../include/common.h"

int proc_net_read_tcp(struct proc_net_entry *entries, int max_entries);
int proc_net_read_udp(struct proc_net_entry *entries, int max_entries);
int proc_net_read_tcp6(struct proc_net_entry *entries, int max_entries);
int proc_net_read_udp6(struct proc_net_entry *entries, int max_entries);
int proc_net_read_dev(__u64 *rx_bytes, __u64 *tx_bytes);

#endif
