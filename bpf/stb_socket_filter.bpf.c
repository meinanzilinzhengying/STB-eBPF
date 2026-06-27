#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

SEC("socket")
int stb_packet_filter(struct __sk_buff *skb) {
    /* For socket filter, return skb->len to pass all packets */
    /* The BPF program runs in kernel and allows the packet through */
    return skb->len;
}

char _license[] SEC("license") = "GPL";
