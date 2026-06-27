#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int stb_passfilter(struct __sk_buff *skb) {
    return skb->len;
}

char _license[] SEC("license") = "GPL";
