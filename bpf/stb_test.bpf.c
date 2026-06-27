#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int stb_test_filter(struct __sk_buff *skb) {
    /* Simple pass-through: just check if packet is valid */
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    /* Basic bounds check */
    if (data + 14 > data_end)
        return 0;
    
    return skb->len;
}

char _license[] SEC("license") = "GPL";
