/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux_legacy.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
char __license[] SEC("license") = "GPL";
struct bpf_map_def { unsigned int t,k,v,m,f; };
#define DM(N,T,K,V,MX) struct bpf_map_def SEC("maps") N={.t=T,.k=K,.v=V,.m=MX}
struct eth { unsigned char dst[6],src[6]; unsigned short proto; };
DM(events,BPF_MAP_TYPE_PERF_EVENT_ARRAY,4,4,64);
DM(exclude_dest_ips,BPF_MAP_TYPE_HASH,4,1,32);
struct fe { __u64 ts; __u32 si,di,by,pk; __u16 sp,dp; __u8 pr,dir,pad[2]; };
static __always_inline int ex(__u32 ip) {
    long v = (long)bpf_map_lookup_elem(&exclude_dest_ips, &ip);
    return v && *(unsigned char*)v;
}
SEC("tc_ingress")
int f1(struct __sk_buff *skb) {
    void *de=(void*)(long)skb->data_end,*da=(void*)(long)skb->data;
    struct eth *e=da; if((void*)(e+1)>de)return 0;
    if(e->proto!=bpf_htons(0x0800))return 0;
    struct iphdr *ip=(void*)(e+1); if((void*)(ip+1)>de)return 0;
    if(ex(ip->daddr))return 0;
    struct fe ev={}; ev.ts=bpf_ktime_get_ns();
    ev.si=ip->saddr; ev.di=ip->daddr; ev.by=skb->len; ev.pk=1;
    ev.pr=ip->protocol; ev.dir=0;
    if(ip->protocol==6){unsigned char tcph[20];if(bpf_skb_load_bytes(skb,34,tcph,20)==0){ev.sp=bpf_ntohs(*(unsigned short*)(tcph+0));ev.dp=bpf_ntohs(*(unsigned short*)(tcph+2));}}
    else if(ip->protocol==17){unsigned char udph[8];if(bpf_skb_load_bytes(skb,34,udph,8)==0){ev.sp=bpf_ntohs(*(unsigned short*)(udph+0));ev.dp=bpf_ntohs(*(unsigned short*)(udph+2));}}
    __u32 cpu=bpf_get_smp_processor_id();
    bpf_perf_event_output(skb,&events,cpu,&ev,sizeof(ev));
    return 0;
}
SEC("tc_egress")
int f2(struct __sk_buff *skb) {
    void *de=(void*)(long)skb->data_end,*da=(void*)(long)skb->data;
    struct eth *e=da; if((void*)(e+1)>de)return 0;
    if(e->proto!=bpf_htons(0x0800))return 0;
    struct iphdr *ip=(void*)(e+1); if((void*)(ip+1)>de)return 0;
    if(ex(ip->saddr))return 0;
    struct fe ev={}; ev.ts=bpf_ktime_get_ns();
    ev.si=ip->saddr; ev.di=ip->daddr; ev.by=skb->len; ev.pk=1;
    ev.pr=ip->protocol; ev.dir=1;
    if(ip->protocol==6){unsigned char tcph[20];if(bpf_skb_load_bytes(skb,34,tcph,20)==0){ev.sp=bpf_ntohs(*(unsigned short*)(tcph+0));ev.dp=bpf_ntohs(*(unsigned short*)(tcph+2));}}
    else if(ip->protocol==17){unsigned char udph[8];if(bpf_skb_load_bytes(skb,34,udph,8)==0){ev.sp=bpf_ntohs(*(unsigned short*)(udph+0));ev.dp=bpf_ntohs(*(unsigned short*)(udph+2));}}
    __u32 cpu=bpf_get_smp_processor_id();
    bpf_perf_event_output(skb,&events,cpu,&ev,sizeof(ev));
    return 0;
}
