#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct config {
    __u32 filter_src_ip;
    __u32 filter_dst_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct event {
    __u64 skb_addr;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb)
{
    struct iphdr iph;
    unsigned char *head;
    __u16 network_header;
    struct config *cfg;
    __u32 key = 0;
    
    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) return 0;

    // Read skb->head and skb->network_header
    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);

    unsigned char *ip_header_start = head + network_header;

    bpf_probe_read_kernel(&iph, sizeof(iph), ip_header_start);

    if (iph.version != 4)
        return 0;

    __u32 src_ip = iph.saddr;
    __u32 dst_ip = iph.daddr;

    if (cfg->filter_src_ip != 0 && src_ip != cfg->filter_src_ip)
        return 0;
    if (cfg->filter_dst_ip != 0 && dst_ip != cfg->filter_dst_ip)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->skb_addr = (__u64)skb;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

