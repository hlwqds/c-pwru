#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
	__u64 addr;
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

int kprobe_ip_rcv(struct pt_regs *ctx)
{
	// bpf_printk("Enter: %llx\n", PT_REGS_IP(ctx));
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct iphdr iph;
	unsigned char *head;
	__u16 network_header;
	struct config *cfg;
	__u32 key = 0;
	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg) {
		bpf_printk("Lookup failed\n");
		return 0;
	}
	if (!skb)
		return 0;

	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_printk("RB reserve failed\n");
		return 0;
	}

	e->skb_addr = (__u64)skb;
	e->addr = PT_REGS_IP(ctx);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// Default IPs to 0
	e->src_ip = 0;
	e->dst_ip = 0;
	// Try to parse IPv4
	head = BPF_CORE_READ(skb, head);
	network_header = BPF_CORE_READ(skb, network_header);
	if (head) {
		unsigned char *ip_header_start = head + network_header;
		if (bpf_probe_read_kernel(&iph, sizeof(iph), ip_header_start) ==
		    0) {
			if (iph.version == 4) {
				e->src_ip = iph.saddr;
				e->dst_ip = iph.daddr;
			}
		}
	}

	// Apply filter ONLY if we successfully parsed IPs

	if (e->src_ip != 0) {
		if (cfg->filter_src_ip != 0 &&
		    e->src_ip != cfg->filter_src_ip) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}

		if (cfg->filter_dst_ip != 0 &&
		    e->dst_ip != cfg->filter_dst_ip) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
	}

	bpf_ringbuf_submit(e, 0);
	// bpf_printk("Submitted\n");
	return 0;
}
