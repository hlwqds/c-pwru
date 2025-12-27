#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct config {
	__u32 filter_src_ip;
	__u32 filter_dst_ip;
	__u16 filter_sport;
	__u16 filter_dport;
	__u8 filter_proto;
	__u32 filter_pid;
	__u16 filter_family;
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
	__u16 protocol;
	__s32 stack_id;
	__u16 sport;
	__u16 dport;
	__u8 l4_proto;
	__u16 family;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);

} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 100 * sizeof(__u64));
	__uint(max_entries, 1024);
} stack_map SEC(".maps");

static __always_inline int handle_packet(void *ctx, struct sk_buff *skb,
					 __u64 ip)
{
	struct config *cfg;
	__u32 key = 0;
	struct iphdr iph;
	unsigned char *head;
	__u16 network_header;
	struct sock *sk;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg) {
		return 0;
	}
	if (!skb)
		return 0;

	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->skb_addr = (__u64)skb;
	e->addr = ip;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->protocol = BPF_CORE_READ(skb, protocol);
	e->stack_id = bpf_get_stackid(ctx, &stack_map, 0);
	
	// Read Family
	e->family = 0;
	sk = BPF_CORE_READ(skb, sk);
	if (sk) {
		e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	}

	// Default IPs/Ports to 0
	e->src_ip = 0;
	e->dst_ip = 0;
	e->sport = 0;
	e->dport = 0;
	e->l4_proto = 0;

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
				e->l4_proto = iph.protocol;

				// Parse L4
				unsigned char *l4_header_start =
				    ip_header_start + (iph.ihl * 4);

				if (iph.protocol == IPPROTO_TCP) {
					struct tcphdr tcp;
					if (bpf_probe_read_kernel(
						&tcp, sizeof(tcp),
						l4_header_start) == 0) {
						e->sport = tcp.source;
						e->dport = tcp.dest;
					}
				} else if (iph.protocol == IPPROTO_UDP) {
					struct udphdr udp;
					if (bpf_probe_read_kernel(
						&udp, sizeof(udp),
						l4_header_start) == 0) {
						e->sport = udp.source;
						e->dport = udp.dest;
					}
				}
			}
		}
	}

	// Apply Filters

	// Family filter (checking skb->sk->sk_family)
	if (cfg->filter_family != 0 && e->family != cfg->filter_family) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	// Apply filter ONLY if we successfully parsed IPs (for IP-specific filters)

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

		if (cfg->filter_proto != 0 && e->l4_proto != cfg->filter_proto) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}

		if (cfg->filter_sport != 0 && e->sport != cfg->filter_sport) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}

		if (cfg->filter_dport != 0 && e->dport != cfg->filter_dport) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
	}

	if (cfg->filter_pid != 0 && e->pid != cfg->filter_pid) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/ip_rcv")
int kprobe_ip_rcv(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	return handle_packet(ctx, skb, PT_REGS_IP(ctx));
}

SEC("fentry/ip_rcv")
int BPF_PROG(fentry_ip_rcv, struct sk_buff *skb)
{
	return handle_packet(ctx, skb, bpf_get_func_ip(ctx));
}

SEC("kprobe.multi/arg1")
int kprobe_multi_arg1(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	return handle_packet(ctx, skb, PT_REGS_IP(ctx));
}

SEC("kprobe.multi/arg2")
int kprobe_multi_arg2(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	return handle_packet(ctx, skb, PT_REGS_IP(ctx));
}

SEC("kprobe.multi/arg3")
int kprobe_multi_arg3(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
	return handle_packet(ctx, skb, PT_REGS_IP(ctx));
}

SEC("kprobe.multi/arg4")
int kprobe_multi_arg4(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
	return handle_packet(ctx, skb, PT_REGS_IP(ctx));
}

SEC("kprobe.multi/arg5")
int kprobe_multi_arg5(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM5(ctx);
	return handle_packet(ctx, skb, PT_REGS_IP(ctx));
}
