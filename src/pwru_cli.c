#include <argp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "pwru_cli.h"

const char *argp_program_version = "c-pwru 0.1";
const char *argp_program_bug_address = "<huanglin@example.com>";
static char doc[] = "C-pwru: Packet Where Are You (C version) -- An eBPF network tracer";
static char args_doc[] = "[PCAP FILTER]";

// Option keys for flags without short names
#define OPT_TEST_ATTACH 1001
#define OPT_LIST_FUNCS  1002
#define OPT_ALL_KPROBES 1003
#define OPT_SPORT       1004
#define OPT_DPORT       1005

static struct argp_option options[] = {
	{0, 0, 0, 0, "Filter options:", 1},
	{"src-ip",  's', "IP",    0, "Filter by source IPv4 address", 1},
	{"dst-ip",  'd', "IP",    0, "Filter by destination IPv4 address", 1},
	{"sport",   OPT_SPORT, "PORT",  0, "Filter by source port", 1},
	{"dport",   OPT_DPORT, "PORT",  0, "Filter by destination port", 1},
	{"port",    'p', "PORT",  0, "Filter by source or destination port", 1},
	{"proto",   'l', "PROTO", 0, "Filter by L4 protocol (tcp, udp, or number)", 1},
	{"pid",     'i', "PID",   0, "Filter by process ID", 1},
	{"family",  'f', "FAMILY",0, "Filter by address family (unix, inet, inet6, etc.)", 1},

	{0, 0, 0, 0, "Tracing options:", 2},
	{"backend", 'b', "MODE",  0, "Tracing backend (kprobe, fentry, kprobe-multi)", 2},
	{"all-kprobes", OPT_ALL_KPROBES, 0, 0, "Attach to all available skb-related functions", 2},
	{"list-funcs",  OPT_LIST_FUNCS,  0, 0, "List available skb-related functions and exit", 2},
	{"test-attach", OPT_TEST_ATTACH, 0, 0, "Performance test mode: attach and detach only", 2},

	{0}
};

static pwru_err_t parse_proto(const char *arg, uint8_t *proto)
{
	if (strcasecmp(arg, "tcp") == 0) {
		*proto = IPPROTO_TCP;
	} else if (strcasecmp(arg, "udp") == 0) {
		*proto = IPPROTO_UDP;
	} else {
		*proto = (uint8_t)atoi(arg);
	}
	return PWRU_OK;
}

static pwru_err_t parse_family(const char *arg, uint16_t *family)
{
	if (strcasecmp(arg, "unix") == 0) *family = AF_UNIX;
	else if (strcasecmp(arg, "inet") == 0) *family = AF_INET;
	else if (strcasecmp(arg, "inet6") == 0) *family = AF_INET6;
	else if (strcasecmp(arg, "netlink") == 0) *family = AF_NETLINK;
	else *family = (uint16_t)atoi(arg);
	return PWRU_OK;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct pwru_config *cfg = state->input;

	switch (key) {
	case 's':
		if (inet_pton(AF_INET, arg, &cfg->filter_src_ip) != 1)
			argp_error(state, "Invalid source IP address: %s", arg);
		break;
	case 'd':
		if (inet_pton(AF_INET, arg, &cfg->filter_dst_ip) != 1)
			argp_error(state, "Invalid destination IP address: %s", arg);
		break;
	case OPT_SPORT:
		cfg->filter_sport = htons((uint16_t)atoi(arg));
		break;
	case OPT_DPORT:
		cfg->filter_dport = htons((uint16_t)atoi(arg));
		break;
	case 'p': // port
	{
		uint16_t p = htons((uint16_t)atoi(arg));
		cfg->filter_sport = p;
		cfg->filter_dport = p;
		break;
	}
	case 'l': // proto
		parse_proto(arg, &cfg->filter_proto);
		break;
	case 'i': // pid
		cfg->filter_pid = (uint32_t)atoi(arg);
		break;
	case 'f': // family
		parse_family(arg, &cfg->filter_family);
		break;
	case 'b': // backend
		if (strcmp(arg, "kprobe") == 0) cfg->backend = BACKEND_KPROBE;
		else if (strcmp(arg, "fentry") == 0) cfg->backend = BACKEND_FENTRY;
		else if (strcmp(arg, "kprobe-multi") == 0) cfg->backend = BACKEND_KPROBE_MULTI;
		else argp_error(state, "Invalid backend: %s", arg);
		break;
	case OPT_ALL_KPROBES:
		cfg->all_kprobes = true;
		break;
	case OPT_LIST_FUNCS:
		cfg->cmd = PWRU_CMD_LIST;
		break;
	case OPT_TEST_ATTACH:
		cfg->test_attach = true;
		break;
	case ARGP_KEY_ARG:
		// We only support one positional argument for now (PCAP filter)
		if (state->arg_num >= 1)
			argp_usage(state);
		cfg->pcap_filter = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

pwru_err_t pwru_cli_parse(int argc, char **argv, struct pwru_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->backend = BACKEND_AUTO; // Default
	cfg->cmd = PWRU_CMD_TRACE;   // Default

	if (argp_parse(&argp, argc, argv, 0, 0, cfg) != 0) {
		return PWRU_ERR_INVALID_ARG;
	}

	return PWRU_OK;
}
