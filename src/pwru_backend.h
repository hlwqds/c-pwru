#ifndef __PWRU_BACKEND_H
#define __PWRU_BACKEND_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pwru_error.h"

#define MAX_ARGS_SUPPORTED 5
#define FUNC_LIST_INIT_CAP 128
#define KSYMS_INIT_CAP 4096
#define STACK_TRACE_DEPTH 100
#define RINGBUF_MAX_ENTRIES (256 * 1024)
#define STACK_MAP_MAX_ENTRIES 1024
#define POLL_TIMEOUT_MS 100
#define DEFAULT_RLIMIT_NOFILE 8192
#define COMM_LEN 16
#define PROG_NAME_LEN 32
#define LINE_BUF_SIZE 256

struct func_list {
	char **names;
	__s32 *ids; // BTF IDs
	__u8 *arg_idxs;
	int count;
	int capacity;
};

struct attach_state {
	struct bpf_link **links;
	int *fentry_fds;
	struct bpf_link *multi_links[MAX_ARGS_SUPPORTED];
	int count;      // Successfully attached count
	int total_funcs; // Total expected funcs (array size)
};

struct backend_ops {
	const char *name;
	pwru_err_t (*setup)(struct bpf_object *obj);
	pwru_err_t (*attach)(struct bpf_object *obj, struct func_list *fl, struct attach_state *state);
	void (*detach)(struct attach_state *state);
};

extern struct backend_ops kprobe_ops;
extern struct backend_ops fentry_ops;
extern struct backend_ops kprobe_multi_ops;

// Helper to add functions to func_list
pwru_err_t add_func(struct func_list *fl, const char *name, __s32 id, __u8 arg_idx);

extern volatile bool exiting; 

#endif
