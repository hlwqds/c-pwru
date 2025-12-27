#ifndef __PWRU_BACKEND_H
#define __PWRU_BACKEND_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_ARGS_SUPPORTED 5

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
	int (*setup)(struct bpf_object *obj);
	int (*attach)(struct bpf_object *obj, struct func_list *fl, struct attach_state *state);
	void (*detach)(struct attach_state *state);
};

extern struct backend_ops kprobe_ops;
extern struct backend_ops fentry_ops;
extern struct backend_ops kprobe_multi_ops;

// Helper to add functions to func_list (used by backends for internal grouping if needed)
int add_func(struct func_list *fl, const char *name, __s32 id, __u8 arg_idx);

// Helper for resizing (internal to add_func usually, but maybe useful)
// actually add_func handles it.

extern volatile bool exiting; // Backends check this during loops

#endif
