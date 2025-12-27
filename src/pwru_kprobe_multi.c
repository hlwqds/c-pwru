#include "pwru_backend.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static pwru_err_t kprobe_multi_setup(struct bpf_object *obj)
{
	struct bpf_program *p;

	p = bpf_object__find_program_by_name(obj, "kprobe_ip_rcv");
	if (p) bpf_program__set_autoload(p, false);

	p = bpf_object__find_program_by_name(obj, "fentry_ip_rcv");
	if (p) bpf_program__set_autoload(p, false);
	
	return PWRU_OK;
}

static pwru_err_t kprobe_multi_attach(struct bpf_object *obj, struct func_list *fl, struct attach_state *state)
{
	int i;
	struct func_list groups[MAX_ARGS_SUPPORTED] = {0};
	char prog_name[PROG_NAME_LEN];
	struct bpf_program *prog;

	// Group functions
	for (i = 0; i < fl->count; i++) {
		int idx = fl->arg_idxs[i] - ARG_INDEX_OFFSET;
		if (idx >= 0 && idx < MAX_ARGS_SUPPORTED) {
			add_func(&groups[idx], fl->names[i], fl->ids[i], fl->arg_idxs[i]);
		}
	}

	for (i = 0; i < MAX_ARGS_SUPPORTED; i++) {
		snprintf(prog_name, sizeof(prog_name), "kprobe_multi_arg%d", i + ARG_INDEX_OFFSET);
		prog = bpf_object__find_program_by_name(obj, prog_name);
		
		if (groups[i].count > 0 && prog) {
			LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
			opts.syms = (const char **)groups[i].names;
			opts.cnt = groups[i].count;
			
			state->multi_links[i] = bpf_program__attach_kprobe_multi_opts(prog, NULL, &opts);
			
			if (libbpf_get_error(state->multi_links[i])) {
				state->multi_links[i] = NULL;
			} else {
				state->count += groups[i].count;
			}
		}
		// Cleanup group
		for (int j = 0; j < groups[i].count; j++) {
			free(groups[i].names[j]);
		}
		free(groups[i].names);
		free(groups[i].ids);
		free(groups[i].arg_idxs);
	}
	return PWRU_OK;
}

static void kprobe_multi_detach(struct attach_state *state)
{
	int i;
	for (i = 0; i < MAX_ARGS_SUPPORTED; i++) {
		if (state->multi_links[i]) {
			bpf_link__destroy(state->multi_links[i]);
			state->multi_links[i] = NULL;
		}
	}
}

struct backend_ops kprobe_multi_ops = {
	.name = "kprobe-multi",
	.setup = kprobe_multi_setup,
	.attach = kprobe_multi_attach,
	.detach = kprobe_multi_detach,
};
