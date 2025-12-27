#include "pwru_backend.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static pwru_err_t kprobe_setup(struct bpf_object *obj)
{
	struct bpf_program *p;
	int i;
	char name[PROG_NAME_LEN];

	p = bpf_object__find_program_by_name(obj, "fentry_ip_rcv");
	if (p) bpf_program__set_autoload(p, false);

	for (i = 0; i < MAX_ARGS_SUPPORTED; i++) {
		snprintf(name, sizeof(name), "kprobe_multi_arg%d", i + 1);
		p = bpf_object__find_program_by_name(obj, name);
		if (p) bpf_program__set_autoload(p, false);
	}
	return PWRU_OK;
}

static pwru_err_t kprobe_attach(struct bpf_object *obj, struct func_list *fl, struct attach_state *state)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "kprobe_ip_rcv");
	int i;

	if (!prog) return PWRU_ERR_BPF_OPEN;

	state->total_funcs = fl->count;
	state->links = calloc(fl->count, sizeof(struct bpf_link *));
	if (!state->links) return PWRU_ERR_NOMEM;

	for (i = 0; i < fl->count; i++) {
		if (exiting) break;
		state->links[i] = bpf_program__attach_kprobe(prog, false, fl->names[i]);
		if (libbpf_get_error(state->links[i])) {
			state->links[i] = NULL;
		} else {
			state->count++;
		}
	}
	return PWRU_OK;
}

static void kprobe_detach(struct attach_state *state)
{
	int i;
	if (state->links) {
		for (i = 0; i < state->total_funcs; i++)
			if (state->links[i])
				bpf_link__destroy(state->links[i]);
		free(state->links);
		state->links = NULL;
	}
}

struct backend_ops kprobe_ops = {
	.name = "kprobe",
	.setup = kprobe_setup,
	.attach = kprobe_attach,
	.detach = kprobe_detach,
};
