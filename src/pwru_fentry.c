#include "pwru_backend.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

static pwru_err_t fentry_setup(struct bpf_object *obj)
{
	struct bpf_program *p;
	int i;
	char name[PROG_NAME_LEN];

	p = bpf_object__find_program_by_name(obj, "kprobe_ip_rcv");
	if (p) bpf_program__set_autoload(p, false);

	for (i = 0; i < MAX_ARGS_SUPPORTED; i++) {
		snprintf(name, sizeof(name), "kprobe_multi_arg%d", i + ARG_INDEX_OFFSET);
		p = bpf_object__find_program_by_name(obj, name);
		if (p) bpf_program__set_autoload(p, false);
	}
	return PWRU_OK;
}

static pwru_err_t fentry_attach(struct bpf_object *obj, struct func_list *fl, struct attach_state *state)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "fentry_ip_rcv");
	int i, prog_fd;

	if (!prog) return PWRU_ERR_BPF_OPEN;
	prog_fd = bpf_program__fd(prog);

	state->total_funcs = fl->count;
	state->fentry_fds = calloc(fl->count, sizeof(int));
	if (!state->fentry_fds) return PWRU_ERR_NOMEM;

	for (i = 0; i < fl->count; i++) {
		if (exiting) break;
		LIBBPF_OPTS(bpf_link_create_opts, opts);
		opts.target_btf_id = fl->ids[i];
		// if id is 0, fentry attach fails.
		int fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FENTRY, &opts);
		if (fd < 0) {
			state->fentry_fds[i] = -1;
		} else {
			state->fentry_fds[i] = fd;
			state->count++;
		}
	}
	return PWRU_OK;
}

static void fentry_detach(struct attach_state *state)
{
	int i;
	if (state->fentry_fds) {
		for (i = 0; i < state->total_funcs; i++)
			if (state->fentry_fds[i] > 0)
				close(state->fentry_fds[i]);
		free(state->fentry_fds);
		state->fentry_fds = NULL;
	}
}

struct backend_ops fentry_ops = {
	.name = "fentry",
	.setup = fentry_setup,
	.attach = fentry_attach,
	.detach = fentry_detach,
};
