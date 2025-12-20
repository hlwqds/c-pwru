#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

struct config {
	__u32 filter_src_ip;
	__u32 filter_dst_ip;
	bool list_funcs;
	bool all_kprobes;
};

struct func_list {
	char **names;
	int count;
	int capacity;
};

static int add_func(struct func_list *fl, const char *name)
{
	if (fl->count == fl->capacity) {
		int new_cap = fl->capacity == 0 ? 128 : fl->capacity * 2;
		char **new_names = realloc(fl->names, new_cap * sizeof(char *));
		if (!new_names)
			return -1;
		fl->names = new_names;
		fl->capacity = new_cap;
	}
	fl->names[fl->count] = strdup(name);
	if (!fl->names[fl->count])
		return -1;
	fl->count++;
	return 0;
}

struct event {
	__u64 skb_addr;
	__u32 src_ip;
	__u32 dst_ip;
	__u32 pid;
	char comm[16];
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));

	printf("skb: %llx, Src: %s, Dst: %s, PID: %u, Comm: %s\n",
	       (unsigned long long)e->skb_addr, src, dst, e->pid, e->comm);
	return 0;
}

// Helper: skip CONST/VOLATILE/RESTRICT/TYPEDEF modifiers
static __u32 btf_resolve_type(struct btf *btf, __u32 type_id)
{
	const struct btf_type *t;
	while (true) {
		t = btf__type_by_id(btf, type_id);
		if (!t)
			return 0;
		if (!btf_is_mod(t) && !btf_is_typedef(t))
			break;
		type_id = t->type;
	}
	return type_id;
}

static bool is_skb_func(struct btf *btf, const struct btf_type *func,
			__s32 skb_id)
{
	const struct btf_type *proto;
	const struct btf_param *param;
	__u32 type_id;

	if (!btf_is_func(func))
		return false;

	// Get the function prototype
	proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto))
		return false;

	// We only care if it has at least one argument
	if (btf_vlen(proto) == 0)
		return false;

	// Check first argument
	param = btf_params(proto);
	type_id = param->type;

	// Arg0 must be a POINTER
	type_id = btf_resolve_type(btf, type_id);
	const struct btf_type *t = btf__type_by_id(btf, type_id);
	if (!t || !btf_is_ptr(t))
		return false;

	// De-reference pointer and resolve modifiers to find the struct
	type_id = btf_resolve_type(btf, t->type);

	// Check if it matches sk_buff ID
	return type_id == skb_id;
}

static int get_skb_funcs(struct func_list *fl)
{
	struct btf *btf;
	__s32 skb_id;

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		fprintf(stderr, "Failed to load vmlinux BTF\n");
		return -1;
	}

	skb_id = btf__find_by_name_kind(btf, "sk_buff", BTF_KIND_STRUCT);
	if (skb_id < 0) {
		fprintf(stderr, "Failed to find 'struct sk_buff' in BTF\n");
		btf__free(btf);
		return -1;
	}

	int nr_types = btf__type_cnt(btf);
	for (int i = 1; i <= nr_types; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		if (!t || !btf_is_func(t))
			continue;

		if (is_skb_func(btf, t, skb_id)) {
			if (add_func(fl, btf__name_by_offset(
					     btf, t->name_off)) < 0) {
				fprintf(stderr,
					"Failed to add function name\n");
				btf__free(btf);
				return -1;
			}
		}
	}

	btf__free(btf);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	struct bpf_map *map_cfg, *map_rb;
	struct ring_buffer *rb = NULL;
	struct config cfg = {0};
	int err, i;
	int map_fd;
	__u32 key = 0;

	// For mass attachment
	struct bpf_link **links = NULL;
	int link_count = 0;
	// Simple arg parsing
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &cfg.filter_src_ip);
		} else if (strcmp(argv[i], "--dst-ip") == 0 && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &cfg.filter_dst_ip);
		} else if (strcmp(argv[i], "--list-funcs") == 0) {
			cfg.list_funcs = true;
		} else if (strcmp(argv[i], "--all-kprobes") == 0) {
			cfg.all_kprobes = true;
		}
	}

	if (cfg.list_funcs) {
		struct func_list fl = {0};
		if (get_skb_funcs(&fl) < 0)
			return 1;

		for (i = 0; i < fl.count; i++) {
			printf("%s\n", fl.names[i]);
			free(fl.names[i]);
		}
		free(fl.names);
		return 0;
	}

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Opening BPF object file...\n");
	obj = bpf_object__open_file("build/pwru.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 1;
	}

	printf("Loading BPF object...\n");
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERROR: loading BPF object failed: %d\n", err);
		goto cleanup;
	}

	// Update config map
	map_cfg = bpf_object__find_map_by_name(obj, "config_map");
	if (!map_cfg) {
		fprintf(stderr, "ERROR: finding config map failed\n");
		goto cleanup;
	}

	map_fd = bpf_map__fd(map_cfg);
	if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
		fprintf(stderr, "ERROR: updating config map failed\n");
		goto cleanup;
	}

	printf("Attaching BPF programs...\n");
	prog = bpf_object__find_program_by_name(obj, "ip_rcv");
	if (!prog) {
		fprintf(stderr, "ERROR: finding program failed\n");
		goto cleanup;
	}

	if (cfg.all_kprobes) {
		struct func_list fl = {0};
		printf("Scanning for skb functions...\n");
		if (get_skb_funcs(&fl) < 0)
			goto cleanup;

		printf("Found %d functions. Attaching...\n", fl.count);

		links = calloc(fl.count, sizeof(struct bpf_link *));

		for (i = 0; i < fl.count; i++) {
			links[i] = bpf_program__attach_kprobe(prog, false,
							      fl.names[i]);
			if (libbpf_get_error(links[i])) {
				// It's normal for some kprobes to fail
				// (inlined, blacklist, etc) fprintf(stderr,
				// "Failed to attach to %s: %ld\n", fl.names[i],
				// libbpf_get_error(links[i]));
				links[i] = NULL;
			} else {
				link_count++;
			}
			free(fl.names[i]); // We don't need the name anymore
		}
		free(fl.names);
		printf("Successfully attached to %d / %d functions.\n",
		       link_count, fl.count);

	} else {
		// Default: just attach to ip_rcv
		link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr,
				"ERROR: attaching program failed: %ld\n",
				libbpf_get_error(link));
			link = NULL;
			goto cleanup;
		}
	}

	// Set up ring buffer
	map_rb = bpf_object__find_map_by_name(obj, "rb");
	if (!map_rb) {
		fprintf(stderr, "ERROR: finding ringbuf map failed\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(map_rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ERROR: creating ring buffer failed\n");
		goto cleanup;
	}

	printf("Successfully started! Filtering Src: %x, Dst: %x\n",
	       cfg.filter_src_ip, cfg.filter_dst_ip);
	printf("Press Ctrl+C to stop.\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ERROR: ring buffer poll: %d\n", err);
			break;
		}
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
	if (links)
		free(links);
	return 0;
}
