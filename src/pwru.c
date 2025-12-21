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

enum backend {
	BACKEND_AUTO,
	BACKEND_KPROBE,
	BACKEND_FENTRY,
};

struct config {
	__u32 filter_src_ip;
	__u32 filter_dst_ip;
	__u16 filter_sport;
	__u16 filter_dport;
	__u8 filter_proto;
	__u32 filter_pid;
	bool list_funcs;
	bool all_kprobes;
	enum backend backend;
};

struct func_list {
	char **names;
	__s32 *ids; // BTF IDs
	int count;
	int capacity;
};

static int add_func(struct func_list *fl, const char *name, __s32 id)
{
	if (fl->count == fl->capacity) {
		int new_cap = fl->capacity == 0 ? 128 : fl->capacity * 2;
		char **new_names = realloc(fl->names, new_cap * sizeof(char *));
		__s32 *new_ids = realloc(fl->ids, new_cap * sizeof(__s32));
		if (!new_names || !new_ids) {
			free(new_names);
			free(new_ids);
			return -1;
		}
		fl->names = new_names;
		fl->ids = new_ids;
		fl->capacity = new_cap;
	}
	fl->names[fl->count] = strdup(name);
	fl->ids[fl->count] = id;
	if (!fl->names[fl->count])
		return -1;
	fl->count++;
	return 0;
}

static int compare_strs(const void *a, const void *b)
{
	const char *const *pa = a;
	const char *const *pb = b;
	return strcmp(*pa, *pb);
}

static int load_available_funcs(struct func_list *fl)
{
	FILE *f;
	char line[256];
	char *p;

	// Try standard locations
	f = fopen("/sys/kernel/tracing/available_filter_functions", "r");
	if (!f)
		f = fopen(
		    "/sys/kernel/debug/tracing/available_filter_functions",
		    "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		// Format: "function_name" or "function_name [module]" or
		// "function_name\t..."
		p = strpbrk(line, " \t\n\r");
		if (p)
			*p = '\0';

		if (strlen(line) > 0) {
			add_func(fl, line, 0);
		}
	}
	fclose(f);

	qsort(fl->names, fl->count, sizeof(char *), compare_strs);
	return 0;
}

// Ksyms logic
struct ksym {
	__u64 addr;
	char *name;
};

static struct ksym *ksyms = NULL;
static int ksym_count = 0;

static int compare_ksyms(const void *a, const void *b)
{
	const struct ksym *ka = a;
	const struct ksym *kb = b;
	if (ka->addr < kb->addr)
		return -1;
	if (ka->addr > kb->addr)
		return 1;
	return 0;
}

static int load_kallsyms()
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[256];
	char name[128];
	char type;
	__u64 addr;
	int cap = 0;

	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %s", &addr, &type, name) != 3)
			continue;

		// Filter out irrelevant symbols to save memory/time if needed?
		// Traceable functions usually are 't' or 'T' or 'W'.
		if (type != 't' && type != 'T' && type != 'W' && type != 'w')
			continue;

		if (ksym_count >= cap) {
			cap = cap == 0 ? 4096 : cap * 2;
			struct ksym *new_ksyms =
			    realloc(ksyms, cap * sizeof(struct ksym));
			if (!new_ksyms) {
				fclose(f);
				return -1;
			}
			ksyms = new_ksyms;
		}

		ksyms[ksym_count].addr = addr;
		ksyms[ksym_count].name = strdup(name);
		ksym_count++;
	}
	fclose(f);

	qsort(ksyms, ksym_count, sizeof(struct ksym), compare_ksyms);
	return 0;
}

static const char *find_ksym(__u64 addr)
{
	int start = 0, end = ksym_count - 1;
	int best = -1;

	// Binary search for the symbol with address <= addr
	while (start <= end) {
		int mid = start + (end - start) / 2;
		if (ksyms[mid].addr <= addr) {
			best = mid;
			start = mid + 1;
		} else {
			end = mid - 1;
		}
	}

	if (best >= 0)
		return ksyms[best].name;
	return "unknown";
}

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
};

struct env {
	int stack_map_fd;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	const char *func_name = find_ksym(e->addr);

	inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));

	char l4_str[16] = "";
	if (e->l4_proto == IPPROTO_TCP)
		snprintf(l4_str, sizeof(l4_str), "TCP");
	else if (e->l4_proto == IPPROTO_UDP)
		snprintf(l4_str, sizeof(l4_str), "UDP");
	else
		snprintf(l4_str, sizeof(l4_str), "%d", e->l4_proto);

	printf("skb: %llx [%s] Proto: 0x%x Src: %s:%d, Dst: %s:%d [%s] PID: %u, "
	       "Comm: %s\n",
	       (unsigned long long)e->skb_addr, func_name, ntohs(e->protocol), src,
	       ntohs(e->sport), dst, ntohs(e->dport), l4_str, e->pid, e->comm);

	struct env *env = ctx;
	if (e->stack_id >= 0) {
		if (env && env->stack_map_fd >= 0) {
			__u64 ip[100] = {};
			if (bpf_map_lookup_elem(env->stack_map_fd, &e->stack_id,
						ip) == 0) {
				for (int i = 0; i < 100 && ip[i]; i++) {
					const char *sym = find_ksym(ip[i]);
					printf("    %s\n", sym);
				}
			}
		}
	} else {
		if (e->stack_id == -EEXIST) {
			printf("    [Stack truncated: map size limit "
			       "reached]\n");
		} else {
			printf("    [Stack capture failed: err %d]\n",
			       e->stack_id);
		}
	}
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

	struct func_list available = {0};

	int i;

	// Load whitelist

	if (load_available_funcs(&available) < 0) {

		fprintf(stderr,
			"Warning: failed to load available_filter_functions. "
			"Trying blindly...\n");
	}

	btf = btf__load_vmlinux_btf();

	if (!btf) {

		fprintf(stderr, "Failed to load vmlinux BTF\n");

		// Clean up available

		for (i = 0; i < available.count; i++)
			free(available.names[i]);

		free(available.names);
		free(available.ids);

		return -1;
	}

	skb_id = btf__find_by_name_kind(btf, "sk_buff", BTF_KIND_STRUCT);

	if (skb_id < 0) {

		fprintf(stderr, "Failed to find 'struct sk_buff' in BTF\n");

		btf__free(btf);

		// Clean up available

		for (i = 0; i < available.count; i++)
			free(available.names[i]);

		free(available.names);
		free(available.ids);

		return -1;
	}

	int nr_types = btf__type_cnt(btf);

	for (i = 1; i <= nr_types; i++) {

		const struct btf_type *t = btf__type_by_id(btf, i);

		if (!t || !btf_is_func(t))
			continue;

		if (is_skb_func(btf, t, skb_id)) {

			const char *name =
			    btf__name_by_offset(btf, t->name_off);

			// Filter against whitelist

			if (available.count > 0) {

				if (!bsearch(&name, available.names,
					     available.count, sizeof(char *),
					     compare_strs)) {

					continue;
				}
			}

			if (add_func(fl, name, i) < 0) {

				fprintf(stderr,
					"Failed to add function name\n");

				btf__free(btf);

				for (i = 0; i < available.count; i++)
					free(available.names[i]);

				free(available.names);
				free(available.ids);

				return -1;
			}
		}
	}

	btf__free(btf);

	for (i = 0; i < available.count; i++)
		free(available.names[i]);

	free(available.names);
	free(available.ids);

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog_kprobe = NULL, *prog_fentry = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *map_cfg, *map_rb, *map_stack;
	struct ring_buffer *rb = NULL;
	struct config cfg = {0};
	struct env env = {.stack_map_fd = -1};
	int err, i;
	int map_fd;
	__u32 key = 0;

	// For mass attachment
	struct bpf_link **links = NULL;
	int *fentry_fds = NULL;
	int link_count = 0;
	int total_funcs = 0;

	// Simple arg parsing
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &cfg.filter_src_ip);
		} else if (strcmp(argv[i], "--dst-ip") == 0 && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &cfg.filter_dst_ip);
		} else if (strcmp(argv[i], "--sport") == 0 && i + 1 < argc) {
			cfg.filter_sport = htons(atoi(argv[++i]));
		} else if (strcmp(argv[i], "--dport") == 0 && i + 1 < argc) {
			cfg.filter_dport = htons(atoi(argv[++i]));
		} else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			__u16 p = htons(atoi(argv[++i]));
			cfg.filter_sport = p;
			cfg.filter_dport = p;
		} else if (strcmp(argv[i], "--proto") == 0 && i + 1 < argc) {
			if (strcasecmp(argv[i + 1], "tcp") == 0)
				cfg.filter_proto = IPPROTO_TCP;
			else if (strcasecmp(argv[i + 1], "udp") == 0)
				cfg.filter_proto = IPPROTO_UDP;
			else
				cfg.filter_proto = atoi(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
			cfg.filter_pid = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--list-funcs") == 0) {
			cfg.list_funcs = true;
		} else if (strcmp(argv[i], "--all-kprobes") == 0) {
			cfg.all_kprobes = true;
		} else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
			if (strcmp(argv[i + 1], "kprobe") == 0)
				cfg.backend = BACKEND_KPROBE;
			else if (strcmp(argv[i + 1], "fentry") == 0)
				cfg.backend = BACKEND_FENTRY;
			else {
				fprintf(stderr,
					"Invalid backend: %s. Use kprobe or "
					"fentry.\n",
					argv[i + 1]);
				return 1;
			}
			i++;
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
		free(fl.ids);
		return 0;
	}

	// Auto-detect backend if not specified
	if (cfg.backend == BACKEND_AUTO) {
		if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
			cfg.backend = BACKEND_FENTRY;
			printf("Backend: fentry (auto-detected)\n");
		} else {
			cfg.backend = BACKEND_KPROBE;
			printf("Backend: kprobe (vmlinux BTF not found)\n");
		}
	} else {
		printf("Backend: %s\n", cfg.backend == BACKEND_FENTRY
					    ? "fentry"
					    : "kprobe");
	}

	printf("Loading kallsyms...\n");
	if (load_kallsyms() < 0) {
		fprintf(stderr, "Warning: failed to load /proc/kallsyms, "
				"symbols will not be resolved.\n");
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

	// Disable programs we don't need based on backend
	prog_kprobe = bpf_object__find_program_by_name(obj, "kprobe_ip_rcv");
	prog_fentry = bpf_object__find_program_by_name(obj, "fentry_ip_rcv");

	if (cfg.backend == BACKEND_KPROBE) {
		if (prog_fentry)
			bpf_program__set_autoload(prog_fentry, false);
	} else {
		if (prog_kprobe)
			bpf_program__set_autoload(prog_kprobe, false);
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

	map_stack = bpf_object__find_map_by_name(obj, "stack_map");
	if (map_stack) {
		env.stack_map_fd = bpf_map__fd(map_stack);
	} else {
		fprintf(stderr, "Warning: stack map not found\n");
	}

	printf("Attaching BPF programs...\n");

	if (cfg.all_kprobes) {
		struct func_list fl = {0};
		printf("Scanning for skb functions...\n");
		if (get_skb_funcs(&fl) < 0)
			goto cleanup;

		printf("Found %d functions. Attaching...\n", fl.count);
		total_funcs = fl.count;

		if (cfg.backend == BACKEND_KPROBE) {
			links = calloc(fl.count, sizeof(struct bpf_link *));
		} else {
			fentry_fds = calloc(fl.count, sizeof(int));
		}

		for (i = 0; i < fl.count; i++) {
			if (cfg.backend == BACKEND_KPROBE) {
				links[i] = bpf_program__attach_kprobe(
				    prog_kprobe, false, fl.names[i]);
				if (libbpf_get_error(links[i])) {
					links[i] = NULL;
				} else {
					link_count++;
				}
			} else {
				// fentry attachment
				int prog_fd = bpf_program__fd(prog_fentry);
				LIBBPF_OPTS(bpf_link_create_opts, opts);
				opts.target_btf_id = fl.ids[i];
				int fd = bpf_link_create(
				    prog_fd, 0, BPF_TRACE_FENTRY, &opts);
				if (fd < 0) {
					fentry_fds[i] = -1;
				} else {
					fentry_fds[i] = fd;
					link_count++;
				}
			}

			free(fl.names[i]); // We don't need the name anymore
		}
		free(fl.names);
		free(fl.ids);
		printf("Successfully attached to %d / %d functions.\n",
		       link_count, fl.count);

	} else {
		// Default: just attach to ip_rcv
		if (cfg.backend == BACKEND_KPROBE)
			link = bpf_program__attach(prog_kprobe);
		else
			link = bpf_program__attach(prog_fentry);

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

	rb = ring_buffer__new(bpf_map__fd(map_rb), handle_event, &env, NULL);
	if (!rb) {
		fprintf(stderr, "ERROR: creating ring buffer failed\n");
		goto cleanup;
	}

	printf("Successfully started! Filtering Src: %x, Dst: %x, Sport: %d, "
	       "Dport: %d, Proto: %d, PID: %u\n",
	       cfg.filter_src_ip, cfg.filter_dst_ip, ntohs(cfg.filter_sport),
	       ntohs(cfg.filter_dport), cfg.filter_proto, cfg.filter_pid);
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
	if (links) {
		for (i = 0; i < total_funcs; i++)
			if (links[i])
				bpf_link__destroy(links[i]);
		free(links);
	}
	if (fentry_fds) {
		for (i = 0; i < total_funcs; i++)
			if (fentry_fds[i] > 0)
				close(fentry_fds[i]);
		free(fentry_fds);
	}
	if (obj)
		bpf_object__close(obj);
	return 0;
}
