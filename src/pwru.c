#include "pwru_backend.h"
#include "pwru_error.h"
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
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

enum backend {
	BACKEND_AUTO,
	BACKEND_KPROBE,
	BACKEND_FENTRY,
	BACKEND_KPROBE_MULTI,
};

struct config {
	__u32 filter_src_ip;
	__u32 filter_dst_ip;
	__u16 filter_sport;
	__u16 filter_dport;
	__u8 filter_proto;
	__u32 filter_pid;
	__u16 filter_family;
	bool list_funcs;
	bool all_kprobes;
	enum backend backend;
};

static int resize_func_list(struct func_list *fl)
{
	int new_cap = fl->capacity == 0 ? FUNC_LIST_INIT_CAP : fl->capacity * 2;
	char **new_names = realloc(fl->names, new_cap * sizeof(char *));
	__s32 *new_ids = realloc(fl->ids, new_cap * sizeof(__s32));
	__u8 *new_idxs = realloc(fl->arg_idxs, new_cap * sizeof(__u8));
	if (!new_names || !new_ids || !new_idxs) {
		free(new_names);
		free(new_ids);
		free(new_idxs);
		return PWRU_ERR_NOMEM;
	}
	fl->names = new_names;
	fl->ids = new_ids;
	fl->arg_idxs = new_idxs;
	fl->capacity = new_cap;
	return PWRU_OK;
}

pwru_err_t add_func(struct func_list *fl, const char *name, __s32 id, __u8 arg_idx)
{
	if (fl->count == fl->capacity) {
		if (resize_func_list(fl) != PWRU_OK)
			return PWRU_ERR_NOMEM;
	}
	fl->names[fl->count] = strdup(name);
	fl->ids[fl->count] = id;
	fl->arg_idxs[fl->count] = arg_idx;
	if (!fl->names[fl->count])
		return PWRU_ERR_NOMEM;
	fl->count++;
	return PWRU_OK;
}

static int compare_strs(const void *a, const void *b)
{
	const char *const *pa = a;
	const char *const *pb = b;
	return strcmp(*pa, *pb);
}

static pwru_err_t load_available_funcs(struct func_list *fl)
{
	FILE *f;
	char line[LINE_BUF_SIZE];
	char *p;

	// Try standard locations
	f = fopen("/sys/kernel/tracing/available_filter_functions", "r");
	if (!f)
		f = fopen(
		    "/sys/kernel/debug/tracing/available_filter_functions",
		    "r");
	if (!f)
		return PWRU_ERR_NOT_FOUND;

	while (fgets(line, sizeof(line), f)) {
		// Format: "function_name" or "function_name [module]" or
		// "function_name\t..."
		p = strpbrk(line, " \t\n\r");
		if (p)
			*p = '\0';

		if (strlen(line) > 0) {
			add_func(fl, line, 0, 0);
		}
	}
	fclose(f);

	qsort(fl->names, fl->count, sizeof(char *), compare_strs);
	return PWRU_OK;
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

static pwru_err_t load_kallsyms()
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[LINE_BUF_SIZE];
	char name[LINE_BUF_SIZE]; // Use LINE_BUF_SIZE for symbol names too
	char type;
	__u64 addr;
	int cap = 0;

	if (!f)
		return PWRU_ERR_NOT_FOUND;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %s", &addr, &type, name) != 3)
			continue;

		// Filter out irrelevant symbols to save memory/time if needed?
		// Traceable functions usually are 't' or 'T' or 'W'.
		if (type != 't' && type != 'T' && type != 'W' && type != 'w')
			continue;

		if (ksym_count >= cap) {
			cap = cap == 0 ? KSYMS_INIT_CAP : cap * 2;
			struct ksym *new_ksyms =
			    realloc(ksyms, cap * sizeof(struct ksym));
			if (!new_ksyms) {
				fclose(f);
				return PWRU_ERR_NOMEM;
			}
			ksyms = new_ksyms;
		}

		ksyms[ksym_count].addr = addr;
		ksyms[ksym_count].name = strdup(name);
		ksym_count++;
	}
	fclose(f);

	qsort(ksyms, ksym_count, sizeof(struct ksym), compare_ksyms);
	return PWRU_OK;
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
	char comm[COMM_LEN];
	__u16 protocol;
	__s32 stack_id;
	__u16 sport;
	__u16 dport;
	__u8 l4_proto;
	__u16 family;
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

	char fam_str[16] = "";
	if (e->family == AF_UNIX)
		snprintf(fam_str, sizeof(fam_str), "UNIX");
	else if (e->family == AF_INET)
		snprintf(fam_str, sizeof(fam_str), "INET");
	else if (e->family == AF_INET6)
		snprintf(fam_str, sizeof(fam_str), "INET6");
	else if (e->family == AF_NETLINK)
		snprintf(fam_str, sizeof(fam_str), "NETLINK");
	else if (e->family == AF_PACKET)
		snprintf(fam_str, sizeof(fam_str), "PACKET");
	else
		snprintf(fam_str, sizeof(fam_str), "%d", e->family);

	printf("skb: %llx [%s] Family: %s Proto: 0x%x Src: %s:%d, Dst: %s:%d [%s] PID: "
	       "%u, "
	       "Comm: %s\n",
	       (unsigned long long)e->skb_addr, func_name, fam_str, ntohs(e->protocol), src,
	       ntohs(e->sport), dst, ntohs(e->dport), l4_str, e->pid, e->comm);

	struct env *env = ctx;
	if (e->stack_id >= 0) {
		if (env && env->stack_map_fd >= 0) {
			__u64 ip[STACK_TRACE_DEPTH] = {};
			if (bpf_map_lookup_elem(env->stack_map_fd, &e->stack_id,
						ip) == 0) {
				for (int i = 0; i < STACK_TRACE_DEPTH && ip[i]; i++) {
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

static __u8 get_skb_arg_idx(struct btf *btf, const struct btf_type *func,
			    __s32 skb_id)
{
	const struct btf_type *proto;
	const struct btf_param *param;
	__u32 type_id;
	int i, nr_args;

	if (!btf_is_func(func))
		return 0;

	// Get the function prototype
	proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto))
		return 0;

	nr_args = btf_vlen(proto);
	if (nr_args == 0)
		return 0;

	param = btf_params(proto);
	for (i = 0; i < nr_args && i < MAX_ARGS_SUPPORTED; i++) {
		type_id = param[i].type;

		// Arg must be a POINTER
		type_id = btf_resolve_type(btf, type_id);
		const struct btf_type *t = btf__type_by_id(btf, type_id);
		if (!t || !btf_is_ptr(t))
			continue;

		// De-reference pointer and resolve modifiers to find the struct
		type_id = btf_resolve_type(btf, t->type);

		// Check if it matches sk_buff ID
		if (type_id == skb_id)
			return i + 1;
	}

	return 0;
}

static pwru_err_t get_skb_funcs(struct func_list *fl)
{
	struct btf *btf;
	__s32 skb_id;
	struct func_list available = {0};
	int i;

	// Load whitelist
	load_available_funcs(&available);

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		fprintf(stderr, "Failed to load vmlinux BTF\n");
		for (i = 0; i < available.count; i++)
			free(available.names[i]);
		free(available.names);
		free(available.ids);
		free(available.arg_idxs);
		return PWRU_ERR_BPF_LOAD;
	}

	skb_id = btf__find_by_name_kind(btf, "sk_buff", BTF_KIND_STRUCT);
	if (skb_id < 0) {
		fprintf(stderr, "Failed to find 'struct sk_buff' in BTF\n");
		btf__free(btf);
		for (i = 0; i < available.count; i++)
			free(available.names[i]);
		free(available.names);
		free(available.ids);
		free(available.arg_idxs);
		return PWRU_ERR_NOT_FOUND;
	}

	int nr_types = btf__type_cnt(btf);
	for (i = 1; i <= nr_types; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		if (!t || !btf_is_func(t))
			continue;

		__u8 arg_idx = get_skb_arg_idx(btf, t, skb_id);
		if (arg_idx > 0) {
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

			if (add_func(fl, name, i, arg_idx) != PWRU_OK) {
				btf__free(btf);
				for (i = 0; i < available.count; i++)
					free(available.names[i]);
				free(available.names);
				free(available.ids);
				free(available.arg_idxs);
				return PWRU_ERR_NOMEM;
			}
		}
	}

	btf__free(btf);
	for (i = 0; i < available.count; i++)
		free(available.names[i]);
	free(available.names);
	free(available.ids);
	free(available.arg_idxs);

	return PWRU_OK;
}

static struct backend_ops *get_backend_ops(enum backend b) {
	switch (b) {
		case BACKEND_KPROBE: return &kprobe_ops;
		case BACKEND_FENTRY: return &fentry_ops;
		case BACKEND_KPROBE_MULTI: return &kprobe_multi_ops;
		default: return NULL;
	}
}

int main(int argc, char **argv)
{
	struct rlimit r;
	pwru_err_t err_ret;

	if (getrlimit(RLIMIT_NOFILE, &r) == 0) {
		if (r.rlim_max < DEFAULT_RLIMIT_NOFILE) {
			r.rlim_max = DEFAULT_RLIMIT_NOFILE;
		}
		r.rlim_cur = r.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &r)) {
			fprintf(stderr, "Warning: failed to increase rlimit: %s\n", strerror(errno));
		}
	}

	struct bpf_object *obj;
	struct bpf_map *map_cfg, *map_rb, *map_stack;
	struct ring_buffer *rb = NULL;
	struct config cfg = {0};
	struct env env = {.stack_map_fd = -1};
	int i;
	int map_fd;
	__u32 key = 0;
	bool test_attach = false;
	struct timespec start, end;
	
	struct attach_state state = {0};
	struct backend_ops *ops = NULL;
	struct func_list fl = {0};

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
		} else if (strcmp(argv[i], "--family") == 0 && i + 1 < argc) {
			if (strcasecmp(argv[i + 1], "unix") == 0)
				cfg.filter_family = AF_UNIX;
			else if (strcasecmp(argv[i + 1], "inet") == 0)
				cfg.filter_family = AF_INET;
			else if (strcasecmp(argv[i + 1], "inet6") == 0)
				cfg.filter_family = AF_INET6;
			else if (strcasecmp(argv[i + 1], "netlink") == 0)
				cfg.filter_family = AF_NETLINK;
			else
				cfg.filter_family = atoi(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "--list-funcs") == 0) {
			cfg.list_funcs = true;
		} else if (strcmp(argv[i], "--all-kprobes") == 0) {
			cfg.all_kprobes = true;
		} else if (strcmp(argv[i], "--test-attach") == 0) {
			test_attach = true;
		} else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
			if (strcmp(argv[i + 1], "kprobe") == 0)
				cfg.backend = BACKEND_KPROBE;
			else if (strcmp(argv[i + 1], "fentry") == 0)
				cfg.backend = BACKEND_FENTRY;
			else if (strcmp(argv[i + 1], "kprobe-multi") == 0)
				cfg.backend = BACKEND_KPROBE_MULTI;
			else {
				fprintf(stderr,
					"Invalid backend: %s. Use kprobe, fentry or "
					"kprobe-multi.\n",
					argv[i + 1]);
				return 1;
			}
			i++;
		}
	}

	if (cfg.list_funcs) {
		if (get_skb_funcs(&fl) != PWRU_OK)
			return 1;

		for (i = 0; i < fl.count; i++) {
			printf("%s\n", fl.names[i]);
			free(fl.names[i]);
		}
		free(fl.names);
		free(fl.ids);
		free(fl.arg_idxs);
		return 0;
	}

	// Auto-detect backend if not specified
	if (cfg.backend == BACKEND_AUTO) {
		if (cfg.all_kprobes) {
			cfg.backend = BACKEND_KPROBE;
			printf("Backend: kprobe (forced for mass attachment)\n");
		} else if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
			cfg.backend = BACKEND_FENTRY;
			printf("Backend: fentry (auto-detected)\n");
		} else {
			cfg.backend = BACKEND_KPROBE;
			printf("Backend: kprobe (vmlinux BTF not found)\n");
		}
	} else {
		printf("Backend: %s\n", cfg.backend == BACKEND_FENTRY ? "fentry" : 
		       (cfg.backend == BACKEND_KPROBE_MULTI ? "kprobe-multi" : "kprobe"));
	}

	ops = get_backend_ops(cfg.backend);
	if (!ops) {
		fprintf(stderr, "Internal Error: Invalid backend ops\n");
		return 1;
	}

	printf("Loading kallsyms...\n");
	if (load_kallsyms() != PWRU_OK) {
		fprintf(stderr, "Warning: failed to load /proc/kallsyms, "
				"symbols will not be resolved.\n");
	}

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Opening BPF object file...\n");
	obj = bpf_object__open_file("build/pwru.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed: %s\n", 
			pwru_strerror(pwru_libbpf_to_err(libbpf_get_error(obj))));
		return 1;
	}

	// Setup programs (autoload settings)
	if ((err_ret = ops->setup(obj)) != PWRU_OK) {
		fprintf(stderr, "ERROR: backend setup failed: %s\n", pwru_strerror(err_ret));
		goto cleanup;
	}

	printf("Loading BPF object...\n");
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object failed\n");
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

	// Prepare functions list
	if (cfg.all_kprobes) {
		printf("Scanning for skb functions...\n");
		if (get_skb_funcs(&fl) != PWRU_OK)
			goto cleanup;
		printf("Found %d functions.\n", fl.count);
	} else {
		// Single attach to ip_rcv
		struct btf *btf = btf__load_vmlinux_btf();
		__s32 id = 0;
		__u8 arg_idx = 0;
		
		if (btf) {
			__s32 skb_id = btf__find_by_name_kind(btf, "sk_buff", BTF_KIND_STRUCT);
			__s32 func_id = btf__find_by_name_kind(btf, "ip_rcv", BTF_KIND_FUNC);
			if (func_id > 0) {
				id = func_id;
				if (skb_id > 0) {
					const struct btf_type *t = btf__type_by_id(btf, func_id);
					arg_idx = get_skb_arg_idx(btf, t, skb_id);
				}
			}
			btf__free(btf);
		}
		
		add_func(&fl, "ip_rcv", id, arg_idx);
	}

	printf("Attaching BPF programs...\n");
	clock_gettime(CLOCK_MONOTONIC, &start);

	if ((err_ret = ops->attach(obj, &fl, &state)) != PWRU_OK) {
		fprintf(stderr, "ERROR: attach failed: %s\n", pwru_strerror(err_ret));
	}
	
	// Free names (we already used them for attachment)
	for (i = 0; i < fl.count; i++) {
		free(fl.names[i]);
	}
	free(fl.names);
	free(fl.ids);
	free(fl.arg_idxs);

	printf("Successfully attached to %d functions.\n", state.count);

	clock_gettime(CLOCK_MONOTONIC, &end);
	if (test_attach) {
		double time_taken = (end.tv_sec - start.tv_sec) +
				    (end.tv_nsec - start.tv_nsec) * 1e-9;
		printf("Attachment finished in %.4f seconds\n", time_taken);
		goto cleanup;
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
		int rb_err = ring_buffer__poll(rb, POLL_TIMEOUT_MS);
		if (rb_err == -EINTR) {
			break;
		}
		if (rb_err < 0) {
			fprintf(stderr, "ERROR: ring buffer poll: %d\n", rb_err);
			break;
		}
	}

cleanup:
	clock_gettime(CLOCK_MONOTONIC, &start);
	if (rb)
		ring_buffer__free(rb);
	
	if (ops)
		ops->detach(&state);

	if (obj)
		bpf_object__close(obj);

	clock_gettime(CLOCK_MONOTONIC, &end);
	if (test_attach) {
		double time_taken = (end.tv_sec - start.tv_sec) +
				    (end.tv_nsec - start.tv_nsec) * 1e-9;
		printf("Cleanup finished in %.4f seconds\n", time_taken);
	}
	return 0;
}
