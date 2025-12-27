#include "pwru_backend.h"
#include "pwru_error.h"
#include "pwru_cli.h"
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

static struct backend_ops *get_backend_ops(enum backend b) {
	switch (b) {
		case BACKEND_KPROBE: return &kprobe_ops;
		case BACKEND_FENTRY: return &fentry_ops;
		case BACKEND_KPROBE_MULTI: return &kprobe_multi_ops;
		default: return NULL;
	}
}

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
		return -1;
	}
	fl->names = new_names;
	fl->ids = new_ids;
	fl->arg_idxs = new_idxs;
	fl->capacity = new_cap;
	return 0;
}

pwru_err_t add_func(struct func_list *fl, const char *name, __s32 id, __u8 arg_idx)
{
	if (fl->count == fl->capacity) {
		if (resize_func_list(fl) < 0)
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

void free_func_list(struct func_list *fl)
{
	int i;
	if (!fl) return;
	for (i = 0; i < fl->count; i++) {
		free(fl->names[i]);
	}
	free(fl->names);
	free(fl->ids);
	free(fl->arg_idxs);
	memset(fl, 0, sizeof(*fl));
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

	f = fopen("/sys/kernel/tracing/available_filter_functions", "r");
	if (!f)
		f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
	if (!f)
		return PWRU_ERR_NOT_FOUND;

	while (fgets(line, sizeof(line), f)) {
		p = strpbrk(line, " 	\n\r");
		if (p) *p = '\0';
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
	if (ka->addr < kb->addr) return -1;
	if (ka->addr > kb->addr) return 1;
	return 0;
}

static pwru_err_t load_kallsyms()
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[LINE_BUF_SIZE];
	char name[LINE_BUF_SIZE];
	char type;
	__u64 addr;
	int cap = 0;

	if (!f) return PWRU_ERR_NOT_FOUND;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %s", &addr, &type, name) != 3)
			continue;
		if (type != 't' && type != 'T' && type != 'W' && type != 'w')
			continue;

		if (ksym_count >= cap) {
			cap = cap == 0 ? KSYMS_INIT_CAP : cap * 2;
			struct ksym *new_ksyms = realloc(ksyms, cap * sizeof(struct ksym));
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
	while (start <= end) {
		int mid = start + (end - start) / 2;
		if (ksyms[mid].addr <= addr) {
			best = mid;
			start = mid + 1;
		} else {
			end = mid - 1;
		}
	}
	return (best >= 0) ? ksyms[best].name : "unknown";
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
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	const char *func_name = find_ksym(e->addr);

	inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));

	char l4_str[COMM_LEN] = "";
	if (e->l4_proto == IPPROTO_TCP) snprintf(l4_str, sizeof(l4_str), "TCP");
	else if (e->l4_proto == IPPROTO_UDP) snprintf(l4_str, sizeof(l4_str), "UDP");
	else snprintf(l4_str, sizeof(l4_str), "%d", e->l4_proto);

	char fam_str[COMM_LEN] = "";
	if (e->family == AF_UNIX) snprintf(fam_str, sizeof(fam_str), "UNIX");
	else if (e->family == AF_INET) snprintf(fam_str, sizeof(fam_str), "INET");
	else if (e->family == AF_INET6) snprintf(fam_str, sizeof(fam_str), "INET6");
	else if (e->family == AF_NETLINK) snprintf(fam_str, sizeof(fam_str), "NETLINK");
	else if (e->family == AF_PACKET) snprintf(fam_str, sizeof(fam_str), "PACKET");
	else snprintf(fam_str, sizeof(fam_str), "%d", e->family);

	printf("skb: %llx [%s] Family: %s Proto: 0x%x Src: %s:%d, Dst: %s:%d [%s] PID: %u, Comm: %s\n",
	       (unsigned long long)e->skb_addr, func_name, fam_str, ntohs(e->protocol), src,
	       ntohs(e->sport), dst, ntohs(e->dport), l4_str, e->pid, e->comm);

	struct env *env = ctx;
	if (e->stack_id >= 0 && env && env->stack_map_fd >= 0) {
		__u64 ip[STACK_TRACE_DEPTH] = {};
		if (bpf_map_lookup_elem(env->stack_map_fd, &e->stack_id, ip) == 0) {
			for (int i = 0; i < STACK_TRACE_DEPTH && ip[i]; i++) {
				printf("    %s\n", find_ksym(ip[i]));
			}
		}
	}
	return 0;
}

static __u32 btf_resolve_type(struct btf *btf, __u32 type_id)
{
	const struct btf_type *t;
	while (true) {
		t = btf__type_by_id(btf, type_id);
		if (!t || (!btf_is_mod(t) && !btf_is_typedef(t))) break;
		type_id = t->type;
	}
	return type_id;
}

static __u8 get_skb_arg_idx(struct btf *btf, const struct btf_type *func, __s32 skb_id)
{
	const struct btf_type *proto;
	const struct btf_param *param;
	__u32 type_id;
	int i, nr_args;

	if (!btf_is_func(func)) return 0;
	proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto)) return 0;

	nr_args = btf_vlen(proto);
	param = btf_params(proto);
	for (i = 0; i < nr_args && i < MAX_ARGS_SUPPORTED; i++) {
		type_id = btf_resolve_type(btf, param[i].type);
		const struct btf_type *t = btf__type_by_id(btf, type_id);
		if (!t || !btf_is_ptr(t)) continue;
		if (btf_resolve_type(btf, t->type) == skb_id) return i + ARG_INDEX_OFFSET;
	}
	return 0;
}

pwru_err_t resolve_func(struct func_list *fl, const char *name)
{
	struct btf *btf = btf__load_vmlinux_btf();
	__s32 id = 0, arg_idx = 0;
	if (btf) {
		__s32 skb_id = btf__find_by_name_kind(btf, "sk_buff", BTF_KIND_STRUCT);
		__s32 func_id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
		if (func_id > 0) {
			id = func_id;
			if (skb_id > 0) arg_idx = get_skb_arg_idx(btf, btf__type_by_id(btf, func_id), skb_id);
		}
		btf__free(btf);
	}
	return add_func(fl, name, id, arg_idx);
}

pwru_err_t get_skb_funcs(struct func_list *fl)
{
	struct btf *btf;
	__s32 skb_id;
	struct func_list available = {0};
	int i;

	load_available_funcs(&available);
	btf = btf__load_vmlinux_btf();
	if (!btf) { free_func_list(&available); return PWRU_ERR_BPF_LOAD; }

	skb_id = btf__find_by_name_kind(btf, "sk_buff", BTF_KIND_STRUCT);
	if (skb_id < 0) { btf__free(btf); free_func_list(&available); return PWRU_ERR_NOT_FOUND; }

	int nr_types = btf__type_cnt(btf);
	for (i = 1; i <= nr_types; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		if (!t || !btf_is_func(t)) continue;
		__u8 arg_idx = get_skb_arg_idx(btf, t, skb_id);
		if (arg_idx > 0) {
			const char *name = btf__name_by_offset(btf, t->name_off);
			if (available.count > 0 && !bsearch(&name, available.names, available.count, sizeof(char *), compare_strs))
				continue;
			add_func(fl, name, i, arg_idx);
		}
	}
	btf__free(btf);
	free_func_list(&available);
	return PWRU_OK;
}

int main(int argc, char **argv)
{
	struct rlimit r;
	struct pwru_config cfg;
	if (pwru_cli_parse(argc, argv, &cfg) != PWRU_OK) return 1;

	if (getrlimit(RLIMIT_NOFILE, &r) == 0) {
		if (r.rlim_max < DEFAULT_RLIMIT_NOFILE) r.rlim_max = DEFAULT_RLIMIT_NOFILE;
		r.rlim_cur = r.rlim_max;
		setrlimit(RLIMIT_NOFILE, &r);
	}

	struct bpf_object *obj;
	struct ring_buffer *rb = NULL;
	struct env env = {.stack_map_fd = -1};
	int i;
	struct timespec start, end;
	struct attach_state state = {0};
	struct backend_ops *ops = NULL;
	struct func_list fl = {0};

	if (cfg.cmd == PWRU_CMD_LIST) {
		if (get_skb_funcs(&fl) != PWRU_OK) return 1;
		for (i = 0; i < fl.count; i++) printf("%s\n", fl.names[i]);
		free_func_list(&fl);
		return 0;
	}

	if (cfg.backend == BACKEND_AUTO) {
		if (cfg.all_kprobes) cfg.backend = BACKEND_KPROBE;
		else if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) cfg.backend = BACKEND_FENTRY;
		else cfg.backend = BACKEND_KPROBE;
	}

	ops = get_backend_ops(cfg.backend);
	if (!ops) return 1;

	load_kallsyms();
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = bpf_object__open_file("build/pwru.bpf.o", NULL);
	if (libbpf_get_error(obj)) return 1;

	if (ops->setup(obj) != PWRU_OK) goto cleanup;
	if (bpf_object__load(obj)) goto cleanup;

	int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map"));
	struct { uint32_t s, d; uint16_t sp, dp; uint8_t pr; uint32_t pid; uint16_t fam; } kcfg = 
		{ cfg.filter_src_ip, cfg.filter_dst_ip, cfg.filter_sport, cfg.filter_dport, cfg.filter_proto, cfg.filter_pid, cfg.filter_family };
	uint32_t key = 0;
	bpf_map_update_elem(map_fd, &key, &kcfg, BPF_ANY);

	struct bpf_map *sm = bpf_object__find_map_by_name(obj, "stack_map");
	if (sm) env.stack_map_fd = bpf_map__fd(sm);

	if (cfg.all_kprobes) {
		if (get_skb_funcs(&fl) != PWRU_OK) goto cleanup;
	} else {
		resolve_func(&fl, "ip_rcv");
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	ops->attach(obj, &fl, &state);
	free_func_list(&fl);
	clock_gettime(CLOCK_MONOTONIC, &end);

	if (cfg.test_attach) {
		printf("Attachment finished in %.4f seconds\n", (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "rb")), handle_event, &env, NULL);
	if (!rb) goto cleanup;

	printf("Successfully started! Press Ctrl+C to stop.\n");
	while (!exiting) {
		if (ring_buffer__poll(rb, POLL_TIMEOUT_MS) < 0 && errno != EINTR) break;
	}

cleanup:
	clock_gettime(CLOCK_MONOTONIC, &start);
	if (rb) ring_buffer__free(rb);
	if (ops) ops->detach(&state);
	if (obj) bpf_object__close(obj);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if (cfg.test_attach) printf("Cleanup finished in %.4f seconds\n", (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9);
	return 0;
}
