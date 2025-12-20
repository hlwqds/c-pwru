#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
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
};

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

	// Simple arg parsing
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &cfg.filter_src_ip);
		} else if (strcmp(argv[i], "--dst-ip") == 0 && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &cfg.filter_dst_ip);
		}
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

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: attaching program failed: %ld\n", libbpf_get_error(link));
		link = NULL;
		goto cleanup;
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

	printf("Successfully started! Filtering Src: %x, Dst: %x\n", cfg.filter_src_ip, cfg.filter_dst_ip);

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
	if (rb) ring_buffer__free(rb);
	if (link) bpf_link__destroy(link);
	if (obj) bpf_object__close(obj);
	return 0;
}