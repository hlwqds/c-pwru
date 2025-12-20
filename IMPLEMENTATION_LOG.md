# C-pwru Implementation Log

This document records the step-by-step implementation of `C-pwru`, a C-based eBPF network tracer inspired by `pwru`.

## Phase 1: Environment & "Hello skb"

### 1. Project Structure
We established a standard C/eBPF project structure:

```text
c-pwru/
├── Makefile       # Build system
├── src/
│   ├── pwru.c     # User-space loader (libbpf)
│   ├── pwru.bpf.c # Kernel-space eBPF program
│   └── vmlinux.h  # Kernel type definitions (CO-RE)
└── build/         # Compiled artifacts
```

**Note on `vmlinux.h`**: We utilized the existing `vmlinux.h` from the parent `pwru` project to ensure compatibility with modern CO-RE (Compile Once - Run Everywhere) standards.

### 2. The Build System (Makefile)
We created a `Makefile` to handle the dual-compilation process:
1.  **eBPF Object**: Uses `clang` with `-target bpf` to compile `pwru.bpf.c` into `pwru.bpf.o`.
2.  **User Binary**: Uses `gcc`/`cc` to compile `pwru.c` and link against `libbpf`, `libelf`, and `zlib`.

### 3. First Trace (kprobe/ip_rcv)
The initial goal was to prove we could hook a function. We chose `ip_rcv`, the entry point for IPv4 packets.

**Kernel (pwru.bpf.c):**
```c
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb) {
    bpf_printk("Hello skb: %llx\n", skb);
    return 0;
}
```

**User (pwru.c):**
Used `libbpf` APIs to:
1. Open and load `pwru.bpf.o`.
2. Find the `ip_rcv` program.
3. Attach it using `bpf_program__attach`.
4. Keep the process alive to maintain the hook.

---

## Phase 2: Deep Inspection & Filtering

### 1. Parsing `sk_buff`
To filter traffic, we needed to look inside the packet. Accessing `sk_buff` fields directly is unstable across kernel versions, so we used `BPF_CORE_READ` macros.

**Logic:**
1.  Read `skb->head` (start of buffer).
2.  Read `skb->network_header` (offset to IP header).
3.  Calculate `ip_header_start = head + network_header`.
4.  Use `bpf_probe_read_kernel` to copy the `struct iphdr` into stack memory.

```c
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 net_off = BPF_CORE_READ(skb, network_header);
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
```

### 2. Configuration via BPF Maps
Hardcoding IPs in C code is impractical. We implemented a `BPF_MAP_TYPE_ARRAY` to pass configuration from user space to kernel space.

*   **Map**: `config_map` (Key: 0, Value: `struct config`).
*   **User Space**: Parses CLI args (`--src-ip`, `--dst-ip`) and updates the map *before* attaching probes.
*   **Kernel Space**: Lookups the map at the start of the kprobe. If the packet doesn't match the filter, it returns early (`0`).

### 3. High-Performance Output (Ring Buffer)
`bpf_printk` uses `/sys/kernel/debug/tracing/trace_pipe`, which is slow and global. We migrated to `BPF_MAP_TYPE_RINGBUF`.

*   **Structure**: Defined `struct event` containing `skb` address, IPs, PID, and Comm.
*   **Kernel**:
    ```c
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    // ... fill data ...
    bpf_ringbuf_submit(e, 0);
    ```
*   **User**: Implemented a polling loop using `ring_buffer__poll` and a callback function to pretty-print events.

## Current Status
*   [x] **Hook**: Static hook on `ip_rcv`.
*   [x] **Parsing**: Extract IPv4 Src/Dst.
*   [x] **Filtering**: CLI-based IP filtering.
*   [x] **Output**: Efficient RingBuffer events.
*   [x] **BTF Magic**: Automated discovery of 1000+ kernel functions.
*   [x] **Phase 4**: Dynamic Mass Attachment (1100+ kprobes).

---

## Phase 3: BTF Magic (Automation)
(details...)

## Phase 4: Dynamic Mass Attachment

With the function list from Phase 3, we implemented the logic to attach kprobes to **all** identified functions.

### 1. Implementation
-   **Refactoring**: Split `get_skb_funcs` to populate a `struct func_list`.
-   **Mass Attach Loop**: Iterate through the list and call `bpf_program__attach_kprobe` for each function.
-   **Error Handling**: Gracefully handle attachment failures (e.g., inlined functions, blacklisted symbols).
-   **Resource Management**: Maintain an array of `bpf_link` pointers (though for this CLI tool, we rely on process exit to clean up bulk links).

### 2. Results
-   Successfully attached to **1100+** functions in the networking stack.
-   Verified by capturing **47,000+ events** in a 5-second ping test.
-   This proves `C-pwru` can achieve the same "whole-system visibility" as the original Go version.

## Phase 5: Polish & Performance (Planned)
-   Resolve function addresses to symbols (ksyms) to see *where* the packet is.
-   Improve output formatting.

## How to Run
```bash
cd c-pwru
make
sudo ./build/pwru --dst-ip 8.8.8.8
```

