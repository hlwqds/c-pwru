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

---

## Phase 3: BTF Magic (Automation)

The core "magic" of `pwru` is its ability to find every kernel function that processes a network packet. We implemented this by crawling the kernel's BTF (BPF Type Format) data.

### 1. In-tree Libbpf Build
To support advanced BTF APIs, we migrated from system-wide `libbpf` to a git submodule (`v1.6.2`).
-   **Makefile**: Added logic to automatically build `libbpf.a` and install headers into a local `build/` directory. This ensures the project is portable and uses consistent API versions.

### 2. BTF Traversal Logic
Implemented `print_skb_funcs()` in `pwru.c` which performs the following:
1.  **Load vmlinux BTF**: Loads the type information of the currently running kernel.
2.  **Find `sk_buff`**: Locates the unique Type ID for `struct sk_buff`.
3.  **Iterate Types**: Loops through every type defined in the kernel.
4.  **Filter Functions**: 
    -   Identify `BTF_KIND_FUNC` entries.
    -   Resolve their `FUNC_PROTO` (prototype).
    -   Check the **first parameter** (`params[0]`).
    -   Verify if the parameter is a **Pointer** to the `sk_buff` ID.
5.  **Result**: Successfully identified **1100+** functions in the local kernel that accept `skb` as their first argument.

### 3. CLI Integration
Added the `--list-funcs` flag to allow users to verify the discovered functions without running the full tracer.

## Phase 4: Dynamic Attachment (Planned)
The next step is to programmatically attach our kprobe to the entire list of discovered functions.


## How to Run
```bash
cd c-pwru
make
sudo ./build/pwru --dst-ip 8.8.8.8
```

