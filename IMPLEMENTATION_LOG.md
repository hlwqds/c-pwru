# C-pwru 实现日志

本文档记录了 `C-pwru` 的分步实现过程。这是一个基于 C 语言的 eBPF 网络追踪工具，灵感来自 `pwru`。

## 第一阶段：环境搭建与 "Hello skb"

### 1. 项目结构
我们建立了标准的 C/eBPF 项目结构：

```text
c-pwru/
├── Makefile       # 构建系统
├── src/
│   ├── pwru.c     # 用户态加载器 (libbpf)
│   ├── pwru.bpf.c # 内核态 eBPF 程序
│   └── vmlinux.h  # 内核类型定义 (CO-RE)
└── build/         # 编译产物
```

**关于 `vmlinux.h`**：我们使用了现有的 `vmlinux.h` 以确保符合现代 CO-RE（一次编译，到处运行）标准。

### 2. 构建系统 (Makefile)
我们创建了一个 `Makefile` 来 handle 双重编译流程：
1.  **eBPF 对象**：使用 `clang` 的 `-target bpf` 参数将 `pwru.bpf.c` 编译为 `pwru.bpf.o`。
2.  **用户态二进制**：使用 `gcc`/`cc` 编译 `pwru.c` 并链接 `libbpf`、`libelf` 和 `zlib`。

### 3. 第一次追踪 (kprobe/ip_rcv)
最初的目标是证明我们可以挂载一个函数。我们选择了 `ip_rcv`，它是 IPv4 数据包的入口点。

**内核态 (pwru.bpf.c):**
```c
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb) {
    bpf_printk("Hello skb: %llx\n", skb);
    return 0;
}
```

**用户态 (pwru.c):**
使用 `libbpf` API：
1. 打开并加载 `pwru.bpf.o`。
2. 找到 `ip_rcv` 程序。
3. 使用 `bpf_program__attach` 进行挂载。
4. 保持进程运行以维持挂载状态。

---

## 第二阶段：深度解析与过滤

### 1. 解析 `sk_buff`
为了过滤流量，我们需要查看数据包内部。由于 `sk_buff` 的字段在不同内核版本间不稳定，我们使用了 `BPF_CORE_READ` 宏。

**逻辑：**
1.  读取 `skb->head`（缓冲区起始位置）。
2.  读取 `skb->network_header`（相对于 head 的 IP 头偏移）。
3.  计算 `ip_header_start = head + network_header`。
4.  使用 `bpf_probe_read_kernel` 将 `struct iphdr` 拷贝到栈内存。

```c
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 net_off = BPF_CORE_READ(skb, network_header);
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
```

### 2. 通过 BPF Map 进行配置
在 C 代码中硬编码 IP 是不现实的。我们实现了 `BPF_MAP_TYPE_ARRAY` 来将配置从用户态传递到内核态。

*   **Map**: `config_map` (Key: 0, Value: `struct config`)。
*   **用户态**：解析命令行参数（`--src-ip`, `--dst-ip`）并在挂载探针*之前*更新 Map。
*   **内核态**：在 kprobe 开始时查找 Map。如果数据包不匹配过滤器，则提前返回 (`0`)。

### 3. 高性能输出 (Ring Buffer)
`bpf_printk` 使用的 `/sys/kernel/debug/tracing/trace_pipe` 速度慢且是全局共享的。我们迁移到了 `BPF_MAP_TYPE_RINGBUF`。

*   **结构**：定义了 `struct event`，包含 `skb` 地址、IP 地址、PID 和进程名。
*   **内核态**：
    ```c
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    // ... 填充数据 ...
    bpf_ringbuf_submit(e, 0);
    ```
*   **用户态**：使用 `ring_buffer__poll` 实现轮询循环，并通过回调函数美化输出事件。

## 当前状态
*   [x] **挂载**：`ip_rcv` 的静态挂载。
*   [x] **解析**：提取 IPv4 源/目的地址。
*   [x] **过滤**：基于 CLI 的 IP 过滤。
*   [x] **输出**：高效的 RingBuffer 事件传输。
*   [x] **BTF 魔法**：自动发现 1000+ 个内核函数。
*   [x] **第四阶段**：动态大规模挂载 (1100+ kprobes)。
*   [x] **第四.五阶段**：Kprobe 白名单过滤（优化启动速度）。
*   [x] **第五阶段**：堆栈追踪、符号解析、L4/PID 过滤。
*   [x] **第六阶段**：性能优化 (fentry)。
*   [ ] **第七阶段**：高级大规模挂载 (kprobe_multi & groups)。

## 第六阶段：性能优化 (fentry)（已完成）

实现了对 `fentry` (BPF Trampoline) 的支持，大幅降低了追踪开销。

### 1. 混合后端架构

-   **内核态**：重构了 `pwru.bpf.c`，将核心逻辑提取为 `static inline` 函数 `handle_packet`。

    -   `kprobe/ip_rcv`：继续使用 `PT_REGS_IP(ctx)` 获取 IP。

    -   `fentry/ip_rcv`：新增挂载点，使用 `bpf_get_func_ip(ctx)` 获取 IP。

-   **用户态**：

    -   增加了 `--backend <kprobe|fentry>` 参数。

    -   实现了自动检测：如果存在 `/sys/kernel/btf/vmlinux`，默认使用 `fentry`，否则回退到 `kprobe`。



### 2. 动态 fentry 挂载

与 kprobe 不同，`fentry` 的多点挂载机制有所差异：

-   **BTF ID 获取**：更新了 `get_skb_funcs`，在扫描函数名时同时记录其 BTF ID。

-   **低级 API 使用**：使用 `bpf_link_create` 直接创建 `BPF_TRACE_FENTRY` 类型的链接，指定 `target_btf_id`。这允许我们将同一个 BPF 程序实例挂载到数千个不同的内核函数上。

-   **资源管理**：实现了针对 `fentry` 文件描述符 (FD) 的独立管理与清理逻辑。

## 第七阶段：高级大规模挂载 (kprobe_multi)（计划中）

为了进一步解决传统 kprobe 启动慢（在大规模模式下）以及 fentry 签名匹配严格的问题，计划引入 **Kprobe Multi (KPM)**。

### 目标
实现类似于原版 `pwru` 的分组挂载策略，利用 Linux 5.17+ 的 `BPF_TRACE_KPROBE_MULTI` 特性，实现毫秒级的千点挂载。

### 实现计划
1.  **参数分组 (Kprobe Groups)**：
    *   利用 BTF 扫描所有内核函数。
    *   根据 `struct sk_buff *` 参数出现的位置（第1、2、3、4或5个参数）将函数分为 5 个组。
2.  **多入口 BPF 程序**：
    *   在 `pwru.bpf.c` 中生成 5 个不同的 BPF 程序入口（例如 `kprobe_multi_arg1`, `kprobe_multi_arg2`...）。
    *   每个程序专门负责从特定的寄存器/参数位置读取 `skb`。
3.  **批量挂载**：
    *   使用 `libbpf` 的 `bpf_program__attach_kprobe_multi_opts` 接口。
    *   一次系统调用即可为一个组内的数百个函数完成挂载。

## 当前状态

*   [x] **挂载**：`ip_rcv` 的静态挂载。

*   [x] **解析**：提取 IPv4 源/目的地址。

*   [x] **过滤**：基于 CLI 的 IP 过滤。

*   [x] **输出**：高效的 RingBuffer 事件传输。

*   [x] **BTF 魔法**：自动发现 1000+ 个内核函数。

*   [x] **第四阶段**：动态大规模挂载 (1100+ kprobes)。

*   [x] **第四.五阶段**：Kprobe 白名单过滤（优化启动速度） 。

*   [x] **第五阶段**：堆栈追踪、符号解析、L4/PID 过滤。

*   [x] **第六阶段**：性能优化 (fentry)。



## 如何运行

```bash

cd c-pwru

make

# 自动选择最佳后端（优先 fentry）

sudo ./build/pwru --proto tcp --dport 80



# 强制使用 kprobe

sudo ./build/pwru --backend kprobe --dst-ip 1.1.1.1

```
