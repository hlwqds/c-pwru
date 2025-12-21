# C-pwru

一个基于 C 语言开发的 eBPF 网络包追踪工具，灵感源自原始的 [pwru](https://github.com/cilium/pwru)。

`C-pwru` 利用 `kprobes` 和 eBPF 技术追踪 Linux 内核中的网络数据包，直观展示数据包在内核网络栈中的流转路径。

## 特性

*   **追踪数据包路径**：精确查看数据包经过了哪些内核函数（如 `ip_rcv`、`netif_receive_skb` 等）。
*   **eBPF CO-RE**：基于“一次编译，到处运行”技术，具备跨内核版本的可移植性。
*   **高效过滤**：直接在内核中按 IP、协议、端口和 PID 进行过滤，最大程度降低开销。
*   **L4 解析**：识别 TCP/UDP 并显示源/目的端口。
*   **堆栈追踪**：显示每个捕获事件的完整内核调用栈。
*   **轻量级**：极少依赖（仅需 libbpf、libelf、zlib）。

## 构建

```bash
make
```

## 使用说明

**注意**：加载 eBPF 程序需要 root 权限（`sudo`）。

```bash
# 追踪所有流量（不建议在繁忙系统上运行）
sudo ./build/pwru

# 追踪发往/来自特定 IP 的流量
sudo ./build/pwru --dst-ip 1.1.1.1
sudo ./build/pwru --src-ip 192.168.1.5

# 追踪特定的 L4 流量
sudo ./build/pwru --proto tcp --dport 80
sudo ./build/pwru --port 53 --proto udp

# 追踪来自特定进程的流量
sudo ./build/pwru --pid 1234

# 列出可追踪的所有内核函数
./build/pwru --list-funcs
```

## 选项

*   `--src-ip <ip>`：按源 IPv4 地址过滤。
*   `--dst-ip <ip>`：按目的 IPv4 地址过滤。
*   `--port <port>`：按源或目的端口过滤。
*   `--sport <port>`：按源端口过滤。
*   `--dport <port>`：按目的端口过滤。
*   `--proto <protocol>`：按 L4 协议过滤（tcp、udp 或数字）。
*   `--pid <pid>`：按进程 ID (TGID) 过滤。
*   `--list-funcs`：列出所有与 `sk_buff` 相关的可追踪内核函数。
*   `--all-kprobes`：挂载到所有发现的函数（警告：开销巨大）。

## 架构设计

详见 [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md) 了解开发详情。
参考 [docs/kprobe_vs_fentry.md](docs/kprobe_vs_fentry.md) 了解性能相关概念。