# C-pwru

一个基于 C 语言开发的 eBPF 网络包追踪工具，灵感源自原始的 [pwru](https://github.com/cilium/pwru)。

`C-pwru` 利用 `kprobes`、`fentry` 和 `kprobe-multi` 等先进 eBPF 技术追踪 Linux 内核中的网络数据包，直观展示数据包在内核网络栈中的流转路径。

## 特性

*   **高性能追踪**：支持 `kprobe-multi` (Linux 5.17+) 和 `fentry` (Linux 5.5+) 后端，实现毫秒级的大规模探针挂载和极低的运行时开销。
*   **eBPF CO-RE**：基于“一次编译，到处运行”技术，具备跨内核版本的可移植性。
*   **高效过滤**：直接在内核中按 IP、协议、端口和 PID 进行过滤，最大程度降低开销。
*   **深度洞察**：
    *   **路径追踪**：查看数据包经过的所有内核函数。
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
# 自动选择最佳后端（优先 fentry > kprobe）
sudo ./build/pwru --dst-ip 1.1.1.1

# 强制使用 kprobe-multi (极速挂载，需内核 >= 5.17)
sudo ./build/pwru --backend kprobe-multi --all-kprobes --dst-ip 1.1.1.1

# 强制使用传统 kprobe (兼容性最好，但慢)
sudo ./build/pwru --backend kprobe --dst-ip 1.1.1.1

# 仅测试挂载/清理性能（不抓包）
sudo ./build/pwru --backend kprobe-multi --all-kprobes --test-attach
```

## 选项

### 过滤选项
*   `--src-ip <ip>`：按源 IPv4 地址过滤。
*   `--dst-ip <ip>`：按目的 IPv4 地址过滤。
*   `--port <port>`：按源或目的端口过滤。
*   `--sport <port>`：按源端口过滤。
*   `--dport <port>`：按目的端口过滤。
*   `--proto <protocol>`：按 L4 协议过滤（tcp、udp 或数字）。
*   `--pid <pid>`：按进程 ID (TGID) 过滤。

### 运行模式
*   `--backend <mode>`：指定追踪后端。
    *   `kprobe-multi`：最佳性能 (Linux 5.17+)。
    *   `fentry`：高性能 (Linux 5.5+, 需要 BTF)。
    *   `kprobe`：传统模式 (通用兼容)。
    *   `auto`：自动检测 (默认)。
*   `--all-kprobes`：挂载到所有与 `sk_buff` 相关的内核函数（约 1000+ 个）。
*   `--list-funcs`：列出可追踪的所有内核函数。
*   `--test-attach`：仅执行挂载和清理流程，并打印耗时统计（用于性能基准测试）。

## 架构设计

*   **模块化后端**：实现了 `kprobe`、`fentry` 和 `kprobe-multi` 的抽象接口，易于扩展。
*   **性能优化**：`kprobe-multi` 利用批量系统调用，将 1700+ 个探针的挂载时间从 ~6秒 缩短至 ~0.5秒，清理时间从 ~130秒 缩短至 ~0.02秒。

详见 [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md) 了解开发详情。
参考 [docs/kprobe_vs_fentry.md](docs/kprobe_vs_fentry.md) 了解性能相关概念。