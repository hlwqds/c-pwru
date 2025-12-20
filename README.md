# C-pwru

A C-based eBPF network tracer inspired by [pwru](https://github.com/cilium/pwru).

## Introduction

`C-pwru` is a project aimed at reimplementing the core functionality of Cilium's `pwru` using pure C and `libbpf`. It tracks network packets in the Linux kernel and provides insights into where packets are being processed or dropped.

## Acknowledgments

This project is heavily inspired by and based on the logic of **[cilium/pwru](https://github.com/cilium/pwru)**. We are grateful to the Cilium authors for their pioneering work in eBPF networking visibility.

## Current Progress

- [x] Phase 1: Environment setup and basic `sk_buff` tracking via `kprobe/ip_rcv`.
- [x] Phase 2: Deep packet parsing (IPv4) and dynamic filtering via BPF Maps & RingBuffer.
- [x] Phase 3: BTF-based automatic function discovery.
- [x] Phase 4: Dynamic mass kprobe attachment (optimized with kprobe whitelist).
- [ ] Phase 5: Stack trace, symbol resolution, and performance optimization.

## License

- User-space: Apache License 2.0
- Kernel-space (BPF): Dual BSD/GPL

See [LICENSE](LICENSE) for details.
