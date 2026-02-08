# Zynx

Zynx (**Zy**gote **N**e**x**us) is a dynamic code injection framework for Android, written in Rust. It uses eBPF for kernel-level process monitoring and ptrace for runtime injection, loading custom code into app processes during initialization.

## Features

- **eBPF-based process monitoring** — efficiently tracks Zygote fork events in kernel space
- **Ptrace-driven injection** — injects code into app processes at the `SpecializeCommon` stage
- **Stealthy** — traceless operation with no mounts; non-target processes are left completely untouched
- **Policy framework** — determines per-app injection decisions with async two-phase checks

## License

MIT
